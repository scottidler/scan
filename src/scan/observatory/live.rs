// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Part of scan's port of mdn/mdn-http-observatory at commit 2776308: the acceptance oracle, which
// compares scan's grade with the live API's (`/api/v2/scan` and `/api/v2/analyze`).

//! The ignored live test: for each host, a fresh `POST /api/v2/scan`, then the grade `HttpScanner`
//! computes, compared test by test.
//!
//! ```text
//! cargo test --release --lib -- --ignored --exact scan::observatory::live::scan_matches_the_live_observatory_api
//! ```
//!
//! Hosts that flap (neverssl.com answered on port 80 or 443 from one vantage and not the other, run
//! to run, and left the list for that) are retried as a pair, a fresh POST and a fresh local grade, until the two sides agree.
//! Only a graded pair agrees: the same 12 test results and modifiers, score, grade and algorithm
//! version. A pair where both sides report the site down compares none of those, so it is a retry,
//! never agreement; a host with no graded agreement in `PAIR_ATTEMPTS` pairs fails with the last
//! pair's provenance.

use crate::scan::cache::FETCH_TIMEOUT;
use crate::scan::http::HttpScanner;
use crate::scan::observatory::hsts::PRELOAD_CACHE_FILE;
use crate::scan::observatory::{ALGORITHM_VERSION, ObservatoryOutcome, ObservatoryResult};
use crate::scan::psl::SuffixList;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

const API: &str = "https://observatory-api.mdn.mozilla.net/api/v2";
const HOSTS: [&str; 6] = [
    "google.com",
    "www.tatari.tv",
    "github.com",
    "example.com",
    "mozilla.org",
    "httpforever.com",
];
/// Fresh POST plus local grade pairs per host before a disagreement fails the test.
const PAIR_ATTEMPTS: usize = 4;
/// The API answers a repeat POST for a host inside this window with the earlier scan.
const API_COOLDOWN: Duration = Duration::from_secs(61);
/// A scan of google.com can take 15-60s and has answered 503.
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const API_RETRIES: usize = 3;
const API_RETRY_PAUSE: Duration = Duration::from_secs(15);
const LOCAL_DEADLINE: Duration = Duration::from_secs(60);

/// One API test as compared: its result string and score modifier.
type ApiTests = BTreeMap<String, (String, i64)>;

/// What the API said about a fresh scan, with the provenance a mismatch prints.
#[derive(Debug)]
enum ApiOutcome {
    Graded {
        scan_id: u64,
        scanned_at: String,
        algorithm_version: u64,
        score: i64,
        grade: String,
        tests: ApiTests,
    },
    /// `422 scan-failed`: "The site seems to be down."
    SiteDown { message: String },
}

fn api_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(API_REQUEST_TIMEOUT)
        .user_agent("scan-live-test")
        .build()
        .expect("API client")
}

async fn send_with_retries(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
) -> eyre::Result<reqwest::Response> {
    let mut last = eyre::eyre!("no attempt made");
    for attempt in 1..=API_RETRIES {
        match client.request(method.clone(), url).send().await {
            Ok(response) if response.status().is_server_error() => {
                last = eyre::eyre!("{method} {url}: HTTP {}", response.status());
            }
            Ok(response) => return Ok(response),
            Err(e) => last = eyre::eyre!("{method} {url}: {e}"),
        }
        println!("  API attempt {attempt}/{API_RETRIES} failed: {last:#}");
        tokio::time::sleep(API_RETRY_PAUSE).await;
    }
    Err(last)
}

/// A fresh `POST /scan`, then `GET /analyze` for the tests of that scan.
async fn api_scan(client: &reqwest::Client, host: &str) -> eyre::Result<ApiOutcome> {
    let posted = send_with_retries(client, reqwest::Method::POST, &format!("{API}/scan?host={host}")).await?;
    let status = posted.status();
    let body: Value = posted.json().await?;
    if status.as_u16() == 422 {
        return Ok(ApiOutcome::SiteDown {
            message: body["message"].as_str().unwrap_or_default().to_string(),
        });
    }
    eyre::ensure!(status.is_success(), "POST scan {host}: HTTP {status}: {body}");
    let scan_id = body["id"].as_u64().ok_or_else(|| eyre::eyre!("no scan id: {body}"))?;

    let analyzed = send_with_retries(client, reqwest::Method::GET, &format!("{API}/analyze?host={host}")).await?;
    let analysis: Value = analyzed.json().await?;
    let analyzed_id = analysis["scan"]["id"].as_u64();
    eyre::ensure!(
        analyzed_id == Some(scan_id),
        "analyze returned scan {analyzed_id:?}, not the POST's {scan_id}"
    );
    let tests = analysis["tests"]
        .as_object()
        .ok_or_else(|| eyre::eyre!("no tests in the analysis of scan {scan_id}"))?
        .iter()
        .map(|(name, test)| {
            (
                name.clone(),
                (
                    test["result"].as_str().unwrap_or_default().to_string(),
                    test["score_modifier"].as_i64().unwrap_or_default(),
                ),
            )
        })
        .collect();
    Ok(ApiOutcome::Graded {
        scan_id,
        scanned_at: body["scanned_at"].as_str().unwrap_or_default().to_string(),
        algorithm_version: body["algorithm_version"].as_u64().unwrap_or_default(),
        score: body["score"].as_i64().unwrap_or_default(),
        grade: body["grade"].as_str().unwrap_or_default().to_string(),
        tests,
    })
}

/// What one pair of runs, the API's and scan's, came to.
#[derive(Debug, PartialEq)]
enum PairVerdict {
    /// Both graded, and every compared field is identical.
    Agree,
    /// Both report the site down: nothing was compared, so the pair is retried.
    BothDown,
    /// The sides differ, each difference named.
    Differ(Vec<String>),
}

/// The verdict on one pair: agreement only when both sides graded and [`differences`] finds none.
fn pair_verdict(api: &ApiOutcome, local: &ObservatoryOutcome) -> PairVerdict {
    if let (ApiOutcome::SiteDown { .. }, ObservatoryOutcome::Failed { reason, .. }) = (api, local)
        && reason == "site down"
    {
        return PairVerdict::BothDown;
    }
    let found = differences(api, local);
    if found.is_empty() { PairVerdict::Agree } else { PairVerdict::Differ(found) }
}

/// Every difference between the API's result and ours, empty when they agree. Compares each test's
/// result string and modifier, the score, the grade and the algorithm version; never `pass`, which
/// the API nulls for not-applicable results. Any side without a grade is a difference: there is
/// nothing to compare.
fn differences(api: &ApiOutcome, local: &ObservatoryOutcome) -> Vec<String> {
    match (api, local) {
        (ApiOutcome::SiteDown { message }, other) => {
            vec![format!("API: {message:?}; scan: {}", other.grade_text())]
        }
        (ApiOutcome::Graded { grade, score, .. }, ObservatoryOutcome::Failed { reason, .. }) => {
            vec![format!("API: {grade} ({score}); scan: no grade ({reason})")]
        }
        (ApiOutcome::Graded { grade, score, .. }, ObservatoryOutcome::NotApplicable(reason)) => {
            vec![format!("API: {grade} ({score}); scan: n/a ({reason})")]
        }
        (
            ApiOutcome::Graded {
                algorithm_version,
                score,
                grade,
                tests,
                ..
            },
            ObservatoryOutcome::Graded(local),
        ) => graded_differences(*algorithm_version, *score, grade, tests, local),
    }
}

fn graded_differences(
    algorithm_version: u64,
    score: i64,
    grade: &str,
    api_tests: &ApiTests,
    local: &ObservatoryResult,
) -> Vec<String> {
    let mut found = Vec::new();
    if algorithm_version != u64::from(ALGORITHM_VERSION) || local.algorithm_version != ALGORITHM_VERSION {
        found.push(format!(
            "algorithm_version: API {algorithm_version}, scan {}, expected {ALGORITHM_VERSION}",
            local.algorithm_version
        ));
    }
    if score != i64::from(local.score) {
        found.push(format!("score: API {score}, scan {}", local.score));
    }
    if grade != local.grade.as_str() {
        found.push(format!("grade: API {grade}, scan {}", local.grade));
    }
    for test in &local.tests {
        match api_tests.get(test.name) {
            None => found.push(format!("{}: absent from the API's tests", test.name)),
            Some((result, modifier)) => {
                if result != test.result.as_str() {
                    found.push(format!("{}: API {result}, scan {}", test.name, test.result.as_str()));
                }
                if *modifier != i64::from(test.score_modifier) {
                    found.push(format!(
                        "{} modifier: API {modifier}, scan {}",
                        test.name, test.score_modifier
                    ));
                }
            }
        }
    }
    for name in api_tests.keys() {
        if !local.tests.iter().any(|t| t.name == name) {
            found.push(format!("{name}: absent from scan's tests"));
        }
    }
    found
}

/// sha256 of the cached Chromium list, the fingerprint a disputed grade is traced with.
fn preload_fingerprint(cache_dir: Option<&std::path::Path>) -> String {
    let Some(path) = cache_dir.map(|dir| dir.join(PRELOAD_CACHE_FILE)) else {
        return "no cache dir".to_string();
    };
    match std::fs::read(&path) {
        Ok(bytes) => openssl::sha::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        Err(e) => format!("unreadable ({}: {e})", path.display()),
    }
}

/// The provenance of one comparison: the API's scan, what scan computed, and the preload list.
fn provenance(host: &str, api: &ApiOutcome, local: &ObservatoryOutcome) -> String {
    let api_side = match api {
        ApiOutcome::Graded {
            scan_id,
            scanned_at,
            grade,
            score,
            ..
        } => format!("scan id {scan_id}, scanned_at {scanned_at}, {grade} ({score})"),
        ApiOutcome::SiteDown { message } => format!("{message:?}"),
    };
    let local_side = match local {
        ObservatoryOutcome::Graded(result) => format!(
            "{} ({}), verified={}, preload_available={}",
            result.grade, result.score, result.verified, result.preload_available
        ),
        other => other.grade_text(),
    };
    format!(
        "{host}\n    API: {api_side}\n    scan: {local_side}\n    preload sha256: {}",
        preload_fingerprint(crate::scan::cache::default_cache_dir().as_deref())
    )
}

/// The auto session's effective URL, for a mismatch's provenance: the retrieval's own redirect
/// chain, from a second retrieval of the host.
async fn effective_url(host: &str) -> String {
    let client = reqwest::Client::builder().timeout(FETCH_TIMEOUT).build().unwrap();
    let lists = SuffixList::new(client)
        .cached_source()
        .load(
            tokio::time::Instant::now() + LOCAL_DEADLINE,
            crate::scan::psl::parse_suffixes,
        )
        .await;
    let (Ok(lists), Ok(retriever)) = (lists, crate::scan::observatory::Retriever::standard()) else {
        return "unavailable".to_string();
    };
    match retriever.retrieve(host, &lists.all).await {
        Ok(retrieval) => retrieval
            .auto()
            .map(|session| {
                session
                    .redirects
                    .last()
                    .map_or(session.url.to_string(), |hop| hop.url.to_string())
            })
            .unwrap_or_else(|| "no session answered".to_string()),
        Err(e) => format!("retrieval failed: {e}"),
    }
}

#[tokio::test]
#[ignore = "calls the live MDN HTTP Observatory API and the sites it grades"]
async fn scan_matches_the_live_observatory_api() {
    let client = api_client();
    let scanner = HttpScanner::new();
    let mut disputes = Vec::new();

    for host in HOSTS {
        let mut last_report = String::new();
        let mut agreed = false;
        for pair in 1..=PAIR_ATTEMPTS {
            if pair > 1 {
                println!("{host}: retrying the pair after the API's cooldown");
                tokio::time::sleep(API_COOLDOWN).await;
            }
            let api = api_scan(&client, host)
                .await
                .unwrap_or_else(|e| panic!("{host}: API failed: {e:#}"));
            let deadline = tokio::time::Instant::now() + LOCAL_DEADLINE;
            let local = scanner.grade_host(host, deadline).await;
            println!(
                "{host} (pair {pair}/{PAIR_ATTEMPTS}): {}",
                provenance(host, &api, &local)
            );
            let found = match pair_verdict(&api, &local) {
                PairVerdict::Agree => {
                    println!("{host}: identical");
                    agreed = true;
                    break;
                }
                PairVerdict::BothDown => {
                    println!("{host}: both sides report the site down; nothing compared, retrying");
                    vec!["both sides report the site down: no graded pair to compare".to_string()]
                }
                PairVerdict::Differ(found) => found,
            };
            last_report = format!(
                "pair {pair}/{PAIR_ATTEMPTS}: {}\n    effective URL: {}\n    differences:\n      {}",
                provenance(host, &api, &local),
                effective_url(host).await,
                found.join("\n      ")
            );
        }
        if !agreed {
            disputes.push(last_report);
        }
    }

    assert!(
        disputes.is_empty(),
        "scan disagrees with the live Observatory API:\n{}",
        disputes.join("\n")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::tests::google_com_result;

    fn api_matching(local: &ObservatoryResult) -> ApiOutcome {
        ApiOutcome::Graded {
            scan_id: 1,
            scanned_at: "2026-10-30T00:00:00.000Z".to_string(),
            algorithm_version: 6,
            score: i64::from(local.score),
            grade: local.grade.to_string(),
            tests: local
                .tests
                .iter()
                .map(|t| {
                    (
                        t.name.to_string(),
                        (t.result.as_str().to_string(), i64::from(t.score_modifier)),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn identical_results_have_no_differences() {
        let local = google_com_result();
        let outcome = ObservatoryOutcome::Graded(local.clone());
        assert!(differences(&api_matching(&local), &outcome).is_empty());
    }

    /// The comparison bites: each kind of disagreement is reported by name.
    #[test]
    fn every_kind_of_disagreement_is_named() {
        let local = google_com_result();
        let outcome = ObservatoryOutcome::Graded(local.clone());

        let mut api = api_matching(&local);
        if let ApiOutcome::Graded {
            tests,
            score,
            grade,
            algorithm_version,
            ..
        } = &mut api
        {
            tests.get_mut("cookies").unwrap().0 = "cookies-no-secure-flag".to_string();
            tests.get_mut("redirection").unwrap().1 += 5;
            tests.remove("referrer-policy");
            *score += 5;
            *grade = "B".to_string();
            *algorithm_version = 7;
        }
        let found = differences(&api, &outcome).join("\n");
        for expected in [
            "algorithm_version: API 7",
            "score: API 50, scan 45",
            "grade: API B, scan C-",
            "cookies: API cookies-no-secure-flag",
            "redirection modifier",
            "referrer-policy: absent from the API's tests",
        ] {
            assert!(found.contains(expected), "{expected}:\n{found}");
        }
    }

    #[test]
    fn identical_graded_results_agree() {
        let local = google_com_result();
        assert_eq!(
            pair_verdict(&api_matching(&local), &ObservatoryOutcome::Graded(local.clone())),
            PairVerdict::Agree
        );
    }

    /// Audit: both sides down compares nothing, so it is a retry, never agreement; one side down
    /// is a difference.
    #[test]
    fn site_down_on_both_sides_is_a_retry_and_one_sided_is_a_difference() {
        let down = ApiOutcome::SiteDown {
            message: "The site seems to be down.".to_string(),
        };
        let local_down = ObservatoryOutcome::failed("neverssl.com", "site down");
        assert_eq!(pair_verdict(&down, &local_down), PairVerdict::BothDown);
        assert_ne!(pair_verdict(&down, &local_down), PairVerdict::Agree);
        assert_eq!(differences(&down, &local_down).len(), 1);
        let graded = ObservatoryOutcome::Graded(google_com_result());
        assert!(matches!(pair_verdict(&down, &graded), PairVerdict::Differ(found) if found.len() == 1));
        let api = api_matching(&google_com_result());
        assert!(matches!(pair_verdict(&api, &local_down), PairVerdict::Differ(found) if found.len() == 1));
        assert_eq!(
            differences(&api, &ObservatoryOutcome::NotApplicable("IP address".to_string())).len(),
            1
        );
    }
}
