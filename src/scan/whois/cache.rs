//! Fetched data files the WHOIS scanner caches on disk: the public suffix list and the IANA RDAP
//! bootstrap. Both change faster than the code, so they are fetched, not compiled in.

use reqwest::Client;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// How long a cached file is used before it is refetched. IANA serves `dns.json` with
/// `max-age=86400`.
pub const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Bound on one fetch of a cached file, taken from inside the caller's deadline, so a hung fetch
/// leaves the rest of the RDAP budget for the RDAP query.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Time the outer timer gives past reqwest's own request timeout, so a hung fetch normally fails
/// with reqwest's classified error, which names the stage, not the bare outer deadline.
const FETCH_DEADLINE_GRACE: Duration = Duration::from_secs(1);

/// Distinguishes temp files written by concurrent fetches inside one process.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One fetched, cached data file.
pub struct CachedSource<'a> {
    pub client: &'a Client,
    pub url: &'a str,
    /// `None` when there is no cache directory: every lookup fetches.
    pub cache_dir: Option<&'a Path>,
    pub file_name: &'a str,
    /// Bound on one fetch; the fetch gets the smaller of this and the time left on the deadline.
    pub fetch_timeout: Duration,
}

impl CachedSource<'_> {
    /// The parsed file. A cache younger than `CACHE_MAX_AGE` is used as is; otherwise the file is
    /// fetched within `deadline`, and a failed fetch falls back to a stale cache of any age. A cache
    /// file that does not parse is treated as missing. Errors only when there is neither a fetch
    /// nor a usable cache.
    pub async fn load<T>(
        &self,
        deadline: tokio::time::Instant,
        parse: impl Fn(&str) -> eyre::Result<T>,
    ) -> eyre::Result<T> {
        log::debug!(
            "[scan::whois::cache] load: file={} url={} cache_dir={:?}",
            self.file_name,
            self.url,
            self.cache_dir
        );

        let cached = self.read_cache(&parse).await;
        let stale = match cached {
            Some((value, age)) if age < CACHE_MAX_AGE => {
                log::debug!(
                    "[scan::whois::cache] cache_fresh: file={} age={}s",
                    self.file_name,
                    age.as_secs()
                );
                return Ok(value);
            }
            other => other,
        };

        let fetched = self.bounded_fetch(deadline).await.map_err(|failure| failure.error);
        let refresh_error = match fetched.and_then(|text| parse(&text).map(|value| (text, value))) {
            Ok((text, value)) => {
                self.write_cache(&text).await;
                log::debug!(
                    "[scan::whois::cache] fetched: file={} bytes={}",
                    self.file_name,
                    text.len()
                );
                return Ok(value);
            }
            Err(e) => e,
        };

        match stale {
            Some((value, age)) => {
                log::warn!(
                    "[scan::whois::cache] refresh_failed_using_stale_cache: file={} age={}s error={:#}",
                    self.file_name,
                    age.as_secs(),
                    refresh_error
                );
                Ok(value)
            }
            None => {
                log::warn!(
                    "[scan::whois::cache] refresh_failed_no_cache: file={} error={:#}",
                    self.file_name,
                    refresh_error
                );
                Err(refresh_error)
            }
        }
    }

    fn cache_path(&self) -> Option<PathBuf> {
        self.cache_dir.map(|dir| dir.join(self.file_name))
    }

    /// The cached value and its age; `None` when the file is missing, unreadable or corrupt.
    async fn read_cache<T>(&self, parse: &impl Fn(&str) -> eyre::Result<T>) -> Option<(T, Duration)> {
        let path = self.cache_path()?;
        let modified = match tokio::fs::metadata(&path).await.and_then(|m| m.modified()) {
            Ok(modified) => modified,
            Err(e) => {
                log::debug!(
                    "[scan::whois::cache] cache_missing: path={} error={}",
                    path.display(),
                    e
                );
                return None;
            }
        };
        // A modification time in the future reads as age zero.
        let age = SystemTime::now().duration_since(modified).unwrap_or(Duration::ZERO);
        let text = match tokio::fs::read_to_string(&path).await {
            Ok(text) => text,
            Err(e) => {
                log::warn!(
                    "[scan::whois::cache] cache_unreadable: path={} error={}",
                    path.display(),
                    e
                );
                return None;
            }
        };
        match parse(&text) {
            Ok(value) => {
                log::debug!(
                    "[scan::whois::cache] cache_read: path={} age={}s",
                    path.display(),
                    age.as_secs()
                );
                Some((value, age))
            }
            Err(e) => {
                log::warn!(
                    "[scan::whois::cache] cache_corrupt_treated_as_missing: path={} error={:#}",
                    path.display(),
                    e
                );
                None
            }
        }
    }

    /// One fetch within `deadline`: reqwest's request timeout is the smaller of `fetch_timeout` and
    /// the time left, and the outer timer gives it `FETCH_DEADLINE_GRACE` more, still capped by the
    /// time left. A failure is logged at WARN with its elapsed time, class and detail, so the log
    /// names the stage that failed.
    async fn bounded_fetch(&self, deadline: tokio::time::Instant) -> Result<String, FetchFailure> {
        let (limit, window) = fetch_bounds(
            self.fetch_timeout,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        );
        log::debug!(
            "[scan::whois::cache] bounded_fetch: url={} limit={:?} window={:?}",
            self.url,
            limit,
            window
        );
        let started = Instant::now();
        let fetched = match tokio::time::timeout(window, self.fetch(limit)).await {
            Ok(fetched) => fetched,
            Err(_) => Err(FetchFailure {
                class: "deadline".to_string(),
                detail: format!("window={:?}", window),
                error: eyre::eyre!("{} fetch timed out after {:?}", self.url, window),
            }),
        };
        match &fetched {
            Ok(text) => log::debug!(
                "[scan::whois::cache] fetch_succeeded: url={} elapsed={}ms bytes={}",
                self.url,
                started.elapsed().as_millis(),
                text.len()
            ),
            Err(failure) => log::warn!(
                "[scan::whois::cache] fetch_failed: url={} elapsed={}ms class={} {}",
                self.url,
                started.elapsed().as_millis(),
                failure.class,
                failure.detail
            ),
        }
        fetched
    }

    /// One GET bounded by `limit` (reqwest's request timeout covers connect, TLS and body).
    async fn fetch(&self, limit: Duration) -> Result<String, FetchFailure> {
        log::debug!("[scan::whois::cache] fetch: url={} limit={:?}", self.url, limit);
        let response = self
            .client
            .get(self.url)
            .timeout(limit)
            .send()
            .await
            .map_err(|e| self.reqwest_failure("fetch failed", limit, &e))?;
        if !response.status().is_success() {
            return Err(FetchFailure {
                class: "status".to_string(),
                detail: format!("status={}", response.status()),
                error: eyre::eyre!("{} returned {}", self.url, response.status()),
            });
        }
        response
            .text()
            .await
            .map_err(|e| self.reqwest_failure("body read failed", limit, &e))
    }

    /// reqwest's error class and source chain for the log; for the caller, a timeout names the
    /// limit it hit and anything else carries the chain, since reqwest's own message ("error
    /// sending request") hides the cause.
    fn reqwest_failure(&self, what: &str, limit: Duration, error: &reqwest::Error) -> FetchFailure {
        let chain = error_chain(error);
        let report = if error.is_timeout() {
            eyre::eyre!("{} fetch timed out after {:?}", self.url, limit)
        } else {
            eyre::eyre!("{} {}: {}", self.url, what, chain)
        };
        FetchFailure {
            class: reqwest_error_class(error),
            detail: format!("chain={}", chain),
            error: report,
        }
    }

    /// Writes a temp file in the cache dir, then renames it over the cache file, so a concurrent
    /// reader never sees half a file. A failure is logged; the fetched data is still used.
    async fn write_cache(&self, text: &str) {
        let (Some(dir), Some(path)) = (self.cache_dir, self.cache_path()) else {
            log::debug!(
                "[scan::whois::cache] no_cache_dir: file={} kept in memory only",
                self.file_name
            );
            return;
        };
        let temp = dir.join(format!(
            ".{}.{}.{}.tmp",
            self.file_name,
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let written = async {
            tokio::fs::create_dir_all(dir).await?;
            tokio::fs::write(&temp, text).await?;
            tokio::fs::rename(&temp, &path).await
        }
        .await;
        if let Err(e) = written {
            let _ = tokio::fs::remove_file(&temp).await;
            log::warn!(
                "[scan::whois::cache] cache_write_failed: path={} error={}; using fetched data in memory",
                path.display(),
                e
            );
        }
    }
}

/// reqwest's request timeout and the outer timer for one fetch with `remaining` left on the
/// deadline: the limit is the smaller of `fetch_timeout` and `remaining`, and the outer timer runs
/// `FETCH_DEADLINE_GRACE` past it, never past `remaining`.
fn fetch_bounds(fetch_timeout: Duration, remaining: Duration) -> (Duration, Duration) {
    let limit = fetch_timeout.min(remaining);
    (limit, (limit + FETCH_DEADLINE_GRACE).min(remaining))
}

/// A failed fetch: what the WARN logs, and the error the caller gets.
struct FetchFailure {
    /// reqwest's error flags (`connect`, `timeout+request`), `status`, or `deadline` when the outer
    /// timer fired first.
    class: String,
    /// `chain=<reqwest source chain>`, `status=<code>` or `window=<outer timer>`.
    detail: String,
    error: eyre::Report,
}

/// The reqwest error flags that are set, e.g. `connect+timeout`; `other` when none is.
fn reqwest_error_class(error: &reqwest::Error) -> String {
    let flags = [
        ("connect", error.is_connect()),
        ("timeout", error.is_timeout()),
        ("request", error.is_request()),
        ("body", error.is_body()),
        ("decode", error.is_decode()),
    ];
    let set: Vec<&str> = flags.iter().filter(|(_, on)| *on).map(|(name, _)| *name).collect();
    if set.is_empty() { "other".to_string() } else { set.join("+") }
}

/// `error` and each `source()` below it, joined with `: `.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    while let Some(cause) = source {
        parts.push(cause.to_string());
        source = cause.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::testing::{FakeHttp, dead_http_url, temp_dir};

    fn parse_nonempty(text: &str) -> eyre::Result<String> {
        if text.starts_with("ok:") {
            Ok(text.to_string())
        } else {
            Err(eyre::eyre!("not a fixture: {:?}", text))
        }
    }

    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(5)
    }

    fn source<'a>(client: &'a Client, url: &'a str, dir: &'a Path) -> CachedSource<'a> {
        CachedSource {
            client,
            url,
            cache_dir: Some(dir),
            file_name: "data.txt",
            fetch_timeout: FETCH_TIMEOUT,
        }
    }

    fn set_age(path: &Path, age: Duration) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - age).unwrap();
    }

    #[tokio::test]
    async fn a_second_load_within_24h_makes_no_fetch() {
        let fake = FakeHttp::start(vec![("/data", 200, "ok:one".to_string())]).await;
        let dir = temp_dir("cache-second-load");
        let client = Client::builder().no_proxy().build().unwrap();
        let url = fake.url("/data");

        let first = source(&client, &url, &dir)
            .load(deadline(), parse_nonempty)
            .await
            .unwrap();
        let second = source(&client, &url, &dir)
            .load(deadline(), parse_nonempty)
            .await
            .unwrap();

        assert_eq!((first.as_str(), second.as_str()), ("ok:one", "ok:one"));
        assert_eq!(fake.hits("/data"), 1);
        assert_eq!(std::fs::read_to_string(dir.join("data.txt")).unwrap(), "ok:one");
    }

    #[tokio::test]
    async fn a_cache_older_than_24h_is_refetched() {
        let fake = FakeHttp::start(vec![("/data", 200, "ok:new".to_string())]).await;
        let dir = temp_dir("cache-expired");
        std::fs::write(dir.join("data.txt"), "ok:old").unwrap();
        set_age(&dir.join("data.txt"), CACHE_MAX_AGE + Duration::from_secs(60));
        let client = Client::builder().no_proxy().build().unwrap();
        let url = fake.url("/data");

        let value = source(&client, &url, &dir)
            .load(deadline(), parse_nonempty)
            .await
            .unwrap();

        assert_eq!(value, "ok:new");
        assert_eq!(fake.hits("/data"), 1);
        assert_eq!(std::fs::read_to_string(dir.join("data.txt")).unwrap(), "ok:new");
    }

    #[tokio::test]
    async fn a_stale_cache_is_used_when_the_refresh_fails() {
        let dir = temp_dir("cache-stale");
        std::fs::write(dir.join("data.txt"), "ok:stale").unwrap();
        set_age(&dir.join("data.txt"), Duration::from_secs(400 * 24 * 60 * 60));
        let client = Client::builder().no_proxy().build().unwrap();
        let url = dead_http_url().await;

        let value = source(&client, &url, &dir)
            .load(deadline(), parse_nonempty)
            .await
            .unwrap();

        assert_eq!(value, "ok:stale");
    }

    #[tokio::test]
    async fn a_corrupt_cache_is_treated_as_missing_and_refetched() {
        let fake = FakeHttp::start(vec![("/data", 200, "ok:fresh".to_string())]).await;
        let dir = temp_dir("cache-corrupt");
        std::fs::write(dir.join("data.txt"), "<html>garbage").unwrap();
        let client = Client::builder().no_proxy().build().unwrap();
        let url = fake.url("/data");

        let value = source(&client, &url, &dir)
            .load(deadline(), parse_nonempty)
            .await
            .unwrap();

        assert_eq!(value, "ok:fresh");
        assert_eq!(fake.hits("/data"), 1);
        assert_eq!(std::fs::read_to_string(dir.join("data.txt")).unwrap(), "ok:fresh");
    }

    #[tokio::test]
    async fn no_cache_and_a_failed_fetch_is_an_error_naming_the_url() {
        let dir = temp_dir("cache-none");
        let client = Client::builder().no_proxy().build().unwrap();
        let url = dead_http_url().await;

        let err = source(&client, &url, &dir)
            .load(deadline(), parse_nonempty)
            .await
            .unwrap_err();

        assert!(err.to_string().starts_with(&format!("{url} fetch failed: ")), "{err:#}");
    }

    #[tokio::test]
    async fn a_fetched_body_that_does_not_parse_is_an_error_and_is_not_cached() {
        let fake = FakeHttp::start(vec![("/data", 200, "<html>captive portal".to_string())]).await;
        let dir = temp_dir("cache-bad-body");
        let client = Client::builder().no_proxy().build().unwrap();
        let url = fake.url("/data");

        let err = source(&client, &url, &dir)
            .load(deadline(), parse_nonempty)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("not a fixture"), "{err:#}");
        assert!(!dir.join("data.txt").exists());
    }

    #[tokio::test]
    async fn an_unwritable_cache_dir_still_returns_the_fetched_data() {
        let fake = FakeHttp::start(vec![("/data", 200, "ok:memory".to_string())]).await;
        let parent = temp_dir("cache-unwritable");
        let blocker = parent.join("not-a-dir");
        std::fs::write(&blocker, "a file where the cache dir should be").unwrap();
        let dir = blocker.join("scan");
        let client = Client::builder().no_proxy().build().unwrap();
        let url = fake.url("/data");

        let value = source(&client, &url, &dir)
            .load(deadline(), parse_nonempty)
            .await
            .unwrap();

        assert_eq!(value, "ok:memory");
        assert!(!dir.exists());
    }

    /// The per-fetch limit cuts a hung fetch off well before the deadline, leaving the rest of
    /// the caller's budget.
    #[tokio::test]
    async fn a_hung_fetch_gives_up_at_the_fetch_timeout_not_the_deadline() {
        let silent = crate::scan::testing::silent_http_url().await;
        let dir = temp_dir("cache-fetch-timeout");
        let client = Client::builder().no_proxy().build().unwrap();
        let started = std::time::Instant::now();

        let err = CachedSource {
            fetch_timeout: Duration::from_millis(300),
            ..source(&client, &silent, &dir)
        }
        .load(tokio::time::Instant::now() + Duration::from_secs(5), parse_nonempty)
        .await
        .unwrap_err();

        assert!(err.to_string().contains("300ms"), "{err:#}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
    }

    /// Audit round 1: the outer timer runs `FETCH_DEADLINE_GRACE` past reqwest's own timeout, so a
    /// hung fetch fails with reqwest's timeout class, which names the stage, not `deadline`.
    #[tokio::test]
    async fn a_hung_fetch_fails_with_reqwests_timeout_class_not_the_deadline() {
        let silent = crate::scan::testing::silent_http_url().await;
        let dir = temp_dir("cache-fetch-class");
        let client = Client::builder().no_proxy().build().unwrap();

        let failure = CachedSource {
            fetch_timeout: Duration::from_millis(300),
            ..source(&client, &silent, &dir)
        }
        .bounded_fetch(tokio::time::Instant::now() + Duration::from_secs(5))
        .await
        .expect_err("the server never answers");

        assert!(failure.class.contains("timeout"), "class={}", failure.class);
        assert!(failure.detail.starts_with("chain="), "detail={}", failure.detail);
        assert!(
            failure.error.to_string().contains("timed out after 300ms"),
            "{:#}",
            failure.error
        );
    }

    /// Audit round 1: the outer timer outlasts reqwest's timeout by the grace when the deadline
    /// allows, and never outlasts the deadline.
    #[test]
    fn the_outer_timer_runs_a_grace_past_the_fetch_limit_within_the_deadline() {
        let secs = Duration::from_secs;
        assert_eq!(fetch_bounds(secs(10), secs(30)), (secs(10), secs(11)));
        assert_eq!(
            fetch_bounds(secs(10), Duration::from_millis(10_500)),
            (secs(10), Duration::from_millis(10_500))
        );
        assert_eq!(
            fetch_bounds(secs(10), Duration::from_millis(300)),
            (Duration::from_millis(300), Duration::from_millis(300))
        );
        assert_eq!(fetch_bounds(secs(10), Duration::ZERO), (Duration::ZERO, Duration::ZERO));
    }

    /// The deadline still caps the outer timer: with less time left than the fetch limit plus the
    /// grace, the fetch ends at the deadline.
    #[tokio::test]
    async fn the_grace_never_runs_past_the_deadline() {
        let silent = crate::scan::testing::silent_http_url().await;
        let dir = temp_dir("cache-fetch-grace-capped");
        let client = Client::builder().no_proxy().build().unwrap();
        let started = std::time::Instant::now();

        let failure = source(&client, &silent, &dir)
            .bounded_fetch(tokio::time::Instant::now() + Duration::from_millis(300))
            .await
            .expect_err("the server never answers");

        assert!(
            failure.error.to_string().contains("fetch timed out"),
            "{:#}",
            failure.error
        );
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn reqwest_error_class_names_a_refused_connect() {
        let url = dead_http_url().await;
        let client = Client::builder().no_proxy().build().unwrap();
        let error = client.get(&url).send().await.unwrap_err();
        assert!(reqwest_error_class(&error).contains("connect"), "{error:?}");
        assert!(error_chain(&error).contains(": "), "{}", error_chain(&error));
    }

    #[tokio::test]
    async fn the_fetch_is_bounded_by_the_deadline() {
        let silent = crate::scan::testing::silent_http_url().await;
        let dir = temp_dir("cache-deadline");
        let client = Client::builder().no_proxy().build().unwrap();
        let started = std::time::Instant::now();

        let err = source(&client, &silent, &dir)
            .load(tokio::time::Instant::now() + Duration::from_millis(300), parse_nonempty)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("fetch timed out"), "{err:#}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
    }
}
