//! The public suffix list lookup shared by WHOIS (which domain to query RDAP for) and DNS (where
//! DMARC's organizational fallback looks). Fetched and cached through `scan::cache`.

use crate::scan::cache::{CachedSource, FETCH_TIMEOUT, default_cache_dir};
use publicsuffix::{IcannList, List, Psl};
use reqwest::Client;
use std::path::PathBuf;
use std::time::Duration;

/// The public suffix list; its ICANN section names the registrable domain of a host.
pub const PSL_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";
pub const PSL_CACHE_FILE: &str = "public_suffix_list.dat";

/// Marks the start of the ICANN section in the public suffix list.
const PSL_ICANN_MARKER: &str = "===BEGIN ICANN DOMAINS===";

/// Where the suffix list comes from and where it is cached.
#[derive(Debug, Clone)]
pub struct SuffixList {
    pub client: Client,
    pub url: String,
    /// `None` when the platform has no cache dir: every lookup fetches.
    pub cache_dir: Option<PathBuf>,
    /// Bound on one fetch, taken from inside the caller's deadline.
    pub fetch_timeout: Duration,
}

impl SuffixList {
    /// The published list, cached in `~/.cache/scan`.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            url: PSL_URL.to_string(),
            cache_dir: default_cache_dir(),
            fetch_timeout: FETCH_TIMEOUT,
        }
    }

    /// The cached file this list is read from.
    pub fn cached_source(&self) -> CachedSource<'_> {
        CachedSource {
            client: &self.client,
            url: &self.url,
            cache_dir: self.cache_dir.as_deref(),
            file_name: PSL_CACHE_FILE,
            fetch_timeout: self.fetch_timeout,
        }
    }

    /// The registrable domain of `host` under the ICANN section of the public suffix list:
    /// `www.tatari.tv` -> `tatari.tv`. `Ok(None)` when the host has none (`localhost`, a bare
    /// public suffix, a name `idna` rejects). `Err` when the suffix list is unavailable.
    pub async fn registrable_domain(&self, host: &str, deadline: tokio::time::Instant) -> eyre::Result<Option<String>> {
        log::debug!("[scan::psl] registrable_domain: host={}", host);
        let ascii = match idna::domain_to_ascii(host.trim_end_matches('.')) {
            Ok(ascii) => ascii,
            Err(e) => {
                log::debug!("[scan::psl] host_not_a_domain_name: host={} error={}", host, e);
                return Ok(None);
            }
        };
        let list = self.cached_source().load(deadline, parse_suffix_list).await?;
        let domain = list
            .domain(ascii.as_bytes())
            .map(|d| String::from_utf8_lossy(d.as_bytes()).into_owned());
        log::debug!(
            "[scan::psl] registrable_domain_found: host={} ascii={} domain={:?}",
            host,
            ascii,
            domain
        );
        Ok(domain)
    }
}

/// The ICANN section only: the PRIVATE section would make `github.io` a public suffix, so
/// `foo.github.io` would be its own registrable domain. A list without the ICANN marker is corrupt:
/// the crate accepts PRIVATE rules alone, and an empty ICANN section maps `a.b.co.uk` to `co.uk`.
fn parse_suffix_list(text: &str) -> eyre::Result<IcannList> {
    if !text.contains(PSL_ICANN_MARKER) {
        return Err(eyre::eyre!(
            "public suffix list has no ICANN section ({} missing)",
            PSL_ICANN_MARKER
        ));
    }
    text.parse::<IcannList>()
        .map_err(|e| eyre::eyre!("public suffix list does not parse: {}", e))
}

/// Both readings of the one public suffix file: the ICANN section alone (what `tldts` reads by
/// default, the SRI test) and ICANN plus PRIVATE (what tough-cookie's jar rules read).
pub struct Suffixes {
    pub icann: IcannList,
    pub all: List,
}

/// Both lists from one file, under the same corruption check as [`parse_suffix_list`].
pub fn parse_suffixes(text: &str) -> eyre::Result<Suffixes> {
    let icann = parse_suffix_list(text)?;
    let all = text
        .parse::<List>()
        .map_err(|e| eyre::eyre!("public suffix list does not parse: {}", e))?;
    Ok(Suffixes { icann, all })
}

/// ICANN section plus a PRIVATE entry, so a test can tell which section was read.
#[cfg(test)]
pub const PSL_FIXTURE: &str = "// ===BEGIN ICANN DOMAINS===\ntv\nuk\nco.uk\nio\ndev\nde\ncom\n\
                               // ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n\
                               // ===END PRIVATE DOMAINS===\n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::testing::{FakeHttp, temp_dir};

    async fn fake_list(body: &str) -> (FakeHttp, SuffixList) {
        let fake = FakeHttp::start(vec![("/psl", 200, body.to_string())]).await;
        let list = SuffixList {
            client: Client::builder().no_proxy().build().unwrap(),
            url: fake.url("/psl"),
            cache_dir: Some(temp_dir("psl")),
            fetch_timeout: FETCH_TIMEOUT,
        };
        (fake, list)
    }

    fn far_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(5)
    }

    /// The registrable domain under the ICANN section only, from a lowercased, punycoded host.
    #[tokio::test]
    async fn registrable_domain_is_the_icann_registrable_domain() {
        let (_fake, list) = fake_list(PSL_FIXTURE).await;
        for (host, expected) in [
            ("www.tatari.tv", "tatari.tv"),
            ("a.b.co.uk", "b.co.uk"),
            ("foo.github.io", "github.io"),
            ("WWW.Tatari.TV.", "tatari.tv"),
            ("www.bücher.de", "xn--bcher-kva.de"),
        ] {
            let domain = list.registrable_domain(host, far_deadline()).await.unwrap();
            assert_eq!(domain.as_deref(), Some(expected), "{host}");
        }
    }

    #[tokio::test]
    async fn host_without_a_registrable_domain_has_none() {
        let (_fake, list) = fake_list(PSL_FIXTURE).await;
        for host in ["localhost", "co.uk", "tv"] {
            assert_eq!(
                list.registrable_domain(host, far_deadline()).await.unwrap(),
                None,
                "{host}"
            );
        }
    }

    #[test]
    fn suffix_list_without_an_icann_section_is_corrupt() {
        assert!(parse_suffix_list("<html>captive portal</html>").is_err());
        assert!(parse_suffix_list(PSL_FIXTURE).is_ok());
    }

    /// One file, two readings: `github.io` is a suffix only when the PRIVATE section counts, so
    /// the jar's list and the SRI test's list disagree on `foo.github.io` as they should.
    #[test]
    fn suffixes_read_the_one_file_with_and_without_the_private_section() {
        let suffixes = parse_suffixes(PSL_FIXTURE).unwrap();
        assert_eq!(
            suffixes.icann.domain(b"foo.github.io").map(|d| d.as_bytes().to_vec()),
            Some(b"github.io".to_vec())
        );
        assert_eq!(
            suffixes.all.domain(b"foo.github.io").map(|d| d.as_bytes().to_vec()),
            Some(b"foo.github.io".to_vec())
        );
        assert!(parse_suffixes("<html>captive portal</html>").is_err());
    }

    /// PRIVATE rules alone parse in the crate, which counts rules of either section, and an empty
    /// ICANN section then makes `a.b.co.uk` resolve to `co.uk`.
    #[test]
    fn suffix_list_with_only_a_private_section_is_corrupt() {
        let private_only = "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n";
        let error = parse_suffix_list(private_only).expect_err("a list with no ICANN section must not parse");
        assert!(error.to_string().contains("ICANN"), "{error:#}");
    }

    /// A PRIVATE-only body is not cached, so the next lookup refetches it.
    #[tokio::test]
    async fn fetched_suffix_list_without_an_icann_section_is_not_cached() {
        let (fake, list) = fake_list("// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n").await;

        for _ in 0..2 {
            assert!(list.registrable_domain("a.b.co.uk", far_deadline()).await.is_err());
        }

        assert_eq!(fake.hits("/psl"), 2);
        assert!(!list.cache_dir.as_ref().unwrap().join(PSL_CACHE_FILE).exists());
    }

    /// A second lookup within 24h reads the cache file the first one wrote.
    #[tokio::test]
    async fn second_lookup_within_24h_reads_the_cache() {
        let (fake, list) = fake_list(PSL_FIXTURE).await;
        for _ in 0..2 {
            list.registrable_domain("www.tatari.tv", far_deadline()).await.unwrap();
        }
        assert_eq!(fake.hits("/psl"), 1);
        assert!(list.cache_dir.as_ref().unwrap().join(PSL_CACHE_FILE).exists());
    }
}
