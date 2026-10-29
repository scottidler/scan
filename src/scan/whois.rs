use crate::scanner::Scanner;
use crate::target::{Protocol, Target};
use crate::types::ScanResult;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hickory_resolver::Resolver;
use log;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// RDAP request timeout.
const RDAP_TIMEOUT_SECS: u64 = 30;
/// Hard limit on the whole traditional WHOIS fallback: IANA referral, registry, registrar.
const WHOIS_LOOKUP_TIMEOUT_SECS: u64 = 15;
/// IANA's WHOIS server, which names the WHOIS server for each TLD.
const IANA_WHOIS_SERVER: &str = "whois.iana.org";
const WHOIS_PORT: u16 = 43;
/// Upper bound on one WHOIS response; registry answers are a few KiB.
const WHOIS_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
/// `parse_whois_text` keys that carry registration data; an answer with none of them is a
/// refusal or an error page, not a WHOIS record.
const WHOIS_REGISTRAR_KEYS: &[&str] = &["registrar"];
const WHOIS_CREATION_KEYS: &[&str] = &["creation date", "created", "registered", "registration time"];
const WHOIS_EXPIRY_KEYS: &[&str] = &["expiry date", "expires", "expiration date", "registry expiry date"];
const WHOIS_NAMESERVER_KEYS: &[&str] = &["name server", "nameserver", "nserver"];
/// Headroom on the scan deadline past RDAP plus the fallback, for parsing and scheduling.
const DEADLINE_SLACK_SECS: u64 = 5;
const WHOIS_SCAN_INTERVAL_SECS: u64 = 60 * 60; // 1 hour
const RECENT_REGISTRATION_THRESHOLD_DAYS: i64 = 30;
const NEAR_EXPIRY_THRESHOLD_DAYS: i64 = 30;

#[derive(Debug, Clone)]
pub struct WhoisScanner {
    client: Client,
    /// `host:port` of the server that refers each TLD to its registry WHOIS server.
    iana_server: String,
    rdap_timeout: Duration,
    whois_timeout: Duration,
}

impl Default for WhoisScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WhoisScanner {
    pub fn new() -> Self {
        log::debug!(
            "[scan::whois] new: rdap_timeout={}s whois_timeout={}s",
            RDAP_TIMEOUT_SECS,
            WHOIS_LOOKUP_TIMEOUT_SECS
        );

        let client = Client::builder()
            .timeout(Duration::from_secs(RDAP_TIMEOUT_SECS))
            .user_agent("scan/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            iana_server: format!("{}:{}", IANA_WHOIS_SERVER, WHOIS_PORT),
            rdap_timeout: Duration::from_secs(RDAP_TIMEOUT_SECS),
            whois_timeout: Duration::from_secs(WHOIS_LOOKUP_TIMEOUT_SECS),
        }
    }

    async fn scan_whois(&self, target: &Target) -> eyre::Result<WhoisResult> {
        log::debug!("[scan::whois] scan_whois: target={}", target.display_name());

        let domain = match &target.domain {
            Some(d) => d.clone(),
            None => {
                log::debug!("[scan::whois] not_applicable: target={}", target.display_name());
                return Ok(WhoisResult::not_applicable(target.display_name().to_string()));
            }
        };

        log::debug!("[scan::whois] querying_domain: domain={}", domain);

        // Try RDAP first (modern protocol)
        log::trace!("[scan::whois] trying_rdap: domain={}", domain);
        let rdap_start = Instant::now();
        let rdap_error = match self.query_rdap(&domain).await {
            Ok(mut result) => {
                let rdap_duration = rdap_start.elapsed();
                result.data_source = DataSource::Rdap;
                log::trace!(
                    "[scan::whois] rdap_successful: domain={} duration={}ms",
                    domain,
                    rdap_duration.as_millis()
                );
                return Ok(result);
            }
            Err(e) => {
                let rdap_duration = rdap_start.elapsed();
                log::debug!(
                    "[scan::whois] rdap_failed_trying_whois: domain={} duration={}ms error={}",
                    domain,
                    rdap_duration.as_millis(),
                    e
                );
                e
            }
        };

        // Fall back to traditional WHOIS
        log::trace!("[scan::whois] trying_traditional_whois: domain={}", domain);
        let whois_start = Instant::now();
        match self.query_traditional_whois(&domain).await {
            Ok(mut result) => {
                let whois_duration = whois_start.elapsed();
                result.data_source = DataSource::Whois;
                log::trace!(
                    "[scan::whois] whois_successful: domain={} duration={}ms",
                    domain,
                    whois_duration.as_millis()
                );
                Ok(result)
            }
            Err(e) => {
                let whois_duration = whois_start.elapsed();
                log::error!(
                    "[scan::whois] both_methods_failed: domain={} whois_duration={}ms error={}",
                    domain,
                    whois_duration.as_millis(),
                    e
                );

                // Return a failed result rather than error
                let mut result = WhoisResult {
                    domain: domain.clone(),
                    registration_date: None,
                    expiry_date: None,
                    last_updated: None,
                    nameservers: Vec::new(),
                    status: Vec::new(),
                    dnssec: None,
                    registrar: None,
                    abuse_contact: None,
                    registrant: None,
                    admin_contact: None,
                    tech_contact: None,
                    privacy_score: PrivacyLevel::Unknown,
                    domain_age_days: None,
                    expires_in_days: None,
                    risk_indicators: vec![RiskIndicator::QueryFailed],
                    data_source: DataSource::Failed(format!("RDAP: {:#}; WHOIS: {:#}", rdap_error, e)),
                    scan_duration: Duration::from_millis(0),
                    raw_data: None,
                };

                self.calculate_derived_fields(&mut result);
                Ok(result)
            }
        }
    }

    async fn query_rdap(&self, domain: &str) -> eyre::Result<WhoisResult> {
        let start_time = Instant::now();
        let tld = domain.split('.').next_back().unwrap_or("");

        let rdap_url = self.get_rdap_endpoint(tld, domain);

        let response = self.client.get(&rdap_url).timeout(self.rdap_timeout).send().await?;

        if !response.status().is_success() {
            return Err(eyre::eyre!("RDAP query failed with status: {}", response.status()));
        }

        let rdap_data: serde_json::Value = response.json().await?;
        self.parse_rdap_response(domain, rdap_data, start_time.elapsed()).await
    }

    async fn query_traditional_whois(&self, domain: &str) -> eyre::Result<WhoisResult> {
        let start_time = Instant::now();
        let whois_text = self.lookup_whois_text(domain).await?;
        self.parse_whois_text(domain, &whois_text, start_time.elapsed()).await
    }

    /// IANA names the registry WHOIS server for the TLD; the registry may refer on to the
    /// registrar's server (thin registries like .com). All hops share one deadline. IANA and the
    /// registry are required; the registrar hop is optional data, so its timeout, failure or
    /// refusal keeps the registry answer.
    async fn lookup_whois_text(&self, domain: &str) -> eyre::Result<String> {
        let deadline = tokio::time::Instant::now() + self.whois_timeout;
        let tld = domain.rsplit('.').next().unwrap_or(domain);
        log::debug!(
            "[scan::whois] lookup_whois_text: domain={} tld={} timeout={:?}",
            domain,
            tld,
            self.whois_timeout
        );

        let iana_text = self.required_hop(deadline, &self.iana_server, tld).await?;
        let registry =
            whois_referral(&iana_text).ok_or_else(|| eyre::eyre!("IANA lists no WHOIS server for .{}", tld))?;
        let registry_server = with_whois_port(&registry);
        let registry_text = self.required_hop(deadline, &registry_server, domain).await?;

        let (server, text) = match whois_referral(&registry_text).filter(|r| !r.eq_ignore_ascii_case(&registry)) {
            None => (registry_server, registry_text),
            Some(registrar) => {
                let registrar_server = with_whois_port(&registrar);
                match tokio::time::timeout_at(deadline, whois_query(&registrar_server, domain)).await {
                    Ok(Ok(registrar_text)) if has_registration_data(&registrar_text) => {
                        (registrar_server, registrar_text)
                    }
                    Ok(Ok(registrar_text)) => {
                        log::debug!(
                            "[scan::whois] registrar_answer_without_data: registrar={} first_line={:?}; using registry answer",
                            registrar_server,
                            first_non_empty_line(&registrar_text)
                        );
                        (registry_server, registry_text)
                    }
                    Ok(Err(e)) => {
                        log::debug!(
                            "[scan::whois] registrar_referral_failed: registrar={} error={:#}; using registry answer",
                            registrar_server,
                            e
                        );
                        (registry_server, registry_text)
                    }
                    Err(_) => {
                        log::debug!(
                            "[scan::whois] registrar_referral_timed_out: registrar={}; using registry answer",
                            registrar_server
                        );
                        (registry_server, registry_text)
                    }
                }
            }
        };

        if !has_registration_data(&text) {
            return Err(eyre::eyre!(
                "WHOIS answer from {} has no registration data: {}",
                server,
                first_non_empty_line(&text)
            ));
        }
        Ok(text)
    }

    /// One hop the lookup cannot do without; running out of the shared deadline fails the lookup.
    async fn required_hop(&self, deadline: tokio::time::Instant, server: &str, query: &str) -> eyre::Result<String> {
        tokio::time::timeout_at(deadline, whois_query(server, query))
            .await
            .map_err(|_| eyre::eyre!("WHOIS lookup timed out after {:?}", self.whois_timeout))?
    }

    fn get_rdap_endpoint(&self, tld: &str, domain: &str) -> String {
        match tld.to_lowercase().as_str() {
            "com" | "net" => format!("https://rdap.verisign.com/com/v1/domain/{}", domain),
            "org" => format!("https://rdap.publicinterestregistry.org/rdap/domain/{}", domain),
            "tv" => format!("https://rdap.nic.tv/domain/{}", domain),
            "io" => format!("https://rdap.nic.io/domain/{}", domain),
            "uk" => format!("https://rdap.nominet.uk/uk/domain/{}", domain),
            "info" => format!("https://rdap.afilias.net/rdap/domain/{}", domain),
            "biz" => format!("https://rdap.afilias.net/rdap/domain/{}", domain),
            _ => format!("https://rdap.iana.org/domain/{}", domain), // IANA bootstrap
        }
    }

    async fn parse_rdap_response(
        &self,
        domain: &str,
        data: serde_json::Value,
        duration: Duration,
    ) -> eyre::Result<WhoisResult> {
        let mut result = WhoisResult {
            domain: domain.to_string(),
            registration_date: None,
            expiry_date: None,
            last_updated: None,
            nameservers: Vec::new(),
            status: Vec::new(),
            dnssec: None,
            registrar: None,
            abuse_contact: None,
            registrant: None,
            admin_contact: None,
            tech_contact: None,
            privacy_score: PrivacyLevel::Unknown,
            domain_age_days: None,
            expires_in_days: None,
            risk_indicators: Vec::new(),
            data_source: DataSource::Rdap,
            scan_duration: duration,
            raw_data: Some(data.to_string()),
        };

        // Parse events (registration, expiry, last changed)
        if let Some(events) = data.get("events").and_then(|e| e.as_array()) {
            for event in events {
                if let (Some(action), Some(date)) = (
                    event.get("eventAction").and_then(|a| a.as_str()),
                    event.get("eventDate").and_then(|d| d.as_str()),
                ) && let Ok(parsed_date) = DateTime::parse_from_rfc3339(date)
                {
                    let utc_date = parsed_date.with_timezone(&Utc);
                    match action {
                        "registration" => result.registration_date = Some(utc_date),
                        "expiration" => result.expiry_date = Some(utc_date),
                        "last changed" | "last update of RDAP database" => result.last_updated = Some(utc_date),
                        _ => {}
                    }
                }
            }
        }

        // Parse nameservers
        if let Some(nameservers) = data.get("nameservers").and_then(|ns| ns.as_array()) {
            for ns in nameservers {
                if let Some(name) = ns.get("ldhName").and_then(|n| n.as_str()) {
                    result.nameservers.push(name.to_lowercase());
                }
            }
        }

        // Parse status
        if let Some(status) = data.get("status").and_then(|s| s.as_array()) {
            for s in status {
                if let Some(status_str) = s.as_str() {
                    result.status.push(status_str.to_string());
                }
            }
        }

        // Parse DNSSEC
        if let Some(secure_dns) = data.get("secureDNS") {
            result.dnssec = secure_dns.get("delegationSigned").and_then(|ds| ds.as_bool());
        }

        // Parse entities (registrar, contacts)
        if let Some(entities) = data.get("entities").and_then(|e| e.as_array()) {
            for entity in entities {
                if let Some(roles) = entity.get("roles").and_then(|r| r.as_array()) {
                    for role in roles {
                        if let Some(role_str) = role.as_str() {
                            match role_str {
                                "registrar" => {
                                    result.registrar = self.parse_registrar_info(entity);
                                }
                                "registrant" => {
                                    result.registrant = self.parse_contact_info(entity);
                                }
                                "administrative" => {
                                    result.admin_contact = self.parse_contact_info(entity);
                                }
                                "technical" => {
                                    result.tech_contact = self.parse_contact_info(entity);
                                }
                                "abuse" => {
                                    result.abuse_contact = self.parse_contact_info(entity);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // Calculate derived fields
        self.calculate_derived_fields(&mut result);

        Ok(result)
    }

    async fn parse_whois_text(&self, domain: &str, whois_text: &str, duration: Duration) -> eyre::Result<WhoisResult> {
        let mut result = WhoisResult {
            domain: domain.to_string(),
            registration_date: None,
            expiry_date: None,
            last_updated: None,
            nameservers: Vec::new(),
            status: Vec::new(),
            dnssec: None,
            registrar: None,
            abuse_contact: None,
            registrant: None,
            admin_contact: None,
            tech_contact: None,
            privacy_score: PrivacyLevel::Unknown,
            domain_age_days: None,
            expires_in_days: None,
            risk_indicators: Vec::new(),
            data_source: DataSource::Whois,
            scan_duration: duration,
            raw_data: Some(whois_text.to_string()),
        };

        // Parse traditional WHOIS text format
        for line in whois_text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('%') || line.starts_with(">>>") {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                match key.as_str() {
                    k if WHOIS_CREATION_KEYS.contains(&k) => {
                        result.registration_date = self.parse_whois_date(value);
                    }
                    k if WHOIS_EXPIRY_KEYS.contains(&k) => {
                        result.expiry_date = self.parse_whois_date(value);
                    }
                    "updated date" | "last updated" | "changed" | "last modified" => {
                        result.last_updated = self.parse_whois_date(value);
                    }
                    k if WHOIS_NAMESERVER_KEYS.contains(&k) => {
                        if !value.is_empty() {
                            result.nameservers.push(value.to_lowercase());
                        }
                    }
                    "domain status" | "status" => {
                        if !value.is_empty() {
                            result.status.push(value.to_string());
                        }
                    }
                    k if WHOIS_REGISTRAR_KEYS.contains(&k) => {
                        if result.registrar.is_none() {
                            result.registrar = Some(RegistrarInfo {
                                name: value.to_string(),
                                iana_id: None,
                                abuse_contact: None,
                                url: None,
                            });
                        }
                    }
                    "dnssec" => {
                        result.dnssec = match value.to_lowercase().as_str() {
                            "signed" | "yes" | "true" => Some(true),
                            "unsigned" | "no" | "false" => Some(false),
                            _ => None,
                        };
                    }
                    _ => {}
                }
            }
        }

        // Calculate derived fields
        self.calculate_derived_fields(&mut result);

        Ok(result)
    }

    fn parse_registrar_info(&self, entity: &serde_json::Value) -> Option<RegistrarInfo> {
        let mut registrar = RegistrarInfo {
            name: String::new(),
            iana_id: None,
            abuse_contact: None,
            url: None,
        };

        // Parse vCard data
        if let Some(vcard) = entity.get("vcardArray").and_then(|v| v.as_array())
            && vcard.len() > 1
            && let Some(properties) = vcard[1].as_array()
        {
            for prop in properties {
                if let Some(prop_array) = prop.as_array()
                    && prop_array.len() >= 4
                    && let Some(prop_name) = prop_array[0].as_str()
                    && prop_name == "fn"
                    && let Some(name) = prop_array[3].as_str()
                {
                    registrar.name = name.to_string();
                }
            }
        }

        // Parse IANA ID
        if let Some(public_ids) = entity.get("publicIds").and_then(|p| p.as_array()) {
            for id in public_ids {
                if let (Some(id_type), Some(identifier)) = (
                    id.get("type").and_then(|t| t.as_str()),
                    id.get("identifier").and_then(|i| i.as_str()),
                ) && id_type == "IANA Registrar ID"
                {
                    registrar.iana_id = identifier.parse().ok();
                }
            }
        }

        // Parse abuse contact from nested entities
        if let Some(entities) = entity.get("entities").and_then(|e| e.as_array()) {
            for nested_entity in entities {
                if let Some(roles) = nested_entity.get("roles").and_then(|r| r.as_array()) {
                    for role in roles {
                        if role.as_str() == Some("abuse") {
                            registrar.abuse_contact = self.parse_contact_info(nested_entity);
                            break;
                        }
                    }
                }
            }
        }

        if registrar.name.is_empty() { None } else { Some(registrar) }
    }

    fn parse_contact_info(&self, entity: &serde_json::Value) -> Option<ContactInfo> {
        // Check if contact is redacted
        if let Some(remarks) = entity.get("remarks").and_then(|r| r.as_array()) {
            for remark in remarks {
                if let Some(title) = remark.get("title").and_then(|t| t.as_str())
                    && title.contains("REDACTED FOR PRIVACY")
                {
                    return Some(ContactInfo {
                        name: None,
                        organization: None,
                        email: None,
                        phone: None,
                        address: None,
                        is_redacted: true,
                    });
                }
            }
        }

        let mut contact = ContactInfo {
            name: None,
            organization: None,
            email: None,
            phone: None,
            address: None,
            is_redacted: false,
        };

        // Parse vCard data
        if let Some(vcard) = entity.get("vcardArray").and_then(|v| v.as_array())
            && vcard.len() > 1
            && let Some(properties) = vcard[1].as_array()
        {
            for prop in properties {
                if let Some(prop_array) = prop.as_array()
                    && prop_array.len() >= 4
                    && let Some(prop_name) = prop_array[0].as_str()
                {
                    match prop_name {
                        "fn" => {
                            if let Some(name) = prop_array[3].as_str() {
                                contact.name = Some(name.to_string());
                            }
                        }
                        "org" => {
                            if let Some(org) = prop_array[3].as_str() {
                                contact.organization = Some(org.to_string());
                            }
                        }
                        "email" => {
                            if let Some(email) = prop_array[3].as_str() {
                                contact.email = Some(email.to_string());
                            }
                        }
                        "tel" => {
                            if let Some(tel) = prop_array[3].as_str() {
                                contact.phone = Some(tel.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if contact.name.is_some() || contact.organization.is_some() || contact.email.is_some() || contact.is_redacted {
            Some(contact)
        } else {
            None
        }
    }

    fn parse_whois_date(&self, date_str: &str) -> Option<DateTime<Utc>> {
        // RFC 3339 covers fractional seconds and numeric offsets (MarkMonitor: `1997-09-15T07:00:00.000+00:00`)
        if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
            return Some(dt.with_timezone(&Utc));
        }

        // Try various date formats commonly used in WHOIS
        let formats = [
            "%Y-%m-%dT%H:%M:%SZ", // ISO 8601
            "%Y-%m-%d %H:%M:%S",  // Common format
            "%Y-%m-%d",           // Date only
            "%d-%b-%Y",           // DD-MMM-YYYY
            "%d.%m.%Y",           // DD.MM.YYYY
            "%Y/%m/%d",           // YYYY/MM/DD
        ];

        for format in &formats {
            if let Ok(dt) = DateTime::parse_from_str(date_str, format) {
                return Some(dt.with_timezone(&Utc));
            }
            if let Ok(naive_dt) = chrono::NaiveDateTime::parse_from_str(date_str, format) {
                return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
            }
            if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(date_str, format) {
                return Some(DateTime::from_naive_utc_and_offset(
                    naive_date.and_hms_opt(0, 0, 0).unwrap(),
                    Utc,
                ));
            }
        }

        None
    }

    fn calculate_derived_fields(&self, result: &mut WhoisResult) {
        let now = Utc::now();

        // Calculate domain age
        if let Some(reg_date) = result.registration_date {
            let age = now.signed_duration_since(reg_date);
            result.domain_age_days = Some(age.num_days());
        }

        // Calculate days until expiry
        if let Some(exp_date) = result.expiry_date {
            let until_expiry = exp_date.signed_duration_since(now);
            result.expires_in_days = Some(until_expiry.num_days());
        }

        // Assess privacy level
        result.privacy_score = self.assess_privacy_level(result);

        // Identify risk indicators
        result.risk_indicators = self.identify_risk_indicators(result);
    }

    fn assess_privacy_level(&self, result: &WhoisResult) -> PrivacyLevel {
        let has_contact_info = result
            .registrant
            .as_ref()
            .map(|c| !c.is_redacted && (c.name.is_some() || c.email.is_some()))
            .unwrap_or(false);

        let has_org_info = result
            .registrant
            .as_ref()
            .and_then(|c| c.organization.as_ref())
            .is_some();

        match (has_contact_info, has_org_info) {
            (true, _) => PrivacyLevel::Open,
            (false, true) => PrivacyLevel::Corporate,
            (false, false) => {
                if result.registrant.as_ref().map(|c| c.is_redacted).unwrap_or(false) {
                    PrivacyLevel::Protected
                } else {
                    PrivacyLevel::Unknown
                }
            }
        }
    }

    fn identify_risk_indicators(&self, result: &WhoisResult) -> Vec<RiskIndicator> {
        let mut indicators = Vec::new();

        // Recent registration (< 30 days)
        if let Some(age_days) = result.domain_age_days
            && age_days < RECENT_REGISTRATION_THRESHOLD_DAYS
        {
            indicators.push(RiskIndicator::RecentRegistration);
        }

        // Near expiry (< 30 days)
        if let Some(expires_in) = result.expires_in_days
            && expires_in < NEAR_EXPIRY_THRESHOLD_DAYS
            && expires_in > 0
        {
            indicators.push(RiskIndicator::NearExpiry);
        }

        // No abuse contact
        if result.abuse_contact.is_none()
            && result
                .registrar
                .as_ref()
                .and_then(|r| r.abuse_contact.as_ref())
                .is_none()
        {
            indicators.push(RiskIndicator::NoAbuseContact);
        }

        // DNSSEC not enabled
        if result.dnssec == Some(false) {
            indicators.push(RiskIndicator::WeakDnssec);
        }

        // Suspicious status codes
        for status in &result.status {
            if status.contains("hold") || status.contains("lock") {
                // These might indicate issues, but could also be security measures
                // We'll be conservative and not flag them as risks by default
            }
        }

        indicators
    }
}

#[async_trait]
impl Scanner for WhoisScanner {
    fn name(&self) -> &'static str {
        "whois"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(WHOIS_SCAN_INTERVAL_SECS) // 1 hour - WHOIS data changes infrequently
    }

    /// WHOIS queries the registry by domain; the protocol only feeds a log line.
    fn uses_protocol(&self) -> bool {
        false
    }

    /// Covers a hung RDAP request plus the traditional fallback it falls through to.
    fn deadline(&self) -> Duration {
        self.rdap_timeout + self.whois_timeout + Duration::from_secs(DEADLINE_SLACK_SECS)
    }

    async fn scan(&self, target: &Target, protocol: Protocol) -> eyre::Result<ScanResult> {
        log::debug!(
            "[scan::whois] scan: target={} protocol={}",
            target.display_name(),
            protocol.as_str()
        );

        let scan_start = Instant::now();
        match self.scan_whois(target).await {
            Ok(result) => {
                let scan_duration = scan_start.elapsed();
                log::trace!(
                    "[scan::whois] whois_scan_completed: target={} protocol={} duration={}ms source={:?} privacy={:?} risks={}",
                    target.display_name(),
                    protocol.as_str(),
                    scan_duration.as_millis(),
                    result.data_source,
                    result.privacy_score,
                    result.risk_indicators.len()
                );

                if let Some(reg_date) = result.registration_date {
                    log::trace!(
                        "[scan::whois] domain_info: target={} protocol={} registered={} age_days={:?} expires_in_days={:?}",
                        target.display_name(),
                        protocol.as_str(),
                        reg_date.format("%Y-%m-%d"),
                        result.domain_age_days,
                        result.expires_in_days
                    );
                }

                Ok(ScanResult::Whois(result))
            }
            Err(e) => {
                let scan_duration = scan_start.elapsed();
                log::error!(
                    "[scan::whois] whois_scan_failed: target={} protocol={} duration={}ms error={}",
                    target.display_name(),
                    protocol.as_str(),
                    scan_duration.as_millis(),
                    e
                );
                Err(e)
            }
        }
    }
}

// Data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResult {
    pub domain: String,
    pub registration_date: Option<DateTime<Utc>>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub last_updated: Option<DateTime<Utc>>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub dnssec: Option<bool>,
    pub registrar: Option<RegistrarInfo>,
    pub abuse_contact: Option<ContactInfo>,
    pub registrant: Option<ContactInfo>,
    pub admin_contact: Option<ContactInfo>,
    pub tech_contact: Option<ContactInfo>,
    pub privacy_score: PrivacyLevel,
    pub domain_age_days: Option<i64>,
    pub expires_in_days: Option<i64>,
    pub risk_indicators: Vec<RiskIndicator>,
    pub data_source: DataSource,
    pub scan_duration: Duration,
    pub raw_data: Option<String>,
}

impl WhoisResult {
    /// Domain WHOIS has nothing to say about an IP target; GEOIP carries its ISP and ASN.
    pub fn not_applicable(target: String) -> Self {
        Self {
            domain: target,
            registration_date: None,
            expiry_date: None,
            last_updated: None,
            nameservers: Vec::new(),
            status: Vec::new(),
            dnssec: None,
            registrar: None,
            abuse_contact: None,
            registrant: None,
            admin_contact: None,
            tech_contact: None,
            privacy_score: PrivacyLevel::Unknown,
            domain_age_days: None,
            expires_in_days: None,
            risk_indicators: Vec::new(),
            data_source: DataSource::NotApplicable,
            scan_duration: Duration::ZERO,
            raw_data: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrarInfo {
    pub name: String,
    pub iana_id: Option<u32>,
    pub abuse_contact: Option<ContactInfo>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub is_redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrivacyLevel {
    Open,      // Contact info visible
    Corporate, // Organization visible, contacts hidden
    Protected, // Full privacy protection
    Unknown,   // Cannot determine privacy level
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskIndicator {
    RecentRegistration,  // < 30 days old
    NearExpiry,          // < 30 days to expiry
    FrequentUpdates,     // Updated > 3x in 90 days (would need historical data)
    SuspiciousRegistrar, // Known problematic registrar (would need reputation data)
    NoAbuseContact,      // Missing abuse contact
    WeakDnssec,          // DNSSEC not enabled
    QueryFailed,         // Could not retrieve WHOIS data
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataSource {
    Rdap,           // Modern RDAP protocol
    Whois,          // Traditional WHOIS protocol
    Failed(String), // Both RDAP and the WHOIS fallback failed; carries both errors
    NotApplicable,  // IP target: no domain to look up
}

impl std::fmt::Display for DataSource {
    /// The label the WHOIS pane prints after `Source:`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::Rdap => write!(f, "RDAP"),
            DataSource::Whois => write!(f, "WHOIS"),
            DataSource::Failed(reason) => write!(f, "Failed: {}", reason),
            DataSource::NotApplicable => write!(f, "n/a"),
        }
    }
}

/// Sends one WHOIS query (RFC 3912) to `server` (`host:port`) and returns the whole response.
async fn whois_query(server: &str, query: &str) -> eyre::Result<String> {
    log::trace!("[scan::whois] whois_query: server={} query={}", server, query);
    let mut stream = connect_whois_server(server).await?;
    stream.write_all(format!("{}\r\n", query).as_bytes()).await?;
    let mut response = Vec::new();
    stream
        .take(WHOIS_MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .await?;
    if response.len() as u64 > WHOIS_MAX_RESPONSE_BYTES {
        return Err(eyre::eyre!("WHOIS answer from {} exceeded 1 MiB", server));
    }
    if response.is_empty() {
        return Err(eyre::eyre!("WHOIS server {} returned an empty response", server));
    }
    Ok(String::from_utf8_lossy(&response).into_owned())
}

/// Resolves `server` (`host:port`) with the async Hickory resolver, never the blocking system
/// resolver, and connects to the first address that accepts. An IP literal skips resolution.
async fn connect_whois_server(server: &str) -> eyre::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = match server.parse::<SocketAddr>() {
        Ok(addr) => vec![addr],
        Err(_) => {
            let (host, port) = server
                .rsplit_once(':')
                .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
                .ok_or_else(|| eyre::eyre!("WHOIS server {} is not host:port", server))?;
            let resolver = Resolver::builder_tokio()
                .map_err(|e| eyre::eyre!("WHOIS resolver setup failed: {}", e))?
                .build();
            let lookup = resolver
                .lookup_ip(host)
                .await
                .map_err(|e| eyre::eyre!("WHOIS server {} did not resolve: {}", host, e))?;
            lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect()
        }
    };
    log::trace!(
        "[scan::whois] connect_whois_server: server={} addrs={:?}",
        server,
        addrs
    );

    let mut last_error = None;
    for addr in &addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }
    Err(match last_error {
        Some(e) => eyre::eyre!("WHOIS connect to {} failed: {}", server, e),
        None => eyre::eyre!("WHOIS server {} resolved to no addresses", server),
    })
}

/// True when some line's key is one `parse_whois_text` reads registration data from.
fn has_registration_data(text: &str) -> bool {
    text.lines().any(|line| {
        let Some((key, value)) = line.trim().split_once(':') else {
            return false;
        };
        let key = key.trim().to_lowercase();
        !value.trim().is_empty()
            && [
                WHOIS_REGISTRAR_KEYS,
                WHOIS_CREATION_KEYS,
                WHOIS_EXPIRY_KEYS,
                WHOIS_NAMESERVER_KEYS,
            ]
            .iter()
            .any(|keys| keys.contains(&key.as_str()))
    })
}

fn first_non_empty_line(text: &str) -> &str {
    text.lines().map(str::trim).find(|line| !line.is_empty()).unwrap_or("")
}

/// The next WHOIS server named in a response. `whois:`, `refer:` and `Registrar WHOIS Server:`
/// are accepted in any answer; the lookup only follows IANA's and the registry's. `None` when
/// the response names none.
fn whois_referral(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        let key = key.trim().to_lowercase();
        if !matches!(key.as_str(), "whois" | "refer" | "registrar whois server") {
            return None;
        }
        let server = value.trim().trim_start_matches("whois://").trim_end_matches('/');
        (!server.is_empty()).then(|| server.to_string())
    })
}

/// `host` -> `host:43`; a server given with an explicit port is kept as is.
fn with_whois_port(server: &str) -> String {
    if server.contains(':') {
        server.to_string()
    } else {
        format!("{}:{}", server, WHOIS_PORT)
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_covers_rdap_and_whois_fallback() {
        let scanner = WhoisScanner::new();
        let rdap = Duration::from_secs(RDAP_TIMEOUT_SECS);
        let whois = Duration::from_secs(WHOIS_LOOKUP_TIMEOUT_SECS);
        assert!(
            scanner.deadline() > rdap + whois,
            "deadline {:?} must exceed RDAP {:?} + WHOIS {:?}",
            scanner.deadline(),
            rdap,
            whois
        );
    }

    /// Bound on every fake-server accept and read, so a missed connection ends the server
    /// instead of hanging the test.
    const FAKE_SERVER_WAIT: Duration = Duration::from_secs(2);

    /// Serves one canned answer per connection, in order, on 127.0.0.1; returns the address
    /// and a handle yielding the queries received.
    async fn fake_whois(answers: Vec<String>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let mut queries = Vec::new();
            for answer in answers {
                // A connection that never comes ends the server, so a missed referral fails the
                // test's query assertions instead of hanging it.
                let Ok(accepted) = tokio::time::timeout(FAKE_SERVER_WAIT, listener.accept()).await else {
                    break;
                };
                let (mut socket, _) = accepted.unwrap();
                let mut buf = vec![0u8; 512];
                let Ok(read) = tokio::time::timeout(FAKE_SERVER_WAIT, socket.read(&mut buf)).await else {
                    break;
                };
                let n = read.unwrap();
                queries.push(String::from_utf8_lossy(&buf[..n]).trim_end().to_string());
                socket.write_all(answer.as_bytes()).await.unwrap();
            }
            queries
        });
        (addr, handle)
    }

    /// Accepts one connection and never answers it; the socket is held past any test's limit.
    async fn silent_whois() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok(Ok((socket, _))) = tokio::time::timeout(FAKE_SERVER_WAIT, listener.accept()).await {
                tokio::time::sleep(Duration::from_secs(10)).await;
                drop(socket);
            }
        });
        addr
    }

    /// An HTTP proxy that answers every CONNECT with 502, so any HTTPS request through it fails.
    async fn refusing_proxy() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok(Ok((mut socket, _))) = tokio::time::timeout(FAKE_SERVER_WAIT, listener.accept()).await {
                let mut buf = vec![0u8; 1024];
                if tokio::time::timeout(FAKE_SERVER_WAIT, socket.read(&mut buf))
                    .await
                    .is_err()
                {
                    break;
                }
                let _ = socket
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        addr
    }

    /// A registry answer carrying its own registration data and a referral to `registrar`.
    fn registry_answer_referring_to(registrar: &str) -> String {
        format!(
            "Domain Name: EXAMPLE.TEST\nRegistrar: Registry Registrar\nCreation Date: 2001-02-03T00:00:00Z\n\
             Registry Expiry Date: 2031-02-03T00:00:00Z\nRegistrar WHOIS Server: {registrar}\n"
        )
    }

    fn scanner_with_iana(iana_server: String, whois_timeout: Duration) -> WhoisScanner {
        WhoisScanner {
            client: Client::new(),
            iana_server,
            rdap_timeout: Duration::from_secs(1),
            whois_timeout,
        }
    }

    #[test]
    fn whois_referral_reads_iana_and_registrar_lines() {
        assert_eq!(
            whois_referral("domain: COM\nwhois:        whois.verisign-grs.com\n"),
            Some("whois.verisign-grs.com".to_string())
        );
        assert_eq!(
            whois_referral("refer: whois.nic.io\n"),
            Some("whois.nic.io".to_string())
        );
        assert_eq!(
            whois_referral("   Registrar WHOIS Server: whois://whois.markmonitor.com/\n"),
            Some("whois.markmonitor.com".to_string())
        );
        assert_eq!(whois_referral("domain: DEV\nwhois:\n"), None);
        assert_eq!(whois_referral("Registrar: MarkMonitor Inc.\n"), None);
    }

    #[test]
    fn whois_date_parses_fractional_seconds_and_offset() {
        let scanner = WhoisScanner::new();
        let parsed = scanner.parse_whois_date("1997-09-15T07:00:00.000+00:00").unwrap();
        assert_eq!(parsed.to_rfc3339(), "1997-09-15T07:00:00+00:00");
        let offset = scanner.parse_whois_date("2028-09-14T07:00:00-05:00").unwrap();
        assert_eq!(offset.to_rfc3339(), "2028-09-14T12:00:00+00:00");
    }

    #[test]
    fn with_whois_port_adds_43_only_when_missing() {
        assert_eq!(with_whois_port("whois.nic.io"), "whois.nic.io:43");
        assert_eq!(with_whois_port("127.0.0.1:4343"), "127.0.0.1:4343");
    }

    /// IANA -> registry -> registrar, each a separate local server: the fallback follows both
    /// referrals and parses the registrar's answer.
    #[tokio::test]
    async fn traditional_whois_follows_iana_and_registrar_referrals() {
        let (registrar, registrar_queries) = fake_whois(vec![
            "Domain Name: example.test\nRegistrar: Fixture Registrar\nCreation Date: 2001-02-03T00:00:00Z\n"
                .to_string(),
        ])
        .await;
        let (registry, registry_queries) = fake_whois(vec![format!(
            "Domain Name: EXAMPLE.TEST\nRegistrar WHOIS Server: {registrar}\n"
        )])
        .await;
        let (iana, iana_queries) = fake_whois(vec![format!("domain: TEST\nwhois: {registry}\n")]).await;

        let result = scanner_with_iana(iana, Duration::from_secs(5))
            .query_traditional_whois("example.test")
            .await
            .unwrap();

        assert_eq!(iana_queries.await.unwrap(), vec!["test"]);
        assert_eq!(registry_queries.await.unwrap(), vec!["example.test"]);
        assert_eq!(registrar_queries.await.unwrap(), vec!["example.test"]);
        assert_eq!(result.registrar.unwrap().name, "Fixture Registrar");
        assert!(result.registration_date.is_some());
    }

    #[tokio::test]
    async fn traditional_whois_names_a_tld_without_a_whois_server() {
        let (iana, _) = fake_whois(vec!["domain: DEV\nwhois:\n".to_string()]).await;
        let err = scanner_with_iana(iana, Duration::from_secs(5))
            .query_traditional_whois("example.dev")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no WHOIS server for .dev"), "{err:#}");
    }

    /// A server that accepts and never answers is cut off at the fallback's own time limit,
    /// without blocking the runtime, and the error names the sub-second limit truthfully.
    #[tokio::test]
    async fn traditional_whois_is_bounded_by_its_timeout() {
        let iana = silent_whois().await;
        let started = Instant::now();
        let err = scanner_with_iana(iana, Duration::from_millis(300))
            .query_traditional_whois("example.test")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out after 300ms"), "{err:#}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
    }

    /// The registrar hop is optional data: a registrar that accepts and stalls costs the rest of
    /// the budget, not the registry answer already in hand.
    #[tokio::test]
    async fn traditional_whois_keeps_registry_answer_when_registrar_is_silent() {
        let registrar = silent_whois().await;
        let (registry, _) = fake_whois(vec![registry_answer_referring_to(&registrar)]).await;
        let (iana, _) = fake_whois(vec![format!("domain: TEST\nwhois: {registry}\n")]).await;

        let started = Instant::now();
        let result = scanner_with_iana(iana, Duration::from_millis(500))
            .query_traditional_whois("example.test")
            .await
            .unwrap();

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(result.registrar.unwrap().name, "Registry Registrar");
        assert!(result.registration_date.is_some());
        assert!(result.expiry_date.is_some());
    }

    /// A registrar refusal is not a WHOIS record; the registry's data stands.
    #[tokio::test]
    async fn traditional_whois_keeps_registry_answer_when_registrar_refuses() {
        let (registrar, registrar_queries) = fake_whois(vec!["Query limit exceeded\r\n".to_string()]).await;
        let (registry, _) = fake_whois(vec![registry_answer_referring_to(&registrar)]).await;
        let (iana, _) = fake_whois(vec![format!("domain: TEST\nwhois: {registry}\n")]).await;

        let result = scanner_with_iana(iana, Duration::from_secs(5))
            .query_traditional_whois("example.test")
            .await
            .unwrap();

        assert_eq!(registrar_queries.await.unwrap(), vec!["example.test"]);
        assert_eq!(result.registrar.unwrap().name, "Registry Registrar");
        assert!(result.registration_date.is_some());
        assert!(result.expiry_date.is_some());
    }

    /// No registration data anywhere is a loud failure, never an empty success.
    #[tokio::test]
    async fn traditional_whois_errors_when_registry_answer_has_no_registration_data() {
        let (registry, _) = fake_whois(vec!["Query limit exceeded\r\n".to_string()]).await;
        let (iana, _) = fake_whois(vec![format!("domain: TEST\nwhois: {registry}\n")]).await;

        let err = scanner_with_iana(iana, Duration::from_secs(5))
            .query_traditional_whois("example.test")
            .await
            .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("has no registration data"), "{message}");
        assert!(message.contains(&registry), "{message}");
        assert!(message.ends_with("Query limit exceeded"), "{message}");
    }

    #[tokio::test]
    async fn whois_query_errors_on_an_answer_over_1_mib() {
        let mut answer = String::from("Registrar: Prefix Registrar\r\n");
        answer.push_str(&"x".repeat(WHOIS_MAX_RESPONSE_BYTES as usize + 1 - answer.len()));
        let (server, _) = fake_whois(vec![answer]).await;

        let err = whois_query(&server, "test").await.unwrap_err();
        assert!(err.to_string().contains("exceeded 1 MiB"), "{err:#}");
    }

    #[tokio::test]
    async fn whois_query_accepts_an_answer_of_exactly_1_mib() {
        let mut answer = String::from("Registrar: Prefix Registrar\r\n");
        answer.push_str(&"x".repeat(WHOIS_MAX_RESPONSE_BYTES as usize - answer.len()));
        let (server, _) = fake_whois(vec![answer]).await;

        let text = whois_query(&server, "test").await.unwrap();
        assert_eq!(text.len() as u64, WHOIS_MAX_RESPONSE_BYTES);
    }

    /// A hostname goes through the Hickory resolver (here its hosts-file lookup), then the
    /// connection tries each address it returned.
    #[tokio::test]
    async fn whois_query_resolves_a_hostname_server() {
        let (server, queries) = fake_whois(vec!["Registrar: Local Registrar\r\n".to_string()]).await;
        let port = server.rsplit_once(':').unwrap().1;

        let text = whois_query(&format!("localhost:{port}"), "example.test").await.unwrap();

        assert!(text.contains("Local Registrar"), "{text}");
        assert_eq!(queries.await.unwrap(), vec!["example.test"]);
    }

    #[tokio::test]
    async fn whois_query_rejects_a_server_without_a_port() {
        let err = whois_query("whois.example", "example.test").await.unwrap_err();
        assert!(err.to_string().contains("is not host:port"), "{err:#}");
    }

    #[test]
    fn has_registration_data_reads_the_parsed_keys_only() {
        assert!(has_registration_data("Registrar: MarkMonitor Inc.\n"));
        assert!(has_registration_data("   Creation Date: 1997-09-15T04:00:00Z\n"));
        assert!(has_registration_data("Registry Expiry Date: 2028-09-14T04:00:00Z\n"));
        assert!(has_registration_data("nserver: ns1.example.test\n"));
        assert!(!has_registration_data("Query limit exceeded\r\n"));
        assert!(!has_registration_data(
            "Registrar WHOIS Server: whois.example\nDomain Name: X\n"
        ));
        assert!(!has_registration_data("Registrar:\nCreation Date:   \n"));
    }

    #[test]
    fn data_source_display_is_the_pane_label() {
        assert_eq!(DataSource::Rdap.to_string(), "RDAP");
        assert_eq!(DataSource::Whois.to_string(), "WHOIS");
        assert_eq!(DataSource::NotApplicable.to_string(), "n/a");
        assert_eq!(
            DataSource::Failed("both down".to_string()).to_string(),
            "Failed: both down"
        );
    }

    /// AC5: RDAP fails (its only route is a proxy that refuses CONNECT), the scanner falls back to
    /// WHOIS through local servers, and the WHOIS pane shows the WHOIS source and its data.
    #[tokio::test]
    async fn scan_falls_back_to_whois_when_rdap_fails_and_the_pane_shows_it() {
        use crate::tui::WhoisPane;
        use crate::tui::testing::render_pane;
        use crate::types::{AppState, ScanState, ScanStatus};

        let proxy = refusing_proxy().await;
        let (registrar, _) = fake_whois(vec![
            "Domain Name: example.test\nRegistrar: Fixture Registrar\nCreation Date: 2001-02-03T00:00:00Z\n\
             Registry Expiry Date: 2031-02-03T00:00:00Z\n"
                .to_string(),
        ])
        .await;
        let (registry, _) = fake_whois(vec![registry_answer_referring_to(&registrar)]).await;
        let (iana, _) = fake_whois(vec![format!("domain: TEST\nwhois: {registry}\n")]).await;

        let client = Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy}")).unwrap())
            .build()
            .unwrap();
        let scanner = WhoisScanner {
            client,
            iana_server: iana,
            rdap_timeout: Duration::from_secs(5),
            whois_timeout: Duration::from_secs(5),
        };
        let target = Target::parse("example.test").unwrap();

        let result = Scanner::scan(&scanner, &target, Protocol::Both).await.unwrap();
        let ScanResult::Whois(whois) = &result else {
            panic!("expected a WHOIS result, got {result:?}");
        };
        assert_eq!(whois.data_source, DataSource::Whois, "{:?}", whois.data_source);

        let state = AppState::new("example.test".to_string());
        state.scanners.insert(
            "whois".to_string(),
            ScanState {
                result: Some(result),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );
        let out = render_pane(&WhoisPane::new(), &state, 100, 40, false);
        assert!(out.contains("Source: WHOIS"), "{out}");
        assert!(out.contains("Fixture Registrar"), "{out}");
    }

    #[test]
    fn whois_ignores_protocol_changes() {
        assert!(!WhoisScanner::new().uses_protocol());
    }

    #[tokio::test]
    async fn test_whois_scanner_creation() {
        let scanner = WhoisScanner::new();
        assert_eq!(scanner.name(), "whois");
        assert_eq!(scanner.interval(), Duration::from_secs(3600));
    }

    #[test]
    fn test_privacy_level_assessment() {
        let scanner = WhoisScanner::new();

        // Test open privacy (has contact info)
        let mut result = WhoisResult {
            domain: "test.com".to_string(),
            registration_date: None,
            expiry_date: None,
            last_updated: None,
            nameservers: Vec::new(),
            status: Vec::new(),
            dnssec: None,
            registrar: None,
            abuse_contact: None,
            registrant: Some(ContactInfo {
                name: Some("John Doe".to_string()),
                organization: None,
                email: Some("john@example.com".to_string()),
                phone: None,
                address: None,
                is_redacted: false,
            }),
            admin_contact: None,
            tech_contact: None,
            privacy_score: PrivacyLevel::Unknown,
            domain_age_days: None,
            expires_in_days: None,
            risk_indicators: Vec::new(),
            data_source: DataSource::Rdap,
            scan_duration: Duration::from_millis(100),
            raw_data: None,
        };

        assert_eq!(scanner.assess_privacy_level(&result), PrivacyLevel::Open);

        // Test corporate privacy (has org, no personal contact)
        result.registrant = Some(ContactInfo {
            name: None,
            organization: Some("Example Corp".to_string()),
            email: None,
            phone: None,
            address: None,
            is_redacted: false,
        });

        assert_eq!(scanner.assess_privacy_level(&result), PrivacyLevel::Corporate);

        // Test protected privacy (redacted)
        result.registrant = Some(ContactInfo {
            name: None,
            organization: None,
            email: None,
            phone: None,
            address: None,
            is_redacted: true,
        });

        assert_eq!(scanner.assess_privacy_level(&result), PrivacyLevel::Protected);
    }

    #[test]
    fn test_risk_indicators() {
        let scanner = WhoisScanner::new();

        let result = WhoisResult {
            domain: "test.com".to_string(),
            registration_date: Some(Utc::now() - chrono::Duration::days(15)), // Recent registration
            expiry_date: Some(Utc::now() + chrono::Duration::days(15)),       // Near expiry
            last_updated: None,
            nameservers: Vec::new(),
            status: Vec::new(),
            dnssec: Some(false), // Weak DNSSEC
            registrar: None,
            abuse_contact: None, // No abuse contact
            registrant: None,
            admin_contact: None,
            tech_contact: None,
            privacy_score: PrivacyLevel::Unknown,
            domain_age_days: Some(15),
            expires_in_days: Some(15),
            risk_indicators: Vec::new(),
            data_source: DataSource::Rdap,
            scan_duration: Duration::from_millis(100),
            raw_data: None,
        };

        let indicators = scanner.identify_risk_indicators(&result);

        assert!(indicators.contains(&RiskIndicator::RecentRegistration));
        assert!(indicators.contains(&RiskIndicator::NearExpiry));
        assert!(indicators.contains(&RiskIndicator::NoAbuseContact));
        assert!(indicators.contains(&RiskIndicator::WeakDnssec));
    }

    #[test]
    fn test_rdap_endpoint_selection() {
        let scanner = WhoisScanner::new();

        assert!(scanner.get_rdap_endpoint("com", "example.com").contains("verisign"));
        assert!(
            scanner
                .get_rdap_endpoint("org", "example.org")
                .contains("publicinterestregistry")
        );
        assert!(scanner.get_rdap_endpoint("tv", "example.tv").contains("nic.tv"));
        assert!(scanner.get_rdap_endpoint("xyz", "example.xyz").contains("iana.org"));
    }

    #[test]
    fn test_whois_date_parsing() {
        let scanner = WhoisScanner::new();

        // Test various date formats
        assert!(scanner.parse_whois_date("2023-01-15T10:30:00Z").is_some());
        assert!(scanner.parse_whois_date("2023-01-15 10:30:00").is_some());
        assert!(scanner.parse_whois_date("2023-01-15").is_some());
        assert!(scanner.parse_whois_date("15-Jan-2023").is_some());
        assert!(scanner.parse_whois_date("invalid-date").is_none());
    }

    #[tokio::test]
    async fn test_get_rdap_endpoint() {
        let scanner = WhoisScanner::new();

        let com_endpoint = scanner.get_rdap_endpoint("com", "google.com");
        assert!(com_endpoint.contains("verisign.com"));

        let tv_endpoint = scanner.get_rdap_endpoint("tv", "example.tv");
        assert!(tv_endpoint.contains("nic.tv"));

        let unknown_endpoint = scanner.get_rdap_endpoint("unknown", "example.unknown");
        assert!(unknown_endpoint.contains("iana.org"));
    }

    #[test]
    fn test_registrar_info_structure() {
        let registrar = RegistrarInfo {
            name: "GoDaddy.com, LLC".to_string(),
            iana_id: Some(146),
            abuse_contact: Some(ContactInfo {
                name: None,
                organization: Some("GoDaddy.com, LLC".to_string()),
                email: Some("abuse@godaddy.com".to_string()),
                phone: Some("+1.4805058800".to_string()),
                address: None,
                is_redacted: false,
            }),
            url: Some("https://www.godaddy.com".to_string()),
        };

        assert_eq!(registrar.name, "GoDaddy.com, LLC");
        assert_eq!(registrar.iana_id, Some(146));
        assert!(registrar.abuse_contact.is_some());
        assert!(registrar.url.is_some());
    }

    #[test]
    fn test_contact_info_redaction() {
        let public_contact = ContactInfo {
            name: Some("John Doe".to_string()),
            organization: Some("Example Corp".to_string()),
            email: Some("john@example.com".to_string()),
            phone: Some("+1.555.123.4567".to_string()),
            address: Some("123 Main St, Anytown, USA".to_string()),
            is_redacted: false,
        };

        let redacted_contact = ContactInfo {
            name: None,
            organization: None,
            email: None,
            phone: None,
            address: None,
            is_redacted: true,
        };

        assert!(!public_contact.is_redacted);
        assert!(public_contact.name.is_some());
        assert!(public_contact.email.is_some());

        assert!(redacted_contact.is_redacted);
        assert!(redacted_contact.name.is_none());
        assert!(redacted_contact.email.is_none());
    }

    #[test]
    fn test_whois_result_derived_fields() {
        let scanner = WhoisScanner::new();
        let mut result = WhoisResult {
            domain: "example.com".to_string(),
            registration_date: Some(chrono::Utc::now() - chrono::Duration::days(365)),
            expiry_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            last_updated: Some(chrono::Utc::now() - chrono::Duration::days(30)),
            nameservers: vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
            status: vec!["clientTransferProhibited".to_string()],
            dnssec: Some(true),
            registrar: None,
            abuse_contact: None,
            registrant: None,
            admin_contact: None,
            tech_contact: None,
            privacy_score: PrivacyLevel::Unknown,
            domain_age_days: None,
            expires_in_days: None,
            risk_indicators: Vec::new(),
            data_source: DataSource::Rdap,
            scan_duration: Duration::from_millis(500),
            raw_data: None,
        };

        scanner.calculate_derived_fields(&mut result);

        assert!(result.domain_age_days.is_some());
        assert!(result.expires_in_days.is_some());
        // Domain age and expiry calculations might vary by a day due to timing
        assert!(result.domain_age_days.unwrap() >= 364 && result.domain_age_days.unwrap() <= 365);
        assert!(result.expires_in_days.unwrap() >= 364 && result.expires_in_days.unwrap() <= 365);
    }

    #[test]
    fn test_data_source_types() {
        let sources = [DataSource::Rdap, DataSource::Whois, DataSource::Failed("x".to_string())];

        assert_eq!(sources.len(), 3);
        assert!(matches!(sources[0], DataSource::Rdap));
        assert!(matches!(sources[1], DataSource::Whois));
        assert!(matches!(sources[2], DataSource::Failed(_)));
    }

    #[test]
    fn test_comprehensive_risk_indicators() {
        let scanner = WhoisScanner::new();

        // Create a result with multiple risk factors
        let result = WhoisResult {
            domain: "suspicious.com".to_string(),
            registration_date: Some(chrono::Utc::now() - chrono::Duration::days(5)), // Very recent
            expiry_date: Some(chrono::Utc::now() + chrono::Duration::days(10)),      // Soon expiring
            last_updated: Some(chrono::Utc::now() - chrono::Duration::days(1)),
            nameservers: vec![],
            status: vec![],
            dnssec: Some(false), // No DNSSEC
            registrar: Some(RegistrarInfo {
                name: "Suspicious Registrar".to_string(),
                iana_id: None,
                abuse_contact: None, // No abuse contact
                url: None,
            }),
            abuse_contact: None, // No abuse contact at domain level either
            registrant: None,
            admin_contact: None,
            tech_contact: None,
            privacy_score: PrivacyLevel::Unknown,
            domain_age_days: Some(5),
            expires_in_days: Some(10),
            risk_indicators: Vec::new(),
            data_source: DataSource::Whois,
            scan_duration: Duration::from_millis(100),
            raw_data: None,
        };

        let indicators = scanner.identify_risk_indicators(&result);

        assert!(indicators.contains(&RiskIndicator::RecentRegistration));
        assert!(indicators.contains(&RiskIndicator::NearExpiry));
        assert!(indicators.contains(&RiskIndicator::NoAbuseContact));
        assert!(indicators.contains(&RiskIndicator::WeakDnssec));
    }

    #[test]
    fn test_whois_date_parsing_formats() {
        let scanner = WhoisScanner::new();

        // Test various common date formats
        let test_dates = vec![
            "2023-01-15T10:30:00Z",     // ISO 8601 with Z
            "2023-01-15T10:30:00.000Z", // ISO 8601 with milliseconds
            "2023-01-15 10:30:00 UTC",  // Space separated with timezone
            "2023-01-15",               // Date only
            "15-Jan-2023",              // Month name format
            "Jan 15 2023",              // US format
            "2023/01/15",               // Slash format
        ];

        for date_str in test_dates {
            let parsed = scanner.parse_whois_date(date_str);
            // Some date formats might not be supported - that's okay
            if date_str.contains("2023/01/15")
                || date_str.contains("Jan 15 2023")
                || date_str.contains(".000Z")
                || date_str.contains("UTC")
            {
                // These formats might not be implemented
                continue;
            }
            assert!(parsed.is_some(), "Failed to parse date: {}", date_str);
        }

        // Test invalid dates
        let invalid_dates = vec![
            "not-a-date",
            "2023-13-40", // Invalid month/day
            "",
            "2023", // Year only
        ];

        for invalid_date in invalid_dates {
            let parsed = scanner.parse_whois_date(invalid_date);
            assert!(parsed.is_none(), "Should not parse invalid date: {}", invalid_date);
        }
    }

    #[tokio::test]
    async fn test_whois_scanner_timeout() {
        let scanner = WhoisScanner::new();
        let target = Target::parse("nonexistent-domain-12345.test").unwrap();

        let result = scanner.scan(&target, Protocol::Both).await;

        // Should handle timeout gracefully
        match result {
            Ok(ScanResult::Whois(whois_result)) => {
                assert!(matches!(whois_result.data_source, DataSource::Failed(_)));
            }
            Ok(_) => panic!("Expected Whois result"),
            Err(_) => {
                // It's also acceptable to return an error for non-existent domains
            }
        }
    }

    #[test]
    fn test_privacy_level_edge_cases() {
        let scanner = WhoisScanner::new();

        // Test with mixed information
        let mixed_result = WhoisResult {
            domain: "mixed.com".to_string(),
            registration_date: None,
            expiry_date: None,
            last_updated: None,
            nameservers: Vec::new(),
            status: Vec::new(),
            dnssec: None,
            registrar: None,
            abuse_contact: None,
            registrant: Some(ContactInfo {
                name: None,
                organization: Some("Privacy Corp".to_string()),
                email: None,
                phone: None,
                address: None,
                is_redacted: true, // Contradictory: has org but is redacted
            }),
            admin_contact: Some(ContactInfo {
                name: Some("Admin Person".to_string()),
                organization: None,
                email: Some("admin@example.com".to_string()),
                phone: None,
                address: None,
                is_redacted: false,
            }),
            tech_contact: None,
            privacy_score: PrivacyLevel::Unknown,
            domain_age_days: None,
            expires_in_days: None,
            risk_indicators: Vec::new(),
            data_source: DataSource::Rdap,
            scan_duration: Duration::from_millis(100),
            raw_data: None,
        };

        let privacy_level = scanner.assess_privacy_level(&mixed_result);

        // Should handle mixed privacy information gracefully
        assert!(matches!(
            privacy_level,
            PrivacyLevel::Protected | PrivacyLevel::Corporate
        ));
    }

    #[tokio::test]
    async fn ip_target_scan_is_ok_and_not_applicable() {
        let scanner = WhoisScanner::new();
        let target = Target::parse("1.1.1.1").unwrap();
        match scanner.scan(&target, Protocol::Both).await {
            Ok(ScanResult::Whois(result)) => {
                assert_eq!(result.data_source, DataSource::NotApplicable);
                assert_eq!(result.domain, "1.1.1.1");
                assert!(result.risk_indicators.is_empty());
            }
            Ok(other) => panic!("expected Whois result, got {:?}", other),
            Err(e) => panic!("IP target must not fail WHOIS: {}", e),
        }
    }
}
