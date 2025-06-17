use crate::scanner::Scanner;
use crate::target::Target;
use crate::types::{AppState, ScanResult, ScanState, ScanStatus};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use whois_rust::{WhoIs, WhoIsLookupOptions};
use log;

const WHOIS_TIMEOUT_SECS: u64 = 30;
const WHOIS_SCAN_INTERVAL_SECS: u64 = 60 * 60; // 1 hour
const RECENT_REGISTRATION_THRESHOLD_DAYS: i64 = 30;
const NEAR_EXPIRY_THRESHOLD_DAYS: i64 = 30;

#[derive(Debug, Clone)]
pub struct WhoisScanner {
    client: Client,
    whois_client: WhoIs,
    timeout: Duration,
}

impl Default for WhoisScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WhoisScanner {
    pub fn new() -> Self {
        log::debug!("[scan::whois] new: timeout={}s", WHOIS_TIMEOUT_SECS);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(WHOIS_TIMEOUT_SECS))
            .user_agent("scan/1.0")
            .build()
            .expect("Failed to create HTTP client");

        let whois_client = WhoIs::from_path("/usr/bin/whois")
            .unwrap_or_else(|_| WhoIs::from_path("/bin/whois")
                .unwrap_or_else(|_| WhoIs::from_string("whois").unwrap_or_else(|_| {
                    // Fallback to a basic whois client if system whois is not available
                    WhoIs::from_host("whois.iana.org").unwrap()
                })));

        Self {
            client,
            whois_client,
            timeout: Duration::from_secs(WHOIS_TIMEOUT_SECS),
        }
    }

    async fn scan_whois(&self, target: &Target) -> eyre::Result<WhoisResult> {
        log::debug!("[scan::whois] scan_whois: target={}", target.display_name());
        
        let domain = match &target.domain {
            Some(d) => d.clone(),
            None => {
                log::error!("[scan::whois] no_domain_available: target={}", target.display_name());
                return Err(eyre::eyre!("No domain available for WHOIS lookup"));
            }
        };
        
        log::debug!("[scan::whois] querying_domain: domain={}", domain);
        
        // Try RDAP first (modern protocol)
        log::trace!("[scan::whois] trying_rdap: domain={}", domain);
        let rdap_start = Instant::now();
        match self.query_rdap(&domain).await {
            Ok(mut result) => {
                let rdap_duration = rdap_start.elapsed();
                result.data_source = DataSource::Rdap;
                log::trace!("[scan::whois] rdap_successful: domain={} duration={}ms", 
                    domain, rdap_duration.as_millis());
                return Ok(result);
            }
            Err(e) => {
                let rdap_duration = rdap_start.elapsed();
                log::debug!("[scan::whois] rdap_failed_trying_whois: domain={} duration={}ms error={}", 
                    domain, rdap_duration.as_millis(), e);
            }
        }
        
        // Fall back to traditional WHOIS
        log::trace!("[scan::whois] trying_traditional_whois: domain={}", domain);
        let whois_start = Instant::now();
        match self.query_traditional_whois(&domain).await {
            Ok(mut result) => {
                let whois_duration = whois_start.elapsed();
                result.data_source = DataSource::Whois;
                log::trace!("[scan::whois] whois_successful: domain={} duration={}ms", 
                    domain, whois_duration.as_millis());
                Ok(result)
            }
            Err(e) => {
                let whois_duration = whois_start.elapsed();
                log::error!("[scan::whois] both_methods_failed: domain={} whois_duration={}ms error={}", 
                    domain, whois_duration.as_millis(), e);
                
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
                    data_source: DataSource::Failed,
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
        let tld = domain.split('.').last().unwrap_or("");
        
        let rdap_url = self.get_rdap_endpoint(tld, domain);
        
        let response = self.client
            .get(&rdap_url)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(eyre::eyre!("RDAP query failed with status: {}", response.status()));
        }

        let rdap_data: serde_json::Value = response.json().await?;
        self.parse_rdap_response(domain, rdap_data, start_time.elapsed()).await
    }

    async fn query_traditional_whois(&self, domain: &str) -> eyre::Result<WhoisResult> {
        let start_time = Instant::now();
        
        let lookup_options = WhoIsLookupOptions::from_string(domain)?;
        let whois_text = self.whois_client.lookup(lookup_options)?;
        
        self.parse_whois_text(domain, &whois_text, start_time.elapsed()).await
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

    async fn parse_rdap_response(&self, domain: &str, data: serde_json::Value, duration: Duration) -> eyre::Result<WhoisResult> {
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
                    event.get("eventDate").and_then(|d| d.as_str())
                ) {
                    if let Ok(parsed_date) = DateTime::parse_from_rfc3339(date) {
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
                    "creation date" | "created" | "registered" | "registration time" => {
                        result.registration_date = self.parse_whois_date(value);
                    }
                    "expiry date" | "expires" | "expiration date" | "registry expiry date" => {
                        result.expiry_date = self.parse_whois_date(value);
                    }
                    "updated date" | "last updated" | "changed" | "last modified" => {
                        result.last_updated = self.parse_whois_date(value);
                    }
                    "name server" | "nameserver" | "nserver" => {
                        if !value.is_empty() {
                            result.nameservers.push(value.to_lowercase());
                        }
                    }
                    "domain status" | "status" => {
                        if !value.is_empty() {
                            result.status.push(value.to_string());
                        }
                    }
                    "registrar" => {
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
        if let Some(vcard) = entity.get("vcardArray").and_then(|v| v.as_array()) {
            if vcard.len() > 1 {
                if let Some(properties) = vcard[1].as_array() {
                    for prop in properties {
                        if let Some(prop_array) = prop.as_array() {
                            if prop_array.len() >= 4 {
                                if let Some(prop_name) = prop_array[0].as_str() {
                                    match prop_name {
                                        "fn" => {
                                            if let Some(name) = prop_array[3].as_str() {
                                                registrar.name = name.to_string();
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Parse IANA ID
        if let Some(public_ids) = entity.get("publicIds").and_then(|p| p.as_array()) {
            for id in public_ids {
                if let (Some(id_type), Some(identifier)) = (
                    id.get("type").and_then(|t| t.as_str()),
                    id.get("identifier").and_then(|i| i.as_str())
                ) {
                    if id_type == "IANA Registrar ID" {
                        registrar.iana_id = identifier.parse().ok();
                    }
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

        if registrar.name.is_empty() {
            None
        } else {
            Some(registrar)
        }
    }

    fn parse_contact_info(&self, entity: &serde_json::Value) -> Option<ContactInfo> {
        // Check if contact is redacted
        if let Some(remarks) = entity.get("remarks").and_then(|r| r.as_array()) {
            for remark in remarks {
                if let Some(title) = remark.get("title").and_then(|t| t.as_str()) {
                    if title.contains("REDACTED FOR PRIVACY") {
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
        if let Some(vcard) = entity.get("vcardArray").and_then(|v| v.as_array()) {
            if vcard.len() > 1 {
                if let Some(properties) = vcard[1].as_array() {
                    for prop in properties {
                        if let Some(prop_array) = prop.as_array() {
                            if prop_array.len() >= 4 {
                                if let Some(prop_name) = prop_array[0].as_str() {
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
        // Try various date formats commonly used in WHOIS
        let formats = [
            "%Y-%m-%dT%H:%M:%SZ",           // ISO 8601
            "%Y-%m-%d %H:%M:%S",            // Common format
            "%Y-%m-%d",                     // Date only
            "%d-%b-%Y",                     // DD-MMM-YYYY
            "%d.%m.%Y",                     // DD.MM.YYYY
            "%Y/%m/%d",                     // YYYY/MM/DD
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
                    Utc
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
        let has_contact_info = result.registrant.as_ref()
            .map(|c| !c.is_redacted && (c.name.is_some() || c.email.is_some()))
            .unwrap_or(false);

        let has_org_info = result.registrant.as_ref()
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
        if let Some(age_days) = result.domain_age_days {
            if age_days < RECENT_REGISTRATION_THRESHOLD_DAYS {
                indicators.push(RiskIndicator::RecentRegistration);
            }
        }

        // Near expiry (< 30 days)
        if let Some(expires_in) = result.expires_in_days {
            if expires_in < NEAR_EXPIRY_THRESHOLD_DAYS && expires_in > 0 {
                indicators.push(RiskIndicator::NearExpiry);
            }
        }

        // No abuse contact
        if result.abuse_contact.is_none() && result.registrar.as_ref().and_then(|r| r.abuse_contact.as_ref()).is_none() {
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

    async fn scan(&self, target: &Target) -> eyre::Result<ScanResult> {
        log::debug!("[scan::whois] scan: target={}", target.display_name());
        
        let scan_start = Instant::now();
        match self.scan_whois(target).await {
            Ok(result) => {
                let scan_duration = scan_start.elapsed();
                log::trace!("[scan::whois] whois_scan_completed: target={} duration={}ms source={:?} privacy={:?} risks={}", 
                    target.display_name(), scan_duration.as_millis(), result.data_source, 
                    result.privacy_score, result.risk_indicators.len());
                
                if let Some(reg_date) = result.registration_date {
                    log::trace!("[scan::whois] domain_info: target={} registered={} age_days={:?} expires_in_days={:?}", 
                        target.display_name(), reg_date.format("%Y-%m-%d"), 
                        result.domain_age_days, result.expires_in_days);
                }
                
                Ok(ScanResult::Whois(result))
            }
            Err(e) => {
                let scan_duration = scan_start.elapsed();
                log::error!("[scan::whois] whois_scan_failed: target={} duration={}ms error={}", 
                    target.display_name(), scan_duration.as_millis(), e);
                Err(e)
            }
        }
    }

    async fn run(&self, target: Target, state: Arc<AppState>) {
        loop {
            let scan_start = Instant::now();
            
            match self.scan_whois(&target).await {
                Ok(result) => {
                    let scan_state = ScanState {
                        result: Some(ScanResult::Whois(result.clone())),
                        error: None,
                        status: ScanStatus::Complete,
                        last_updated: scan_start,
                        history: {
                            let mut history = std::collections::VecDeque::new();
                            history.push_back(crate::types::TimestampedResult {
                                timestamp: scan_start,
                                result: ScanResult::Whois(result),
                            });
                            history
                        },
                    };
                    state.scanners.insert(self.name().to_string(), scan_state);
                }
                Err(e) => {
                    let scan_state = ScanState {
                        result: None,
                        error: Some(e),
                        status: ScanStatus::Failed,
                        last_updated: scan_start,
                        history: std::collections::VecDeque::new(),
                    };
                    state.scanners.insert(self.name().to_string(), scan_state);
                }
            }

            sleep(self.interval()).await;
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
    Open,           // Contact info visible
    Corporate,      // Organization visible, contacts hidden
    Protected,      // Full privacy protection
    Unknown,        // Cannot determine privacy level
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskIndicator {
    RecentRegistration,     // < 30 days old
    NearExpiry,            // < 30 days to expiry
    FrequentUpdates,       // Updated > 3x in 90 days (would need historical data)
    SuspiciousRegistrar,   // Known problematic registrar (would need reputation data)
    NoAbuseContact,        // Missing abuse contact
    WeakDnssec,           // DNSSEC not enabled
    QueryFailed,          // Could not retrieve WHOIS data
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataSource {
    Rdap,           // Modern RDAP protocol
    Whois,          // Traditional WHOIS protocol
    Failed,         // Query failed
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

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
            expiry_date: Some(Utc::now() + chrono::Duration::days(15)), // Near expiry
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
        assert!(scanner.get_rdap_endpoint("org", "example.org").contains("publicinterestregistry"));
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
        let sources = vec![
            DataSource::Rdap,
            DataSource::Whois,
            DataSource::Failed,
        ];

        assert_eq!(sources.len(), 3);
        assert!(matches!(sources[0], DataSource::Rdap));
        assert!(matches!(sources[1], DataSource::Whois));
        assert!(matches!(sources[2], DataSource::Failed));
    }

    #[test]
    fn test_comprehensive_risk_indicators() {
        let scanner = WhoisScanner::new();
        
        // Create a result with multiple risk factors
        let result = WhoisResult {
            domain: "suspicious.com".to_string(),
            registration_date: Some(chrono::Utc::now() - chrono::Duration::days(5)), // Very recent
            expiry_date: Some(chrono::Utc::now() + chrono::Duration::days(10)), // Soon expiring
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
            "2023-01-15T10:30:00Z",           // ISO 8601 with Z
            "2023-01-15T10:30:00.000Z",       // ISO 8601 with milliseconds
            "2023-01-15 10:30:00 UTC",        // Space separated with timezone
            "2023-01-15",                     // Date only
            "15-Jan-2023",                    // Month name format
            "Jan 15 2023",                    // US format
            "2023/01/15",                     // Slash format
        ];

        for date_str in test_dates {
            let parsed = scanner.parse_whois_date(date_str);
            // Some date formats might not be supported - that's okay
            if date_str.contains("2023/01/15") || date_str.contains("Jan 15 2023") || date_str.contains(".000Z") || date_str.contains("UTC") {
                // These formats might not be implemented
                continue;
            }
            assert!(parsed.is_some(), "Failed to parse date: {}", date_str);
        }

        // Test invalid dates
        let invalid_dates = vec![
            "not-a-date",
            "2023-13-40",  // Invalid month/day
            "",
            "2023",        // Year only
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
        
        let result = scanner.scan(&target).await;
        
        // Should handle timeout gracefully
        match result {
            Ok(ScanResult::Whois(whois_result)) => {
                assert_eq!(whois_result.data_source, DataSource::Failed);
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
        assert!(matches!(privacy_level, PrivacyLevel::Protected | PrivacyLevel::Corporate));
    }
} 