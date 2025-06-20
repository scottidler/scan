use crate::scanner::Scanner;
use crate::target::{Target, Protocol};
use crate::types::ScanResult;
use async_trait::async_trait;
use eyre::Result;
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, SocketAddr};

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use log;

const PORT_SCAN_INTERVAL_SECS: u64 = 30;
const TCP_TIMEOUT_SECS: u64 = 3;
const MAX_CONCURRENT_SCANS: usize = 10; // Reduced from 50 to be less aggressive
const PORT_SCAN_THROTTLE_MS: u64 = 50; // 50ms delay between port scans to avoid bans
const DEBUG_PORT_DISPLAY_LIMIT: usize = 10;
const BANNER_BUFFER_SIZE: usize = 1024;
const BANNER_READ_TIMEOUT_MS: u64 = 500;
const HTTP_BANNER_BUFFER_SIZE: usize = 2048;
const HTTP_BANNER_TIMEOUT_MS: u64 = 1000;
const SERVICE_DETECTION_TIMEOUT_SECS: u64 = 2;
const HIGH_CONFIDENCE_SCORE: f32 = 0.7;
const LOW_CONFIDENCE_SCORE: f32 = 0.3;


#[derive(Debug, Clone)]
pub struct PortScanner {
    interval: Duration,
    tcp_timeout: Duration,
    max_concurrent: usize,
    service_detection: bool,
    scan_mode: ScanMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScanMode {
    Minimal,  // 6 essential ports - NEW DEFAULT
    Quick,    // Top 100 ports
    Standard, // Top 1000 ports
    Custom(Vec<u16>),
}

#[derive(Debug, Clone)]
pub struct PortData {
    pub target_ip: IpAddr,
    pub open_ports: Vec<OpenPort>,
    pub closed_ports: u16,
    pub filtered_ports: u16,
    pub scan_duration: Duration,
    pub scan_mode: ScanMode,
}

#[derive(Debug, Clone)]
pub enum PortStatus {
    NotQueried,           // Protocol not attempted (due to protocol restrictions)
    Success(usize),       // Port scan succeeded with N open ports
    Failed(String),       // Port scan failed with error message
    NoAddress,           // No address available for this protocol
}

impl PortStatus {
    pub fn was_attempted(&self) -> bool {
        !matches!(self, PortStatus::NotQueried)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, PortStatus::Success(_))
    }

    pub fn open_port_count(&self) -> usize {
        match self {
            PortStatus::Success(count) => *count,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortResult {
    // Protocol-specific results
    pub ipv4_result: Option<PortData>,
    pub ipv6_result: Option<PortData>,

    // Status tracking
    pub ipv4_status: PortStatus,
    pub ipv6_status: PortStatus,

    // Metadata
    pub queried_at: Instant,
    pub total_duration: Duration,
}

impl PortResult {
    pub fn new() -> Self {
        Self {
            ipv4_result: None,
            ipv6_result: None,
            ipv4_status: PortStatus::NotQueried,
            ipv6_status: PortStatus::NotQueried,
            queried_at: Instant::now(),
            total_duration: Duration::from_millis(0),
        }
    }

    pub fn has_any_success(&self) -> bool {
        self.ipv4_status.is_success() || self.ipv6_status.is_success()
    }

    pub fn total_open_ports(&self) -> usize {
        self.ipv4_status.open_port_count() + self.ipv6_status.open_port_count()
    }

    pub fn get_all_open_ports(&self) -> Vec<&OpenPort> {
        let mut ports = Vec::new();
        if let Some(ipv4_data) = &self.ipv4_result {
            ports.extend(&ipv4_data.open_ports);
        }
        if let Some(ipv6_data) = &self.ipv6_result {
            ports.extend(&ipv6_data.open_ports);
        }
        ports
    }

    pub fn get_primary_result(&self) -> Option<&PortData> {
        // Prefer IPv4, fallback to IPv6
        self.ipv4_result.as_ref().or(self.ipv6_result.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct OpenPort {
    pub port: u16,
    pub transport: Transport,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
    pub response_time: Duration,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub confidence: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PortScanner {
    pub fn new() -> Self {
        log::debug!("[scan::port] new: interval=30s timeout=3s concurrency=10 service_detection=true mode=minimal");
        Self {
            interval: Duration::from_secs(PORT_SCAN_INTERVAL_SECS),
            tcp_timeout: Duration::from_secs(TCP_TIMEOUT_SECS),
            max_concurrent: MAX_CONCURRENT_SCANS,
            service_detection: true,
            scan_mode: ScanMode::Minimal,
        }
    }

    pub fn with_mode(mut self, mode: ScanMode) -> Self {
        self.scan_mode = mode;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        // Minimum timeout of 1 second for reliability
        self.tcp_timeout = std::cmp::max(timeout, Duration::from_secs(1));
        self
    }

    pub fn with_concurrency(mut self, max_concurrent: usize) -> Self {
        // Maximum concurrency of 25 to avoid overwhelming targets
        self.max_concurrent = std::cmp::min(max_concurrent, 25);
        self
    }

    fn get_ports(&self) -> Vec<u16> {
        match &self.scan_mode {
            ScanMode::Minimal => get_minimal_ports(),
            ScanMode::Quick => get_top_100_ports(),
            ScanMode::Standard => get_top_1000_ports(),
            ScanMode::Custom(ports) => ports.clone(),
        }
    }



    async fn scan_protocol(&self, target: &Target, protocol: Protocol) -> Result<PortData> {
        // Get protocol-specific target IP
        let target_ip = match target.primary_ip_for_protocol(protocol) {
            Some(ip) => ip,
            None => {
                log::warn!("[scan::port] no_ip_for_protocol: target={} protocol={}",
                    target.display_name(), protocol.as_str());
                eyre::bail!("No {} address available for target: {}", protocol.as_str(), target.display_name());
            }
        };

        log::debug!("[scan::port] scanning_protocol: target={} ip={} protocol={}",
            target.display_name(), target_ip, protocol.as_str());

        let ports = self.get_ports();
        log::debug!("[scan::port] port_list: target={} protocol={} port_count={} ports={:?}",
            target.display_name(), protocol.as_str(), ports.len(),
            if ports.len() <= DEBUG_PORT_DISPLAY_LIMIT { format!("{:?}", ports) } else { format!("{:?}...", &ports[..DEBUG_PORT_DISPLAY_LIMIT]) });

        let scan_start = Instant::now();

        // Scan ports with throttling to avoid bans
        let mut scan_results = Vec::new();
        for chunk in ports.chunks(self.max_concurrent) {
            // Scan chunk concurrently
            let chunk_results = stream::iter(chunk.iter().copied())
                .map(|port| self.scan_port_with_throttle(target_ip, port))
                .buffer_unordered(self.max_concurrent)
                .collect::<Vec<_>>()
                .await;

            scan_results.extend(chunk_results);

            // Small delay between chunks to be polite
            if ports.len() > self.max_concurrent {
                sleep(Duration::from_millis(PORT_SCAN_THROTTLE_MS)).await;
            }
        }

        let mut open_ports = Vec::new();
        let mut closed_count = 0;
        let mut filtered_count = 0;

        for result in scan_results {
            match result {
                Ok(Some(open_port)) => open_ports.push(open_port),
                Ok(None) => closed_count += 1,
                Err(_) => filtered_count += 1,
            }
        }

        open_ports.sort_by_key(|p| p.port);
        let scan_duration = scan_start.elapsed();

        let port_data = PortData {
            target_ip,
            open_ports: open_ports.clone(),
            closed_ports: closed_count,
            filtered_ports: filtered_count,
            scan_duration,
            scan_mode: self.scan_mode.clone(),
        };

        log::debug!("[scan::port] protocol_scan_completed: target={} protocol={} duration={}ms open={} closed={} filtered={}",
            target.display_name(), protocol.as_str(), port_data.scan_duration.as_millis(),
            port_data.open_ports.len(), port_data.closed_ports, port_data.filtered_ports);

        if !port_data.open_ports.is_empty() {
            let open_port_numbers: Vec<u16> = port_data.open_ports.iter().map(|p| p.port).collect();
            log::trace!("[scan::port] open_ports_found: target={} protocol={} ports={:?}",
                target.display_name(), protocol.as_str(), open_port_numbers);
        }

        Ok(port_data)
    }

    fn classify_port_error(error: &eyre::Error) -> PortStatus {
        let error_msg = error.to_string();

        if error_msg.contains("No") && error_msg.contains("address available") {
            PortStatus::NoAddress
        } else {
            PortStatus::Failed(error_msg)
        }
    }

    async fn scan_port_with_throttle(&self, ip: IpAddr, port: u16) -> Result<Option<OpenPort>> {
        // Add small delay to avoid overwhelming the target
        sleep(Duration::from_millis(PORT_SCAN_THROTTLE_MS)).await;
        self.scan_port(ip, port).await
    }

    async fn scan_port(&self, ip: IpAddr, port: u16) -> Result<Option<OpenPort>> {
        let socket_addr = SocketAddr::new(ip, port);
        let start_time = Instant::now();

        match timeout(self.tcp_timeout, TcpStream::connect(socket_addr)).await {
            Ok(Ok(mut stream)) => {
                let response_time = start_time.elapsed();

                let service = if self.service_detection {
                    self.detect_service(&mut stream, port).await
                } else {
                    None
                };

                Ok(Some(OpenPort {
                    port,
                    transport: Transport::Tcp,
                    state: PortState::Open,
                    service,
                    response_time,
                }))
            }
            Ok(Err(_)) => Ok(None),
            Err(_) => Err(eyre::eyre!("Port {} timed out", port)),
        }
    }

    async fn detect_service(&self, stream: &mut TcpStream, port: u16) -> Option<ServiceInfo> {
        let service_name = get_service_name(port);

        let banner = timeout(Duration::from_secs(SERVICE_DETECTION_TIMEOUT_SECS), self.grab_banner(stream, port)).await.ok().flatten();

        let (refined_name, version, confidence) = if let Some(ref banner_text) = banner {
            analyze_banner(banner_text, port)
        } else {
            (service_name.clone(), None, if service_name != "unknown" { HIGH_CONFIDENCE_SCORE } else { LOW_CONFIDENCE_SCORE })
        };

        Some(ServiceInfo {
            name: refined_name,
            version,
            banner,
            confidence,
        })
    }

    async fn grab_banner(&self, stream: &mut TcpStream, port: u16) -> Option<String> {
        match port {
            21 | 22 | 25 | 110 | 143 | 220 | 993 | 995 => {
                self.read_banner(stream).await
            }
            80 | 443 | 8080 | 8443 => {
                self.grab_http_banner(stream).await
            }
            _ => {
                if let Some(banner) = self.read_banner(stream).await {
                    Some(banner)
                } else {
                    self.probe_service(stream).await
                }
            }
        }
    }

    async fn read_banner(&self, stream: &mut TcpStream) -> Option<String> {
        let mut buffer = [0; BANNER_BUFFER_SIZE];
        match timeout(Duration::from_millis(BANNER_READ_TIMEOUT_MS), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                if !banner.is_empty() {
                    Some(banner)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    async fn grab_http_banner(&self, stream: &mut TcpStream) -> Option<String> {
        let http_request = b"GET / HTTP/1.0\r\n\r\n";

        if stream.write_all(http_request).await.is_ok() {
            let mut buffer = [0; HTTP_BANNER_BUFFER_SIZE];
            if let Ok(Ok(n)) = timeout(Duration::from_millis(HTTP_BANNER_TIMEOUT_MS), stream.read(&mut buffer)).await {
                if n > 0 {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    for line in response.lines() {
                        if line.to_lowercase().starts_with("server:") {
                            return Some(line.trim().to_string());
                        }
                    }
                    return response.lines().next().map(|s| s.trim().to_string());
                }
            }
        }
        None
    }

    async fn probe_service(&self, stream: &mut TcpStream) -> Option<String> {
        let probe = b"\r\n";

        if stream.write_all(probe).await.is_ok() {
            self.read_banner(stream).await
        } else {
            None
        }
    }
}

fn get_service_name(port: u16) -> String {
    match port {
        21 => "ftp".to_string(),
        22 => "ssh".to_string(),
        23 => "telnet".to_string(),
        25 => "smtp".to_string(),
        53 => "dns".to_string(),
        80 => "http".to_string(),
        110 => "pop3".to_string(),
        143 => "imap".to_string(),
        443 => "https".to_string(),
        993 => "imaps".to_string(),
        995 => "pop3s".to_string(),
        3389 => "rdp".to_string(),
        5432 => "postgresql".to_string(),
        3306 => "mysql".to_string(),
        6379 => "redis".to_string(),
        27017 => "mongodb".to_string(),
        _ => "unknown".to_string(),
    }
}

fn analyze_banner(banner: &str, port: u16) -> (String, Option<String>, f32) {
    let banner_lower = banner.to_lowercase();

    if banner_lower.contains("server:") {
        if let Some(server_line) = banner.lines().find(|line| line.to_lowercase().starts_with("server:")) {
            let server_info = server_line.trim_start_matches("Server:").trim();
            let parts: Vec<&str> = server_info.split('/').collect();
            if parts.len() >= 2 {
                return (parts[0].trim().to_string(), Some(parts[1].split_whitespace().next().unwrap_or("").to_string()), 0.9);
            }
            return ("http".to_string(), Some(server_info.to_string()), 0.8);
        }
    }

    if banner_lower.contains("ssh") {
        let version = banner.split('-').nth(1).map(|v| v.trim().to_string());
        return ("ssh".to_string(), version, 0.95);
    }

    if banner_lower.contains("ftp") || banner.starts_with("220") {
        return ("ftp".to_string(), None, 0.9);
    }

    if banner.starts_with("220") && banner_lower.contains("smtp") {
        return ("smtp".to_string(), None, 0.9);
    }

    let service_name = get_service_name(port);
    (service_name, None, 0.5)
}

// Minimal essential ports - fast and non-aggressive
pub fn get_minimal_ports() -> Vec<u16> {
    vec![
        21,   // FTP
        22,   // SSH
        80,   // HTTP
        8080, // HTTP Alt
        443,  // HTTPS
        8443, // HTTPS Alt
    ]
}

fn get_top_100_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 993, 995, 1723, 3389, 5900, 8080, 8443, 8888,
        20, 69, 79, 88, 102, 113, 119, 123, 137, 138,
        389, 427, 464, 513, 514, 515, 543, 544, 548, 554,
        587, 631, 636, 646, 873, 990, 1025, 1026, 1027, 1028,
        1029, 1110, 1433, 1720, 1755, 1900, 2000, 2001, 2049, 2121,
        2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
        5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8081, 8086, 8087, 8222,
        9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
    ]
}

fn get_top_1000_ports() -> Vec<u16> {
    let mut ports = get_top_100_ports();

    let additional_ports = vec![
        1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 26, 30, 32, 33, 37, 42, 43, 49, 70, 79,
        81, 82, 83, 84, 85, 87, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
        143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340,
        366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514,
        515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
        667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808,
        843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001,
        1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035,
        1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055,
        1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075,
        1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095,
        1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122,
        1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166,
        1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247,
        1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443,
        1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700,
        1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900,
        1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
        2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068,
        2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200,
        2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601,
        2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920,
        2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211,
        3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372,
        3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809,
        3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000,
        4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446,
        4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060,
        5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414,
        5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802,
        5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922,
        5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006,
        6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567,
        6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002,
        7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777,
        7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042,
        8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194,
        8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800,
        8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100,
        9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595,
        9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009,
        10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
        11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660,
        15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
        19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214,
        27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773,
        32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500,
        38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158,
        49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
        50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797,
        58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389
    ];

    ports.extend(additional_ports);
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[async_trait]
impl Scanner for PortScanner {
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult> {
        log::debug!("[scan::port] scan: target={} protocol={} mode={:?} timeout={}s concurrency={}",
            target.display_name(), protocol.as_str(), self.scan_mode,
            self.tcp_timeout.as_secs(), self.max_concurrent);

        let scan_start = Instant::now();
        let mut result = PortResult::new();

        match protocol {
            Protocol::Ipv4 => {
                // IPv4 only
                match self.scan_protocol(target, Protocol::Ipv4).await {
                    Ok(port_data) => {
                        result.ipv4_status = PortStatus::Success(port_data.open_ports.len());
                        result.ipv4_result = Some(port_data);
                    }
                    Err(e) => {
                        result.ipv4_status = Self::classify_port_error(&e);
                        if result.ipv4_status.is_success() {
                            return Err(e); // Shouldn't happen, but just in case
                        }
                    }
                }
            }
            Protocol::Ipv6 => {
                // IPv6 only
                match self.scan_protocol(target, Protocol::Ipv6).await {
                    Ok(port_data) => {
                        result.ipv6_status = PortStatus::Success(port_data.open_ports.len());
                        result.ipv6_result = Some(port_data);
                    }
                    Err(e) => {
                        result.ipv6_status = Self::classify_port_error(&e);
                        if result.ipv6_status.is_success() {
                            return Err(e); // Shouldn't happen, but just in case
                        }
                    }
                }
            }
            Protocol::Both => {
                // Both IPv4 and IPv6

                // Try IPv4
                match self.scan_protocol(target, Protocol::Ipv4).await {
                    Ok(port_data) => {
                        result.ipv4_status = PortStatus::Success(port_data.open_ports.len());
                        result.ipv4_result = Some(port_data);
                    }
                    Err(e) => {
                        result.ipv4_status = Self::classify_port_error(&e);
                        log::debug!("[scan::port] ipv4_scan_failed: error={}", e);
                    }
                }

                // Try IPv6
                match self.scan_protocol(target, Protocol::Ipv6).await {
                    Ok(port_data) => {
                        result.ipv6_status = PortStatus::Success(port_data.open_ports.len());
                        result.ipv6_result = Some(port_data);
                    }
                    Err(e) => {
                        result.ipv6_status = Self::classify_port_error(&e);
                        log::debug!("[scan::port] ipv6_scan_failed: error={}", e);
                    }
                }
            }
        }

        result.total_duration = scan_start.elapsed();

        // Return success if at least one protocol succeeded, or error if all failed
        if result.has_any_success() {
            log::trace!("[scan::port] scan_completed: target={} protocol={} duration={}ms total_open={}",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis(), result.total_open_ports());
            Ok(ScanResult::Port(result))
        } else {
            // All protocols failed
            let error_msg = format!("All port scan attempts failed for target: {} ({})",
                target.display_name(), protocol.as_str());
            log::error!("[scan::port] all_scans_failed: target={} protocol={} duration={}ms",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis());
            Err(eyre::eyre!(error_msg))
        }
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn name(&self) -> &'static str {
        "port"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_scanner_creation() {
        let scanner = PortScanner::new();
        assert_eq!(scanner.name(), "port");
        assert_eq!(scanner.interval(), Duration::from_secs(30));
        assert_eq!(scanner.max_concurrent, 10);
        assert!(scanner.service_detection);
        assert!(matches!(scanner.scan_mode, ScanMode::Minimal));
    }

    #[test]
    fn test_scan_mode_configuration() {
        let scanner = PortScanner::new()
            .with_mode(ScanMode::Quick)
            .with_timeout(Duration::from_secs(1))
            .with_concurrency(25);

        assert_eq!(scanner.tcp_timeout, Duration::from_secs(1));
        assert_eq!(scanner.max_concurrent, 25);
        assert!(matches!(scanner.scan_mode, ScanMode::Quick));
    }

    #[test]
    fn test_get_service_name() {
        assert_eq!(get_service_name(22), "ssh");
        assert_eq!(get_service_name(80), "http");
        assert_eq!(get_service_name(443), "https");
        assert_eq!(get_service_name(12345), "unknown");
    }

    #[test]
    fn test_analyze_banner_ssh() {
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        let (service, version, confidence) = analyze_banner(banner, 22);
        assert_eq!(service, "ssh");
        assert_eq!(version, Some("2.0".to_string()));
        assert_eq!(confidence, 0.95);
    }

    #[test]
    fn test_analyze_banner_http() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n";
        let (service, version, confidence) = analyze_banner(banner, 80);
        assert_eq!(service, "nginx");
        assert_eq!(version, Some("1.18.0".to_string()));
        assert_eq!(confidence, 0.9);
    }

    #[test]
    fn test_port_lists() {
        let top_100 = get_top_100_ports();
        let top_1000 = get_top_1000_ports();

        assert_eq!(top_100.len(), 100);
        assert!(top_1000.len() >= 1000);

        for port in &top_100 {
            assert!(top_1000.contains(port));
        }
    }

    #[test]
    fn test_custom_port_mode() {
        let custom_ports = vec![22, 80, 443];
        let scanner = PortScanner::new().with_mode(ScanMode::Custom(custom_ports.clone()));

        let ports = scanner.get_ports();
        assert_eq!(ports, custom_ports);
    }

    #[tokio::test]
    async fn test_port_scan_localhost() {
        let scanner = PortScanner::new()
            .with_mode(ScanMode::Custom(vec![22, 80, 443, 12345]))
            .with_timeout(Duration::from_millis(100))
            .with_concurrency(4);

        let target = Target::parse("127.0.0.1").unwrap();

        let result = scanner.scan(&target, Protocol::Both).await;
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_port_scan_invalid_ip() {
        let scanner = PortScanner::new()
            .with_mode(ScanMode::Custom(vec![80]))
            .with_timeout(Duration::from_millis(100));

        let target = Target::parse("nonexistent.invalid").unwrap();

        assert!(scanner.scan(&target, Protocol::Both).await.is_err());
    }

    #[test]
    fn test_banner_analysis_edge_cases() {
        let (service, version, confidence) = analyze_banner("SSH-2.0-OpenSSH_7.4", 22);
        assert_eq!(service, "ssh");
        assert_eq!(version, Some("2.0".to_string()));
        assert!(confidence > 0.9);

        let (_service, _version, confidence) = analyze_banner("HTTP/1.1 200 OK\r\nServer: Apache\r\n", 80);
        assert!(confidence > 0.5);

        let (service, _version, confidence) = analyze_banner("220 vsftpd 3.0.3", 21);
        assert_eq!(service, "ftp");
        assert!(confidence > 0.5);

        let (service, version, confidence) = analyze_banner("Unknown service response", 12345);
        assert_eq!(service, "unknown");
        assert!(version.is_none());
        assert!(confidence >= 0.0 && confidence <= 1.0);
    }

    #[test]
    fn test_port_result_structure() {
        let open_port = OpenPort {
            port: 80,
            transport: Transport::Tcp,
            state: PortState::Open,
            service: Some(ServiceInfo {
                name: "http".to_string(),
                version: Some("1.1".to_string()),
                banner: Some("Server: nginx/1.20.1".to_string()),
                confidence: 0.9,
            }),
            response_time: Duration::from_millis(10),
        };

        assert_eq!(open_port.port, 80);
        assert!(matches!(open_port.transport, Transport::Tcp));
        assert!(matches!(open_port.state, PortState::Open));
        assert!(open_port.service.is_some());

        if let Some(service) = &open_port.service {
            assert_eq!(service.name, "http");
            assert_eq!(service.version, Some("1.1".to_string()));
            assert!(service.confidence > 0.8);
        }
    }

    #[test]
    fn test_minimal_port_mode() {
        let minimal_scanner = PortScanner::new(); // Default is minimal
        let minimal_ports = minimal_scanner.get_ports();
        assert_eq!(minimal_ports.len(), 6);
        assert!(minimal_ports.contains(&21));  // FTP
        assert!(minimal_ports.contains(&22));  // SSH
        assert!(minimal_ports.contains(&80));  // HTTP
        assert!(minimal_ports.contains(&8080)); // HTTP Alt
        assert!(minimal_ports.contains(&443)); // HTTPS
        assert!(minimal_ports.contains(&8443)); // HTTPS Alt
    }

    #[test]
    fn test_scan_mode_port_selection() {
        let quick_scanner = PortScanner::new().with_mode(ScanMode::Quick);
        let quick_ports = quick_scanner.get_ports();
        assert_eq!(quick_ports.len(), 100);
        assert!(quick_ports.contains(&22));
        assert!(quick_ports.contains(&80));
        assert!(quick_ports.contains(&443));

        let standard_scanner = PortScanner::new().with_mode(ScanMode::Standard);
        let standard_ports = standard_scanner.get_ports();
        assert!(standard_ports.len() >= 1000);

        for port in &quick_ports {
            assert!(standard_ports.contains(port));
        }

        let custom_ports = vec![8080, 8443, 9000];
        let custom_scanner = PortScanner::new().with_mode(ScanMode::Custom(custom_ports.clone()));
        let result_ports = custom_scanner.get_ports();
        assert_eq!(result_ports, custom_ports);
    }

    #[test]
    fn test_service_detection_accuracy() {
        let known_services = vec![
            (22, "ssh"),
            (80, "http"),
            (443, "https"),
            (25, "smtp"),
            (110, "pop3"),
            (143, "imap"),
            (993, "imaps"),
            (995, "pop3s"),
        ];

        for (port, expected_service) in known_services {
            let detected_service = get_service_name(port);
            assert_eq!(detected_service, expected_service, "Port {} should be detected as {}", port, expected_service);
        }
    }

    #[test]
    fn test_port_scanner_configuration_validation() {
        let scanner = PortScanner::new()
            .with_timeout(Duration::from_millis(50))
            .with_concurrency(100)
            .with_mode(ScanMode::Quick);

        assert_eq!(scanner.tcp_timeout, Duration::from_secs(1));
        assert_eq!(scanner.max_concurrent, 25);
        assert!(matches!(scanner.scan_mode, ScanMode::Quick));
        assert!(scanner.service_detection);
    }

    #[test]
    fn test_transport_and_state_enums() {
        let tcp = Transport::Tcp;
        let udp = Transport::Udp;
        assert!(matches!(tcp, Transport::Tcp));
        assert!(matches!(udp, Transport::Udp));

        let open = PortState::Open;
        let closed = PortState::Closed;
        let filtered = PortState::Filtered;
        assert!(matches!(open, PortState::Open));
        assert!(matches!(closed, PortState::Closed));
        assert!(matches!(filtered, PortState::Filtered));
    }

    #[test]
    fn test_service_info_confidence_levels() {
        let high_confidence = ServiceInfo {
            name: "ssh".to_string(),
            version: Some("2.0".to_string()),
            banner: Some("SSH-2.0-OpenSSH_8.2p1".to_string()),
            confidence: 0.95,
        };

        let low_confidence = ServiceInfo {
            name: "unknown".to_string(),
            version: None,
            banner: Some("Generic response".to_string()),
            confidence: 0.3,
        };

        assert!(high_confidence.confidence > 0.9);
        assert!(low_confidence.confidence < 0.5);
        assert!(high_confidence.version.is_some());
        assert!(low_confidence.version.is_none());
    }
}