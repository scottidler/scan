use std::fs;
use std::io::Write;
use std::path::PathBuf;
use log::LevelFilter;

/// Initialize logging to a system-specific log file
pub fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    let log_path = get_log_file_path()?;

    // Ensure the log directory exists
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Get log level from environment variable, default to INFO
    let log_level = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "info".to_string())
        .parse::<LevelFilter>()
        .unwrap_or(LevelFilter::Info);

    // Create a custom logger that writes to file with timestamps
    env_logger::Builder::new()
        .filter_level(log_level)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {} - {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .target(env_logger::Target::Pipe(Box::new(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)?
        )))
        .init();

    log::info!("Logging initialized to: {}", log_path.display());
    log::info!("Log level: {}", log_level);

    Ok(())
}

/// Get the system-specific log file path
pub fn get_log_file_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let log_dir = if cfg!(target_os = "macos") {
        // macOS: ~/Library/Logs/scan/
        dirs::home_dir()
            .ok_or("Could not find home directory")?
            .join("Library")
            .join("Logs")
            .join("scan")
    } else if cfg!(target_os = "linux") {
        // Linux: ~/.local/share/scan/logs/ or /var/log/scan/ if running as root
        if nix::unistd::getuid().is_root() {
            PathBuf::from("/var/log/scan")
        } else {
            dirs::data_local_dir()
                .ok_or("Could not find local data directory")?
                .join("scan")
                .join("logs")
        }
    } else {
        // Fallback for other systems
        dirs::data_local_dir()
            .ok_or("Could not find local data directory")?
            .join("scan")
            .join("logs")
    };

    Ok(log_dir.join("scan.log"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_path_generation() {
        let path = get_log_file_path().unwrap();
        assert!(path.to_string_lossy().contains("scan"));
        assert!(path.to_string_lossy().ends_with("scan.log"));
    }
}