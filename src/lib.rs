pub mod logging;
pub mod pretty;
pub mod scan;
pub mod scanner;
pub mod target;
pub mod tui;
pub mod types;

// Re-export key types and functions at the crate root
pub use logging::{get_log_file_path, init_logging};
pub use scan::{create_default_scanners, spawn_scanner_tasks};
pub use scanner::Scanner;
pub use target::Target;
pub use tui::{TuiApp, init_terminal, restore_terminal};
pub use types::{AppState, ScanResult, ScanState, ScanStatus};
