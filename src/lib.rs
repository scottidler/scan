pub mod scanner;
pub mod scan;
pub mod target;
pub mod types;
pub mod pretty;
pub mod tui;

// Re-export key types and functions at the crate root
pub use scanner::Scanner;
pub use target::Target;
pub use types::{AppState, ScanResult, ScanState, ScanStatus};
pub use tui::{TuiApp, init_terminal, restore_terminal};
pub use scan::{create_default_scanners, spawn_scanner_tasks}; 