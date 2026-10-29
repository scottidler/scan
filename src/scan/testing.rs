//! Test helpers shared by the scanner tests.

use std::path::Path;

/// Write `content` to `path` as an executable script, ready to exec.
///
/// A child `sh` does the write. If this process held the write fd, a sibling test's fork
/// could inherit it, and exec of the script would fail with `Text file busy (os error 26)`.
pub fn write_executable_script(path: &Path, content: &str) {
    let status = std::process::Command::new("sh")
        .args(["-c", r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#, "sh"])
        .arg(content)
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("spawning sh to write {}: {e}", path.display()));
    assert!(status.success(), "writing {}: {status}", path.display());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_script_is_executable_and_runs() {
        let dir = std::env::temp_dir().join(format!("scan-testing-script-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("hello");
        write_executable_script(&script, "#!/bin/sh\necho \"hi $1\"\n");
        let out = std::process::Command::new(&script).arg("there").output().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hi there\n");
    }

    #[test]
    #[should_panic(expected = "writing")]
    fn unwritable_path_panics_loudly() {
        write_executable_script(Path::new("/nonexistent-dir/script"), "#!/bin/sh\n");
    }
}
