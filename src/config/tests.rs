use super::*;
use chrono::NaiveDate;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn write_config(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scan.yml");
    std::fs::write(&path, text).unwrap();
    (dir, path)
}

#[test]
fn xdg_config_dir_honors_env_and_falls_back() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("XDG_CONFIG_HOME").ok();
    let dir = tempfile::tempdir().unwrap();

    unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path()) };
    assert_eq!(xdg_config_dir().as_deref(), Some(dir.path()));
    assert_eq!(config_path().unwrap(), dir.path().join("scan").join("scan.yml"));

    unsafe { std::env::set_var("XDG_CONFIG_HOME", "relative/path") };
    assert!(xdg_config_dir().unwrap().ends_with(".config"));

    unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    assert!(xdg_config_dir().unwrap().ends_with(".config"));

    match saved {
        Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
        None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
    }
}

#[test]
fn a_missing_file_loads_as_default() {
    let dir = tempfile::tempdir().unwrap();
    let config = load_from(&dir.path().join("absent.yml")).unwrap();
    assert_eq!(config, Config::default());
}

#[test]
fn a_comment_only_file_loads_as_default() {
    let (_dir, path) = write_config("# only a comment\n\n# another\n");
    assert_eq!(load_from(&path).unwrap(), Config::default());
}

#[test]
fn a_blank_file_loads_as_default() {
    let (_dir, path) = write_config("");
    assert_eq!(load_from(&path).unwrap(), Config::default());
}

#[test]
fn a_valid_entry_loads_with_an_unquoted_date() {
    let (_dir, path) = write_config(
        "distrusted-cas:\n  - name: Test CA\n    organizations: [\"Test CA Ltd.\"]\n    issuer-common-names: [\"Test Root\"]\n    distrusted-after: 2026-11-16\n    source: https://example.com/test\n",
    );
    let config = load_from(&path).unwrap();
    assert_eq!(config.distrusted_cas.len(), 1);
    let ca = &config.distrusted_cas[0];
    assert_eq!(ca.name, "Test CA");
    assert_eq!(ca.organizations, vec!["Test CA Ltd."]);
    assert_eq!(ca.issuer_common_names, vec!["Test Root"]);
    assert_eq!(ca.distrusted_after, NaiveDate::from_ymd_opt(2026, 11, 16));
}

#[test]
fn an_unknown_key_names_the_key_and_the_path() {
    let (_dir, path) = write_config("distrusted-cas:\n  - name: X\n    organisations: [a]\n    source: https://x\n");
    let msg = format!("{:#}", load_from(&path).unwrap_err());
    assert!(msg.contains("organisations"), "{msg}");
    assert!(msg.contains(&path.display().to_string()), "{msg}");
}

#[test]
fn an_unknown_top_level_key_is_an_error() {
    let (_dir, path) = write_config("distrusted_cas: []\n");
    let msg = format!("{:#}", load_from(&path).unwrap_err());
    assert!(msg.contains("distrusted_cas"), "{msg}");
}

#[test]
fn an_entry_with_no_matcher_names_the_entry_and_the_path() {
    let (_dir, path) = write_config("distrusted-cas:\n  - name: Broken\n    source: https://example.com/x\n");
    let msg = format!("{:#}", load_from(&path).unwrap_err());
    assert!(msg.contains("Broken"), "{msg}");
    assert!(msg.contains("entry 0"), "{msg}");
    assert!(msg.contains(&path.display().to_string()), "{msg}");
}

#[test]
fn an_entry_missing_its_name_is_an_error() {
    let (_dir, path) = write_config("distrusted-cas:\n  - organizations: [a]\n    source: https://x\n");
    let msg = format!("{:#}", load_from(&path).unwrap_err());
    assert!(msg.contains("name"), "{msg}");
}

#[test]
fn an_unreadable_path_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let msg = format!("{:#}", load_from(dir.path()).unwrap_err());
    assert!(msg.contains(&dir.path().display().to_string()), "{msg}");
}

#[test]
fn the_shipped_example_loads_as_default() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("scan.yml");
    assert_eq!(load_from(&path).unwrap(), Config::default());
}

#[test]
fn the_shipped_example_entry_is_valid_once_uncommented() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("scan.yml");
    let text = std::fs::read_to_string(path).unwrap();
    let start = text.find("\n# distrusted-cas:\n").unwrap() + 1;
    let uncommented: String = text[start..]
        .lines()
        .map(|line| format!("{}\n", line.strip_prefix("# ").unwrap_or(line)))
        .collect();
    let (_dir, path) = write_config(&uncommented);
    let config = load_from(&path).unwrap();
    assert_eq!(config.distrusted_cas.len(), 1);
    validate(&config.distrusted_cas[0]).unwrap();
}
