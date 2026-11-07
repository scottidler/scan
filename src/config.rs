//! `scan.yml`: the user's additions to the built-in distrust list. The file is optional, but one
//! that exists and cannot be read, parsed or validated stops scan; it is never read as empty.

use crate::scan::tls::{DistrustedCa, validate};
use eyre::{Result, WrapErr};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Entries added after the built-ins; they never replace them.
    #[serde(default)]
    pub distrusted_cas: Vec<DistrustedCa>,
}

/// XDG config dir, honoring `$XDG_CONFIG_HOME` and falling back to `$HOME/.config`.
fn xdg_config_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(dir);
        if path.is_absolute() {
            return Some(path);
        }
    }
    dirs::home_dir().map(|h| h.join(".config"))
}

/// Where `scan.yml` is read from; `None` when there is no home directory and no absolute
/// `$XDG_CONFIG_HOME`.
pub fn config_path() -> Option<PathBuf> {
    xdg_config_dir().map(|dir| dir.join("scan").join("scan.yml"))
}

/// Read and validate one config file. Only `NotFound` counts as "no file".
pub fn load_from(path: &Path) -> Result<Config> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            log::info!("[config] load_from: no config at {}", path.display());
            return Ok(Config::default());
        }
        Err(e) => return Err(e).wrap_err_with(|| format!("cannot read {}", path.display())),
    };
    // A comment-only or blank file deserializes to `None`, not a missing-field error.
    let parsed: Option<Config> =
        serde_yaml::from_str(&text).wrap_err_with(|| format!("invalid config {}", path.display()))?;
    let config = parsed.unwrap_or_default();
    for (index, ca) in config.distrusted_cas.iter().enumerate() {
        validate(ca).wrap_err_with(|| format!("invalid config {}: distrusted-cas entry {}", path.display(), index))?;
    }
    log::info!(
        "[config] load_from: {} loaded {} user distrusted-cas entries",
        path.display(),
        config.distrusted_cas.len()
    );
    Ok(config)
}

/// Load `scan.yml` from the XDG config dir.
pub fn load() -> Result<Config> {
    match config_path() {
        Some(path) => load_from(&path),
        None => {
            log::warn!(
                "[config] load: no home directory and no absolute $XDG_CONFIG_HOME; built-in distrust list only"
            );
            Ok(Config::default())
        }
    }
}

#[cfg(test)]
mod tests;
