//! Configuration loaded from `fsrt-remote.toml`.

use std::{fs, path::Path};

use serde::Deserialize;

use crate::mint_common::MintError;

/// Untrusted configuration loaded from `fsrt-remote.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsrtRemoteConfig {
    /// Full Atlassian site URL.
    pub site: String,

    /// Session-cookie file configuration.
    pub auth: AuthConfig,

    /// Context ARI owner.
    pub product: String,

    /// Forge installation ID.
    pub installation_id: String,

    /// Optional Forge environment override.
    pub environment_key: Option<String>,

    /// Optional browser-session harvesting configuration.
    pub cookie: Option<CookieConfig>,
}

/// Session-cookie file configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// File containing the Forge session cookie.
    pub raw_cookie_file: String,
}

/// Browser-session harvesting configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CookieConfig {
    /// Atlassian account email address.
    pub username: String,

    /// Whether Chrome should be visible by default.
    pub headed: Option<bool>,

    /// Maximum time to wait for a manual login step.
    pub verify_wait_secs: Option<u64>,
}

impl FsrtRemoteConfig {
    /// Loads untrusted configuration from a TOML file.
    pub fn from_path(config_path: &Path) -> Result<Self, MintError> {
        Ok(toml::from_str(&fs::read_to_string(config_path)?)?)
    }
}
