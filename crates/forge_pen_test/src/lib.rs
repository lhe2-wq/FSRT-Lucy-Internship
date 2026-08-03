//! Forge pen-testing toolkit.

mod mint_common;

// Errors + result alias.
pub use mint_common::{MintError, Result};

// Config model (deserialised from `fsrt-remote.toml`) + product selector.
pub use mint_common::{
    AuthConfig, ConfluenceConfig, GlobalAppConfig, ManifestContext, MintFctConfig, Product,
};

// High-level operations: load config/manifest, build auth, resolve the
// environment, and mint the token.
pub use mint_common::{
    build_auth_headers, extract_manifest_context, load_config, load_manifest, mint_fct_jwt,
    mint_fct_jwt_opts, resolve_environment,
};
