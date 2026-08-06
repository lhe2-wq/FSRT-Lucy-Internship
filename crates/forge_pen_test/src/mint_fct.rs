//! Forge Context Token (FCT) minting — the `mint-fct` capability.
//!
//! CLI parsing and manifest loading live in `fsrt`; this module owns the
//! orchestration: load config, resolve the module/product/environment, and mint
//! the token. The caller supplies the parsed manifest and `module_key`.

use std::path::Path;

use forge_loader::manifest::ForgeManifest;
use tracing::{debug, info};

use crate::mint_common::{
    MintError, Result, build_auth_headers, build_variables, extract_manifest_context, load_config,
    mint_fct_jwt, resolve_environment,
};

/// Runs the `mint-fct` flow and returns the minted FCT JWT.
///
/// - `manifest`    — the parsed Forge manifest.
/// - `config_path` — path to the `fsrt-remote.toml` config file.
/// - `module_key`  — required manifest module key to mint the token for.
/// - `dry_run`     — when `true`, resolve platform metadata and print the request
///   variables without sending the FCT mint mutation.
///
/// On success returns `Ok(Some(jwt))` for a real mint, or `Ok(None)` for a dry
/// run (the rendered variables are printed to stdout).
pub fn run_mint_fct(
    manifest: &ForgeManifest<'_>,
    config_path: &Path,
    module_key: &str,
    dry_run: bool,
) -> Result<Option<String>> {
    if module_key.trim().is_empty() {
        return Err(MintError::Config(
            "a non-empty module_key is required (usage: fsrt mint-fct <module_key>)".to_string(),
        ));
    }

    let mut config = load_config(config_path)?;
    let mut manifest_ctx = extract_manifest_context(manifest, module_key)?;
    config
        .product
        .validate_manifest_module(module_key, &manifest_ctx.extension_type)?;

    // Derive `cloud_id` from `site_domain` (via `_edge/tenant_info`) when it is
    // not set explicitly in the config.
    config.resolve_cloud_id()?;

    // All apps mint via the global-app request shape.
    info!(
        product = %config.product,
        app_id = %manifest_ctx.app_id,
        app_id_bare = %manifest_ctx.app_id_bare,
        app_name = ?manifest_ctx.app_name,
        module_key = ?manifest_ctx.module_key,
        extension_type = %manifest_ctx.extension_type,
        endpoint = %config.graphql_endpoint(),
        "derived manifest context"
    );

    let auth_headers = build_auth_headers(&config.auth)?;

    resolve_environment(&config, &mut manifest_ctx, &auth_headers)?;

    if dry_run {
        let variables = build_variables(&config, &manifest_ctx)?;
        let pretty =
            serde_json::to_string_pretty(&variables).unwrap_or_else(|_| variables.to_string());
        info!("dry run requested — not sending FCT mint mutation");
        println!("{pretty}");
        return Ok(None);
    }

    let jwt = mint_fct_jwt(&config, &manifest_ctx, &auth_headers)?;
    debug!("successfully minted Forge Context Token");
    Ok(Some(jwt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_mint_fct_rejects_empty_module_key() {
        let manifest = ForgeManifest::default();
        for key in ["", "   "] {
            let err = run_mint_fct(&manifest, Path::new("./nope.toml"), key, true).unwrap_err();
            assert!(matches!(err, MintError::Config(_)), "got: {err:?}");
            assert!(err.to_string().contains("module_key"));
        }
    }

    #[test]
    fn run_mint_fct_rejects_product_mismatch_before_network_requests() {
        let manifest: ForgeManifest<'_> = serde_json::from_str(
            r#"{
                "app": { "name": "My App", "id": "ari:cloud:ecosystem::app/app-1" },
                "modules": {
                    "jira:issuePanel": [{ "key": "jira-panel", "function": "handler" }]
                }
            }"#,
        )
        .unwrap();
        let config = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(
            config.path(),
            r#"
site_domain = "network-must-not-be-called.invalid"
product = "confluence"
installation_id = "installation-1"

[auth]
raw_cookie = "tenant.session.token=a.b.c"
"#,
        )
        .unwrap();

        let err = run_mint_fct(&manifest, config.path(), "jira-panel", true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("configured product 'confluence'"),
            "got: {err}"
        );
        assert!(err.contains("jira-panel"), "got: {err}");
        assert!(err.contains("jira:issuePanel"), "got: {err}");
    }
}
