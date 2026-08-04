//! Forge Context Token (FCT) minting — the `mint-fct` capability.
//!
//! CLI parsing lives in `fsrt`; this module owns the orchestration:
//! load config + manifest, resolve the module/product/environment, and mint
//! the token. The caller supplies `module_key` (a required `fsrt mint-fct`
//! positional argument) — there is no manifest auto-detection.

use std::path::Path;

use forge_loader::manifest::ForgeManifest;
use tracing::{debug, info};

use crate::mint_common::{
    MintError, Product, Result, build_auth_headers, build_variables, extract_manifest_context,
    load_config, load_manifest, mint_fct_jwt, resolve_environment, resolved_product,
};

/// Runs the `mint-fct` flow and returns the minted FCT JWT.
///
/// - `app_dir`     — Forge app directory containing `manifest.yml`/`.yaml`.
/// - `config_path` — path to the `fsrt-remote.toml` config file.
/// - `module_key`  — required manifest module key to mint the token for.
/// - `dry_run`     — when `true`, build and return the request variables as a
///   pretty JSON string instead of calling the GraphQL gateway.
///
/// On success returns `Ok(Some(jwt))` for a real mint, or `Ok(None)` for a dry
/// run (the rendered variables are printed to stdout).
pub fn run_mint_fct(
    app_dir: &Path,
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

    // Derive `cloud_id` from `site_domain` (via `_edge/tenant_info`) when it is
    // not set explicitly in the config.
    config.resolve_cloud_id()?;

    let manifest_text = load_manifest(app_dir)?;
    let manifest: ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    let mut manifest_ctx = extract_manifest_context(&manifest, module_key)?;

    // The request shape is resolved from the manifest.
    let product = resolved_product(&config, &manifest_ctx);
    if config.auth.auth_type == "basic_api_token" && product != Product::Confluence {
        return Err(MintError::Config(
            "auth.type=basic_api_token is only supported for the Confluence request shape; \
             use raw_cookie for global apps"
                .to_string(),
        ));
    }

    info!(
        product = %product,
        app_id = %manifest_ctx.app_id,
        app_id_bare = %manifest_ctx.app_id_bare,
        app_name = ?manifest_ctx.app_name,
        module_key = ?manifest_ctx.module_key,
        module_type = ?manifest_ctx.module_type,
        endpoint = %config.graphql_endpoint(),
        "derived manifest context"
    );

    let auth_headers = build_auth_headers(&config.auth)?;

    resolve_environment(&config, &mut manifest_ctx, &auth_headers)?;

    if dry_run {
        let variables = build_variables(&config, &manifest_ctx)?;
        let pretty =
            serde_json::to_string_pretty(&variables).unwrap_or_else(|_| variables.to_string());
        info!("dry run requested — not sending GraphQL request");
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
        for key in ["", "   "] {
            let err =
                run_mint_fct(Path::new("."), Path::new("./nope.toml"), key, true).unwrap_err();
            assert!(matches!(err, MintError::Config(_)), "got: {err:?}");
            assert!(err.to_string().contains("module_key"));
        }
    }
}
