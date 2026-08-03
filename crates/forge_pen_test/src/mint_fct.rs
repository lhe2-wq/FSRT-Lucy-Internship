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
    build_auth_headers, build_variables, extract_manifest_context, load_config, load_manifest,
    mint_fct_jwt, resolve_environment, MintError, Result,
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
    // The module key is a required input; reject an empty value early with a
    // clear message rather than failing deep in manifest resolution.
    if module_key.trim().is_empty() {
        return Err(MintError::Config(
            "a non-empty module_key is required (usage: fsrt mint-fct <module_key>)".to_string(),
        ));
    }

    // 1. Load config + manifest.
    let config = load_config(config_path)?;
    let manifest_text = load_manifest(app_dir)?;
    let manifest: ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    // 2. Resolve the manifest context for the requested module. This errors if
    //    `module_key` matches no FCT-capable module in the manifest.
    let mut manifest_ctx = extract_manifest_context(&manifest, module_key)?;

    // Diagnostics go to stderr (via tracing); only the JWT is written to stdout.
    info!(
        product = %config.product,
        app_id = %manifest_ctx.app_id,
        app_id_bare = %manifest_ctx.app_id_bare,
        app_name = ?manifest_ctx.app_name,
        module_key = ?manifest_ctx.module_key,
        module_type = ?manifest_ctx.module_type,
        endpoint = %config.graphql_endpoint,
        "derived manifest context"
    );

    // 3. Build auth headers.
    let auth_headers = build_auth_headers(&config.auth)?;

    // 4. Resolve environment_id + app_version from the Forge platform
    //    (production → default fallback when not pinned in config).
    resolve_environment(&config, &mut manifest_ctx, &auth_headers)?;

    // 5. Dry run: render and return the variables without sending the request.
    if dry_run {
        let variables = build_variables(&config, &manifest_ctx)?;
        let pretty = serde_json::to_string_pretty(&variables)
            .unwrap_or_else(|_| variables.to_string());
        info!("dry run requested — not sending GraphQL request");
        println!("{pretty}");
        return Ok(None);
    }

    // 6. Mint the token.
    let jwt = mint_fct_jwt(&config, &manifest_ctx, &auth_headers)?;
    debug!("successfully minted Forge Context Token");
    Ok(Some(jwt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_mint_fct_rejects_empty_module_key() {
        // An empty/whitespace module key fails fast before any config/manifest
        // I/O, with a clear config error.
        for key in ["", "   "] {
            let err = run_mint_fct(Path::new("."), Path::new("./nope.toml"), key, true)
                .unwrap_err();
            assert!(matches!(err, MintError::Config(_)), "got: {err:?}");
            assert!(err.to_string().contains("module_key"));
        }
    }
}
