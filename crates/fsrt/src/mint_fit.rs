//! Forge Invocation Token (FIT) minting — `fsrt mint-fit` subcommand.
//!
//! A FIT (ForgeInvocationToken) signs a specific backend invocation.
//! It is minted in two steps internally:
//!   1. Mint an FCT (Forge Context Token) — proves the user can invoke the extension
//!   2. Use the FCT to mint a FIT — signs the actual remote backend invocation
//!
//! The user only runs one command:
//!   fsrt mint-fit --app-dir ./my-app --config ./cfg.yaml
//!
//! The FCT is minted internally and used as input to the FIT mutation.
//! It is never written to disk.

// ============================================================================
// Imports
// ============================================================================

use super::mint_common::{
    build_auth_headers,
    detect_remote_key,
    extract_manifest_context,
    load_manifest,
    mint_fct_jwt,
    post_graphql,
    MintError,
    MintFctConfig,
};

use forge_loader::manifest::ForgeManifest;
use serde_json::Value as JsonValue;
use std::fs;

// ============================================================================
// GraphQL mutation for FIT minting
// ============================================================================
//
// `SignInvocationTokenForUIInput` fields:
//   forgeContextToken: String!  — the FCT JWT minted in step 1
//   remoteKey: String!          — identifies the remote backend in manifest.yml
//
// Return type `ForgeInvocationToken` fields:
//   jwt: String!        — the actual Forge Invocation Token
//   expiresAt: String!  — expiry in milliseconds since UNIX epoch
// The return type is `SignInvocationTokenForUIResponse` which wraps a
// `ForgeInvocationToken` object containing the jwt and expiresAt fields.
const FIT_MUTATION: &str = r#"mutation SignInvocationTokenForUI($input: SignInvocationTokenForUIInput!) {
  signInvocationTokenForUI(input: $input) {
    forgeInvocationToken {
      jwt
      expiresAt
    }
  }
}"#;

const FIT_OPERATION_NAME: &str = "SignInvocationTokenForUI";

// ============================================================================
// CLI arguments
// ============================================================================
//
// Usage:
//   fsrt mint-fit --app-dir ./my-app --config ./cfg.yaml [--dry-run]
//
// Same flags as mint-fct — same YAML config file, same app directory.
// No --fct or --fct-file flag needed — the FCT is minted internally.
#[derive(Debug, clap::Args)]
pub struct MintFitArgs {
    /// Forge app directory containing manifest.yml
    #[arg(long, value_hint = clap::ValueHint::DirPath)]
    pub app_dir: std::path::PathBuf,

    /// Path to the FCT/FIT config YAML file (see scripts/mint_fct_min_info.confluence.yaml)
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub config: std::path::PathBuf,

    /// Print request details but do not call GraphQL
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

// ============================================================================
// run_mint_fit()
// ============================================================================
// Top-level entry point for `fsrt mint-fit`.
// Called from main.rs after clap parses the CLI arguments.
pub fn run_mint_fit(args: &MintFitArgs) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // --- 1. Load and parse the YAML config file ---
    // The same YAML format as mint-fct — same auth, same confluence IDs.
    let config_text = fs::read_to_string(&args.config)?;
    let config: MintFctConfig = serde_yaml::from_str(&config_text)?;

    if config.product != "confluence" {
        return Err(MintError::Config(
            "mint-fit is Confluence-only. Set `product: confluence` in your config.".into(),
        )
        .into());
    }

    // --- 2. Load manifest.yml ---
    // load_manifest() returns (raw_text, raw_json_value).
    // raw_text is kept alive so ForgeManifest can borrow from it.
    // raw_json is used to walk private fields (modules, remotes).
    let (manifest_text, raw_manifest) = load_manifest(&args.app_dir)?;
    let manifest: ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    // --- 3. Extract manifest context ---
    // module_key — for the FCT minting step (same as mint-fct)
    // remote_key — for the FIT minting step (new — from manifest["remotes"][0]["key"])
    let config_module_key = config
        .confluence
        .as_ref()
        .and_then(|c| c.module_key.as_deref());

    let manifest_ctx = extract_manifest_context(&manifest, &raw_manifest, config_module_key);

    // detect_remote_key() walks raw_manifest["remotes"][0]["key"].
    // Returns None if no remotes are declared — we error clearly in that case.
    // An optional override in the config takes priority over auto-detection
    // (useful for apps with multiple remotes).
    let remote_key_override = config
        .confluence
        .as_ref()
        .and_then(|c| c.module_key.as_deref()); // reuse module_key field for now

    let remote_key = detect_remote_key(&raw_manifest, remote_key_override)
        .ok_or_else(|| MintError::Config(
            "No remotes declared in manifest.yml. \
             FIT minting requires a remote backend. \
             Add a `remotes:` section with a `key:` field to your manifest.".to_string()
        ))?;

    // --- 4. Print diagnostic info ---
    println!("\n=== Derived manifest context ===");
    println!("  app_id:      {}", manifest_ctx.app_id);
    println!("  app_id_bare: {}", manifest_ctx.app_id_bare);
    println!("  app_name:    {:?}", manifest_ctx.app_name);
    println!("  module_key:  {:?}", manifest_ctx.module_key);
    println!("  module_type: {:?}", manifest_ctx.module_type);
    println!("  remote_key:  {}", remote_key);
    println!("\n=== GraphQL endpoint ===");
    println!("{}", config.graphql_endpoint);

    // --- 5. Build auth headers ---
    // Same auth headers for both the FCT and FIT requests —
    // both go to the same Atlassian gateway with the same credentials.
    let auth_headers = build_auth_headers(&config.auth)?;

    // --- 6. Dry-run exit ---
    if args.dry_run {
        println!("\n=== FIT GraphQL mutation ===");
        println!("{}", FIT_MUTATION);
        println!("\n=== FIT GraphQL variables (preview) ===");
        // We can't show the real FCT JWT without minting it, so show the shape.
        let preview_vars = serde_json::json!({
            "input": {
                "forgeContextToken": "<FCT JWT — minted at runtime>",
                "remoteKey": remote_key,
            }
        });
        println!("{}", serde_json::to_string_pretty(&preview_vars)?);
        println!("\nDry run requested — not sending GraphQL request.");
        return Ok(());
    }

    // --- 7. Step 1: Mint the FCT ---
    // mint_fct_jwt() lives in mint_common and is shared with mint_fct.rs.
    // It sends the confluence_generateForgeContextToken mutation and returns
    // the JWT string. The JWT is a local variable — never written to disk.
    println!("\n=== Step 1: Minting FCT ===");
    let fct_jwt = mint_fct_jwt(&config, &manifest_ctx, &auth_headers)?;
    println!("FCT minted successfully.");

    // --- 8. Step 2: Mint the FIT using the FCT ---
    // Build the FIT mutation variables.
    // `forgeContextToken` is the FCT JWT we just minted.
    // `remoteKey` identifies which remote backend to sign the invocation for.
    println!("\n=== Step 2: Minting FIT ===");
    println!("FIT mutation: {}", FIT_OPERATION_NAME);

    let fit_variables = serde_json::json!({
        "input": {
            "forgeContextToken": fct_jwt,   // ← the FCT JWT from step 1
            "remoteKey": remote_key,         // ← from manifest["remotes"][0]["key"]
        }
    });

    println!("\n=== FIT GraphQL variables ===");
    println!("{}", serde_json::to_string_pretty(&fit_variables)?);

    // Send the FIT minting request.
    // post_graphql() is shared from mint_common — same function mint_fct uses.
    let (status, body) = post_graphql(
        &config.graphql_endpoint,
        FIT_OPERATION_NAME,
        &auth_headers,
        FIT_MUTATION,
        &fit_variables,
    )?;

    println!("\n=== FIT GraphQL response ===");
    println!("HTTP status: {}", status);

    // Parse and pretty-print the response.
    let parsed: JsonValue = serde_json::from_str(&body).map_err(|e| {
        println!("{}", body);
        MintError::Json(e)
    })?;
    println!("{}", serde_json::to_string_pretty(&parsed)?);

    // Navigate to the FIT fields in the response.
    // data.signInvocationTokenForUI.forgeInvocationToken → { jwt, expiresAt }
    let fit_obj = parsed
        .get("data")
        .and_then(|d| d.get("signInvocationTokenForUI"))
        .and_then(|r| r.get("forgeInvocationToken"));

    match fit_obj {
        Some(token) => {
            let jwt = token.get("jwt").and_then(|v| v.as_str());
            let expires_at = token.get("expiresAt").and_then(|v| v.as_str());

            if let Some(jwt) = jwt {
                println!("\n=== SUCCESS: Forge Invocation Token ===");
                println!("jwt:       {}", jwt);
                println!("expiresAt: {}", expires_at.unwrap_or("<missing>"));
            } else {
                println!("\n[!] signInvocationTokenForUI returned but jwt field is missing.");
            }
        }
        None => {
            // Check for GraphQL-level errors.
            if let Some(errors) = parsed.get("errors").and_then(|e| e.as_array()) {
                println!("\n[!] Server returned errors:");
                for err in errors {
                    println!(
                        "    - {}",
                        err.get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("(no message)")
                    );
                }
                return Err(MintError::FctFailed("FIT minting failed — see errors above".into()).into());
            }
            println!("\n[!] signInvocationTokenForUI missing from response data.");
        }
    }

    if (200..300).contains(&(status as u32)) {
        Ok(())
    } else {
        Err(MintError::Http(format!("Server returned HTTP {}", status)).into())
    }
}
