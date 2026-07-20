//! Forge Context Token (FCT) minting — `fsrt mint-fct` subcommand.
//!
//! This is a Rust port of `scripts/mint_fct_spike.py`.
//! All shared types and functions live in `mint_common`. This module contains
//! only what is specific to the `mint-fct` subcommand:
//!   - `MintFctArgs` — the CLI argument struct
//!   - `run_mint_fct()` — the top-level entry point

// ============================================================================
// Imports
// ============================================================================

// Everything shared with mint_fit lives in mint_common.
// `super::` means "the parent module" — in Rust's module tree, mint_fct and
// mint_common are siblings under the same crate root (main.rs).
use super::mint_common::{
    MintFctConfig,
    Product,
    build_auth_headers,
    extract_manifest_context,
    load_manifest,
    mint_fct_jwt,
    DEFAULT_CONFLUENCE_MUTATION,
    DEFAULT_GLOBAL_APP_MUTATION,
};

use forge_loader::manifest::ForgeManifest;
use std::fs;

// ============================================================================
// CLI arguments
// ============================================================================

// `#[derive(Debug, clap::Args)]`:
//   Debug      → printable for logging
//   clap::Args → clap parses these fields from the CLI flags
//
// The user runs:
//   fsrt mint-fct --app-dir ./my-app --config ./cfg.yaml [--dry-run]
#[derive(Debug, clap::Args)]
pub struct MintFctArgs {
    /// Forge app directory containing manifest.yml
    #[arg(long, value_hint = clap::ValueHint::DirPath)]
    pub app_dir: std::path::PathBuf,

    /// Path to the FCT config YAML file (see scripts/mint_fct_min_info.confluence.yaml)
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub config: std::path::PathBuf,

    /// Print request details but do not call GraphQL
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

// ============================================================================
// run_mint_fct()
// ============================================================================
// Top-level entry point for `fsrt mint-fct`.
// Called from main.rs after clap parses the CLI arguments.
//
// Returns `Box<dyn std::error::Error>` so it can propagate both MintError
// and any other errors (e.g. serde_yaml parse errors) back to main().
pub fn run_mint_fct(args: &MintFctArgs) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // --- 1. Load and parse the YAML config file ---
    let config_text = fs::read_to_string(&args.config)?;
    let config: MintFctConfig = serde_yaml::from_str(&config_text)?;

    // --- 2. Load manifest.yml ---
    // load_manifest() returns (raw_yaml_text, raw_json_value).
    // We need the raw text to parse into ForgeManifest (which borrows from it),
    // and the raw JSON value to walk private module fields.
    let (manifest_text, raw_manifest) = load_manifest(&args.app_dir)?;

    // Parse the typed ForgeManifest — gives us app.id and app.name.
    // The lifetime `'_` means ForgeManifest borrows from manifest_text.
    let manifest: ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    // --- 3. Extract manifest context ---
    // Use the module_key from the product-specific config section if provided,
    // otherwise auto-detect from the manifest.
    let config_module_key = match config.product {
        Product::Confluence => config
            .confluence
            .as_ref()
            .and_then(|c| c.module_key.as_deref()),
        Product::Global => config
            .global
            .as_ref()
            .and_then(|g| g.module_key.as_deref()),
    };

    let manifest_ctx = extract_manifest_context(&manifest, &raw_manifest, config_module_key);

    // --- 4. Build auth headers ---
    let auth_headers = build_auth_headers(&config.auth)?;

    // --- 5. Print diagnostic info ---
    println!("\n=== Product ===");
    println!("  {}", config.product);
    println!("\n=== Derived manifest context ===");
    println!("  app_id:      {}", manifest_ctx.app_id);
    println!("  app_id_bare: {}", manifest_ctx.app_id_bare);
    println!("  app_name:    {:?}", manifest_ctx.app_name);
    println!("  module_key:  {:?}", manifest_ctx.module_key);
    println!("  module_type: {:?}", manifest_ctx.module_type);
    println!("\n=== GraphQL endpoint ===");
    println!("{}", config.graphql_endpoint);
    println!("\n=== GraphQL mutation ===");
    let default_mutation = match config.product {
        Product::Confluence => DEFAULT_CONFLUENCE_MUTATION,
        Product::Global => DEFAULT_GLOBAL_APP_MUTATION,
    };
    println!(
        "{}",
        config.mutation.as_deref().unwrap_or(default_mutation)
    );

    // --- 6. Dry-run exit ---
    // Build and print variables for inspection, but don't send the request.
    if args.dry_run {
        let variables = super::mint_common::build_variables(&config, &manifest_ctx)?;
        println!("\n=== GraphQL variables ===");
        println!("{}", serde_json::to_string_pretty(&variables)?);
        println!("\nDry run requested — not sending GraphQL request.");
        return Ok(());
    }

    // --- 7. Mint the FCT ---
    // mint_fct_jwt() does the POST and returns the JWT string, or an error.
    // This same function is also called by run_mint_fit() in mint_fit.rs.
    let jwt = mint_fct_jwt(&config, &manifest_ctx, &auth_headers)?;

    // --- 8. Print success output ---
    println!("\n=== SUCCESS: Forge Context Token ===");
    println!("jwt: {}", jwt);

    Ok(())
}
