//! Backend function invocation — `fsrt invoke-extension` subcommand.
//!
//! Invokes a backend function via the
//! `invokeExtension` GraphQL mutation.
//!
//! Flow (mirrors mint_fit.rs):
//!   1. Mint an FCT internally (or accept one via `--fct`).
//!   2. Send the `invokeExtension` mutation. The request shape was reverse-
//!      engineered from a real `useInvokeExtensionRelayMutation` browser call
//!      and cross-checked against the @forge/resolver runtime dispatch:
//!
//! ```text
//! input.entryPoint = "resolver" (a constant)
//! input.payload = {
//!   call: {                                    (the resolver envelope)
//!     functionKey:    <resolver.define name>   (--function)
//!     payload:        <tester JSON>            (--payload)
//!   }
//!   context:          <derived context object>
//!   contextToken:     <minted FCT JWT>         (this is where the FCT goes)
//! }
//! ```
//!
//!      The @forge/resolver runtime destructures the event as
//!      `({ call: { functionKey, payload }, context }) => ...` and dispatches on
//!      `call.functionKey`; a bare `call` string yields `functionKey ===
//!      undefined` and "Resolver has no definition for 'undefined'."
//!
//! Usage (from a Forge app dir containing manifest.yml + fsrt-remote.toml,
//! --app-dir defaults to "." and --config to "./fsrt-remote.toml"):
//!   fsrt invoke-extension \
//!       --function "myResolver" \
//!       --payload '{"issueId":"10001"}' \
//!       [--app-dir ./my-app] \
//!       [--config ./cfg.toml] \
//!       [--context '<json or contextId>'] \
//!       [--fct <token>] \
//!       [--async] \
//!       [--dry-run]

// ============================================================================
// Imports
// ============================================================================

use super::mint_common::{
    Product,
    build_auth_headers,
    extract_manifest_context_for_function,
    load_config,
    load_manifest,
    mint_fct_jwt_opts,
    post_graphql,
    resolve_environment,
    MintError,
};

use forge_loader::manifest::ForgeManifest;
use serde_json::Value as JsonValue;

// ============================================================================
// GraphQL mutation for backend invocation
// ============================================================================
//
// `InvokeExtensionInput` fields (from the GraphQL schema):
//   extensionId: ID           — which extension/module to invoke
//   entryPoint:  String       — alternative entry point function ("<resolver>.<function>"
//                               or "<function>"). Omit to hit the default handler.
//   payload:     JSON!        — tester-controlled invocation payload (required)
//   contextIds:  [ID!]!       — applicable context ARIs (required); the authz-boundary knob
//   async:       Boolean      — invoke asynchronously if possible (optional)
//   productEventScopes: [String!] — OAuth scopes for product events (out of scope here)
//
// NOTE: The FCT is NOT a mutation argument — it travels in the auth headers,
// exactly like the FIT step in mint_fit.rs.
//
// `InvokeExtensionResponse` fields we read back:
//   success:  Boolean!               — did the invocation succeed
//   errors:   [MutationError!]       — structured errors, if any
//   response: InvocationResponsePayload — the actual backend response
//
// Deprecated fields (extensionDetails, oAuthScopes) are intentionally omitted —
// neither relates to context or the resolver-qualified function name, and the
// supported fields cover every acceptance criterion.
const INVOKE_MUTATION: &str = r#"mutation InvokeExtension($input: InvokeExtensionInput!) {
  invokeExtension(input: $input) {
    success
    errors {
      message
    }
    response {
      body
    }
  }
}"#;

const INVOKE_OPERATION_NAME: &str = "InvokeExtension";

// ============================================================================
// CLI arguments
// ============================================================================
//
// Reuses the same --app-dir / --config / --dry-run flags as mint-fct / mint-fit
// so the pen-tester workflow is consistent, plus the invocation-specific
// overrides called out in EAS-4566.
#[derive(Debug, clap::Args)]
pub struct InvokeExtensionArgs {
    /// Forge app directory containing manifest.yml.
    /// Defaults to the current working directory.
    #[arg(long, value_hint = clap::ValueHint::DirPath, default_value = ".")]
    pub app_dir: std::path::PathBuf,

    /// Path to the FCT/FIT config TOML file (see fsrt-remote.toml at repo root).
    /// Defaults to ./fsrt-remote.toml in the current working directory.
    #[arg(long, value_hint = clap::ValueHint::FilePath, default_value = "./fsrt-remote.toml")]
    pub config: std::path::PathBuf,

    /// Function to invoke: the @forge/resolver `resolver.define` name (accepts
    /// "<resolver>.<function>" or "<function>"). Dispatched via
    /// `payload.call.functionKey`. Required.
    #[arg(long, required = true)]
    pub function: String,

    /// The invocation payload as a JSON string. Delivered to the resolver
    /// callback as its `payload` argument (via `payload.call.payload`). This is
    /// the tester-controlled attack surface (fuzzing / injection / IDOR).
    /// Required — pass '{}' for an empty payload.
    #[arg(long, required = true)]
    pub payload: String,

    /// Override the full `payload.context` object as a JSON string — e.g. copied
    /// verbatim from a captured `useInvokeExtensionRelayMutation` request. This
    /// is the authorization-boundary knob (who am I / what am I acting on).
    /// Optional: if omitted, a context object is derived from config + manifest data.
    #[arg(long)]
    pub context: Option<String>,

    /// Provide an FCT JWT directly instead of minting one (maps to the auth header).
    /// Useful for replaying a captured token or testing a token minted for a
    /// different user/module to probe the enforcement boundary.
    /// Optional: if omitted, an FCT is minted automatically.
    #[arg(long)]
    pub fct: Option<String>,

    /// Invoke the function asynchronously if the platform supports it
    /// (maps to InvokeExtensionInput.async).
    #[arg(long = "async", default_value_t = false)]
    pub invoke_async: bool,

    /// Print request details but do not call GraphQL
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

// ============================================================================
// run_invoke_extension()
// ============================================================================
// Top-level entry point for `fsrt invoke-extension`.
// Called from main.rs after clap parses the CLI arguments.
pub fn run_invoke_extension(
    args: &InvokeExtensionArgs,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // --- 1. Load and parse the TOML config file (same format as mint-fct/fit) ---
    let config = load_config(&args.config)?;

    // --- 2. Load + parse manifest.yml exactly once ---
    let manifest_text = load_manifest(&args.app_dir)?;
    let manifest: ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    // --- 3. Extract manifest context (app id, module key/type) ---
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

    // When no module_key is configured, prefer the module whose resolver.function
    // matches --function so context.moduleKey matches the invoked resolver.
    let mut manifest_ctx = extract_manifest_context_for_function(
        &manifest,
        config_module_key,
        Some(&args.function),
    )?;

    // --- 4. Parse the tester-supplied payload JSON (needed for both paths) ---
    let payload: JsonValue = serde_json::from_str(&args.payload).map_err(|e| {
        MintError::Config(format!("--payload is not valid JSON: {e}"))
    })?;

    // --- 5. Derive contextIds (required field [ID!]!) from config — no network. ---
    let context_ids = resolve_context_ids(&config)?;

    // ------------------------------------------------------------------------
    // DRY RUN: render the mutation + variables entirely offline.
    // No auth headers, no environment resolution, no FCT minting, no network.
    // For the extensionId ARI we use environment_id from the config if present;
    // otherwise a clear placeholder shows it would be auto-resolved at runtime.
    // ------------------------------------------------------------------------
    if args.dry_run {
        let environment_id = config_environment_id(&config)
            .unwrap_or_else(|| "<environment_id: auto-resolved at runtime>".to_string());
        let extension_id = build_extension_id_str(
            &manifest_ctx.app_id_bare,
            &environment_id,
            manifest_ctx.module_key.as_deref(),
        )?;

        // Offline: environment_id may be a placeholder, and we don't mint an FCT.
        let mut dry_ctx = manifest_ctx.clone();
        if dry_ctx.environment_id.is_none() {
            dry_ctx.environment_id = Some(environment_id.clone());
        }
        let context = resolve_context_object(args, &config, &dry_ctx)?;
        let variables = build_variables(
            &extension_id,
            &context_ids,
            &context,
            &payload,
            "<contextToken: minted at runtime>",
            &args.function,
            args,
        );

        println!("=== invokeExtension mutation ===");
        println!("{}", INVOKE_MUTATION);
        println!("\n=== invokeExtension variables ===");
        println!("{}", serde_json::to_string_pretty(&variables)?);
        println!("\n=== GraphQL endpoint (would POST here) ===");
        println!("{}", config.graphql_endpoint);
        println!("\nDry run requested — not sending GraphQL request.");
        return Ok(());
    }

    // --- 6. Build auth headers (live path only) ---
    let auth_headers = build_auth_headers(&config.auth)?;

    // --- 6b. Resolve environment_id + app_version (read-only, populates ctx) ---
    // Needed so we can construct the extensionId ARI below.
    resolve_environment(&config, &mut manifest_ctx, &auth_headers)?;

    // --- 7. Derive the extensionId ARI ---
    // Same shape the FCT variables use in mint_common::build_variables():
    //   ari:cloud:ecosystem::extension/<app_id_bare>/<environment_id>/static/<module_key>
    let extension_id = build_extension_id(&manifest_ctx)?;

    // --- 8. Diagnostic info ---
    println!("\n=== Derived manifest context ===");
    println!("  app_id:      {}", manifest_ctx.app_id);
    println!("  app_id_bare: {}", manifest_ctx.app_id_bare);
    println!("  module_key:  {:?}", manifest_ctx.module_key);
    println!("  module_type: {:?}", manifest_ctx.module_type);
    println!("\n=== Invocation target ===");
    println!("  extensionId: {}", extension_id);
    println!("  entryPoint:  {}", RESOLVER_ENTRY_POINT);
    println!("  functionKey: {}", args.function);
    println!("  contextIds:  {:?}", context_ids);
    println!("  async:       {}", args.invoke_async);
    println!("\n=== GraphQL endpoint ===");
    println!("{}", config.graphql_endpoint);

    // --- 9. Obtain the FCT (mint it, or use the --fct override) ---
    // The FCT authorises the invocation and is embedded as payload.contextToken.
    // We mint it quietly — the tester cares about the invocation result, not the
    // intermediate token exchange — and never print the token itself.
    let fct_jwt = match &args.fct {
        Some(token) => token.clone(),
        None => mint_fct_jwt_opts(&config, &manifest_ctx, &auth_headers, true)?,
    };

    // --- 10. Build the invokeExtension variables (real envelope) ---
    // payload = { call: { functionKey, payload }, context, contextToken }, entryPoint="resolver".
    let context = resolve_context_object(args, &config, &manifest_ctx)?;
    let variables = build_variables(
        &extension_id,
        &context_ids,
        &context,
        &payload,
        &fct_jwt,
        &args.function,
        args,
    );

    // --- 11. Send the invokeExtension mutation ---
    let (_status, body) = post_graphql(
        &config.graphql_endpoint,
        INVOKE_OPERATION_NAME,
        &auth_headers,
        INVOKE_MUTATION,
        &variables,
    )?;

    let parsed: JsonValue = serde_json::from_str(&body).map_err(|e| {
        println!("{}", body);
        MintError::Json(e)
    })?;

    // --- 13. Interpret and print a clean, readable result ---
    // data.invokeExtension → { success, errors, response }
    let invoke_obj = parsed.get("data").and_then(|d| d.get("invokeExtension"));

    println!("\n=== Invocation result ===");

    match invoke_obj {
        Some(result) => {
            let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
            if success {
                println!("Status: SUCCESS");
                match result.get("response").filter(|r| !r.is_null()) {
                    Some(response) => {
                        println!("Response:");
                        println!("{}", serde_json::to_string_pretty(response)?);
                    }
                    None => println!("Response: (empty)"),
                }
                Ok(())
            } else {
                println!("Status: FAILED (backend returned success=false)");
                let msgs = collect_error_messages(result.get("errors"));
                print_error_messages(&msgs);
                Err(MintError::InvocationFailed(summarize_errors(&msgs)).into())
            }
        }
        None => {
            // GraphQL-level (transport/validation) errors, or an unexpected shape.
            println!("Status: FAILED (no invokeExtension payload returned)");
            let msgs = collect_error_messages(parsed.get("errors"));
            print_error_messages(&msgs);
            Err(MintError::InvocationFailed(summarize_errors(&msgs)).into())
        }
    }
}

// Extract `[{ message }]` error messages from an optional GraphQL errors array.
fn collect_error_messages(errors: Option<&JsonValue>) -> Vec<String> {
    errors
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .map(|err| {
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("(no message)")
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

// Print collected error messages as a simple bulleted list.
fn print_error_messages(msgs: &[String]) {
    if msgs.is_empty() {
        println!("Errors: (none reported)");
        return;
    }
    println!("Errors:");
    for m in msgs {
        println!("  - {m}");
    }
}

// Condense error messages into a single string for the returned error value.
fn summarize_errors(msgs: &[String]) -> String {
    if msgs.is_empty() {
        "no error message returned".to_string()
    } else {
        msgs.join("; ")
    }
}

// ============================================================================
// Helpers
// ============================================================================

// Build the extensionId ARI, mirroring the format used by the FCT variables in
// mint_common::build_variables():
//   ari:cloud:ecosystem::extension/<app_id_bare>/<environment_id>/static/<module_key>
fn build_extension_id(
    manifest_ctx: &super::mint_common::ManifestContext,
) -> std::result::Result<String, MintError> {
    let environment_id = manifest_ctx.environment_id.as_deref().ok_or_else(|| {
        MintError::Config(
            "environment_id could not be resolved — cannot build extensionId ARI".into(),
        )
    })?;
    build_extension_id_str(
        &manifest_ctx.app_id_bare,
        environment_id,
        manifest_ctx.module_key.as_deref(),
    )
}

// Pure string builder for the extensionId ARI — no ManifestContext / network
// required, so it is reusable by the offline dry-run path.
fn build_extension_id_str(
    app_id_bare: &str,
    environment_id: &str,
    module_key: Option<&str>,
) -> std::result::Result<String, MintError> {
    let module_key = module_key.ok_or_else(|| {
        MintError::Config(
            "No module key detected in manifest — cannot build extensionId ARI".into(),
        )
    })?;

    Ok(format!(
        "ari:cloud:ecosystem::extension/{}/{}/static/{}",
        app_id_bare, environment_id, module_key
    ))
}

// The literal entryPoint value the platform expects for resolver-backed
// invocations. Captured from a real `useInvokeExtensionRelayMutation` request:
// the frontend always sends entryPoint="resolver" and selects the actual
// function via `payload.call` — NOT via entryPoint.
const RESOLVER_ENTRY_POINT: &str = "resolver";

// Build the `{ input: {...} }` variables for the invokeExtension mutation.
//
// Shape (reverse-engineered from a live browser request):
//   input:
//     extensionId  — target extension ARI
//     contextIds   — applicable context ARIs
//     entryPoint   — the literal "resolver"
//     payload:
//       call:
//         functionKey    — the resolver.define name to dispatch (--function, required)
//         payload        — the tester-controlled user data (--payload, required)
//       context          — rich context object (see build_context_object)
//       contextToken     — the minted FCT JWT (this is where the FCT lives)
//
// Shared by the dry-run and live paths so they can never drift. In dry-run the
// caller passes a placeholder `context_token`.
fn build_variables(
    extension_id: &str,
    context_ids: &[String],
    context: &JsonValue,
    extension_payload: &JsonValue,
    context_token: &str,
    function_key: &str,
    args: &InvokeExtensionArgs,
) -> JsonValue {
    // `call` is the resolver dispatch envelope, NOT a bare function-name string.
    // The @forge/resolver runtime destructures it as
    //   ({ call: { functionKey, payload, jobId }, context }) => ...
    // and dispatches on `call.functionKey`. The tester-supplied user data goes
    // in `call.payload` (that is what the resolver callback receives as its
    // `payload` argument). Sending a bare string here makes the runtime read
    // `("...").functionKey === undefined` and fail with
    //   "Resolver has no definition for 'undefined'."
    let payload = serde_json::json!({
        "call": {
            "functionKey": function_key,
            "payload": extension_payload,
        },
        "context": context,
        "contextToken": context_token,
    });

    let input = serde_json::json!({
        "extensionId": extension_id,
        "contextIds": context_ids,
        "entryPoint": RESOLVER_ENTRY_POINT,
        "async": args.invoke_async,
        "payload": payload,
    });
    serde_json::json!({ "input": input })
}

// Resolve the `payload.context` object.
//
// If the tester passed `--context`, it is used verbatim (must be a JSON object)
// — this lets them paste the full context copied from a captured request.
// Otherwise a context object is derived from config + manifest data.
fn resolve_context_object(
    args: &InvokeExtensionArgs,
    config: &super::mint_common::MintFctConfig,
    manifest_ctx: &super::mint_common::ManifestContext,
) -> std::result::Result<JsonValue, MintError> {
    match &args.context {
        Some(raw) => {
            let parsed: JsonValue = serde_json::from_str(raw).map_err(|e| {
                MintError::Config(format!("--context is not valid JSON: {e}"))
            })?;
            if !parsed.is_object() {
                return Err(MintError::Config(
                    "--context must be a JSON object (the payload.context value)".into(),
                ));
            }
            Ok(parsed)
        }
        None => Ok(build_context_object(config, manifest_ctx)),
    }
}

// Build the `payload.context` object from config + resolved manifest data.
//
// This mirrors the `context` the Forge frontend sends (and which is echoed in
// the FCT's own `context` claim). Fields the CLI cannot know without a live UI
// session (e.g. the specific content/space/localId of the surface the macro is
// rendered on) are included only when present in the config.
fn build_context_object(
    config: &super::mint_common::MintFctConfig,
    manifest_ctx: &super::mint_common::ManifestContext,
) -> JsonValue {
    // Pull the product-specific identifiers out of the active config section.
    let (cloud_id, environment_type, site_url, local_id) = match config.product {
        Product::Confluence => {
            let c = config.confluence.as_ref();
            (
                c.and_then(|c| c.cloud_id.clone()),
                c.and_then(|c| c.environment_type.clone()),
                c.and_then(|c| c.site_url.clone()),
                c.and_then(|c| c.local_id.clone()),
            )
        }
        Product::Global => {
            let g = config.global.as_ref();
            (
                g.and_then(|g| g.cloud_id.clone()),
                g.and_then(|g| g.environment_type.clone()),
                None,
                None,
            )
        }
    };

    let mut context = serde_json::Map::new();
    if let Some(v) = cloud_id {
        context.insert("cloudId".into(), JsonValue::String(v));
    }
    if let Some(v) = local_id {
        context.insert("localId".into(), JsonValue::String(v));
    }
    if let Some(v) = &manifest_ctx.environment_id {
        context.insert("environmentId".into(), JsonValue::String(v.clone()));
    }
    if let Some(v) = environment_type {
        context.insert("environmentType".into(), JsonValue::String(v));
    }
    if let Some(v) = &manifest_ctx.module_key {
        context.insert("moduleKey".into(), JsonValue::String(v.clone()));
    }
    if let Some(v) = site_url {
        context.insert("siteUrl".into(), JsonValue::String(v));
    }
    if let Some(v) = &manifest_ctx.app_version {
        context.insert("appVersion".into(), JsonValue::String(v.clone()));
    }
    if let Some(v) = &manifest_ctx.module_type {
        context.insert(
            "extension".into(),
            serde_json::json!({ "type": v }),
        );
    }

    JsonValue::Object(context)
}

// Read the explicit `environment_id` from the active product section of the
// config, if the tester supplied one. Lets the dry-run render a real ARI
// without a network round-trip.
fn config_environment_id(config: &super::mint_common::MintFctConfig) -> Option<String> {
    match config.product {
        Product::Confluence => config
            .confluence
            .as_ref()
            .and_then(|c| c.environment_id.clone()),
        Product::Global => config
            .global
            .as_ref()
            .and_then(|g| g.environment_id.clone()),
    }
}

// Derive the required top-level contextIds ([ID!]!) for the mutation.
//
// This is a site-scoped ARI matching the product, consistent with the
// contextIds built in mint_common::build_variables(). (The tester-facing
// `--context` override applies to `payload.context`, not to these contextIds.)
fn resolve_context_ids(
    config: &super::mint_common::MintFctConfig,
) -> std::result::Result<Vec<String>, MintError> {
    let (cloud_id, ari_prefix) = match config.product {
        Product::Confluence => (
            config.confluence.as_ref().and_then(|c| c.cloud_id.clone()),
            "ari:cloud:confluence::site",
        ),
        Product::Global => (
            config.global.as_ref().and_then(|g| g.cloud_id.clone()),
            "ari:cloud:jira::site",
        ),
    };

    let cloud_id = cloud_id.ok_or_else(|| {
        MintError::Config(
            "contextIds is required but no cloud_id is set in the config to derive a default. \
             Supply --context-id explicitly."
                .into(),
        )
    })?;

    Ok(vec![format!("{ari_prefix}/{cloud_id}")])
}
