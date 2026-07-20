//! Forge Context Token (FCT) minting for Confluence.
//!
//! This module is the Rust port of `scripts/mint_fct_spike.py`.
//! It implements the `fsrt mint-fct` subcommand, which:
//!   1. Reads a YAML config file (auth credentials, Confluence IDs, GraphQL variables)
//!   2. Reads the Forge app's manifest.yml (via forge_loader)
//!   3. Renders a GraphQL variables template using values from both
//!   4. POSTs the FCT minting mutation to the Atlassian GraphQL gateway
//!   5. Prints the returned JWT (or errors)

// ============================================================================
// Imports
// ============================================================================

// `base64` encoding is needed for Basic auth (email:token → base64).
// We use the standard Engine trait from the base64 crate.
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

// `regex` is already a workspace dependency (listed in the root Cargo.toml).
// We use it to find and replace ${...} placeholders in the variables template.
use regex::Regex;

// `serde` derives let us automatically deserialise YAML into our config structs.
// `Deserialize` means "this type can be built from YAML/JSON input".
use serde::{Deserialize, Serialize};

// `serde_json::Value` is a type that can hold *any* JSON value — an object,
// array, string, number, boolean, or null. We use it for the variables template
// because its shape is user-defined and not known at compile time.
use serde_json::Value as JsonValue;

// Standard library imports:
use std::collections::HashMap; // key→value map, used for HTTP headers
use std::fs;                   // reading files from disk
use std::path::PathBuf;        // a file system path (cross-platform)

// `forge_loader` is the crate in this workspace that parses manifest.yml.
// `ForgeManifest` is the top-level struct representing the whole manifest.
// We use it only for the public fields we need (app.id, app.name).
use forge_loader::manifest::ForgeManifest;

// ============================================================================
// The default GraphQL mutation — identical to DEFAULT_CONFLUENCE_MUTATION
// in the Python spike. Used when the config file does not supply a `mutation:`
// field.
// ============================================================================

const DEFAULT_CONFLUENCE_MUTATION: &str = r#"mutation useGetContextTokenMutation($cloudId: ID!, $input: ConfluenceForgeContextTokenRequestInput!) {
  confluence_generateForgeContextToken(cloudId: $cloudId, input: $input) {
    success
    errors {
      message
      __typename
    }
    forgeContextToken {
      jwt
      expiresAt
      extensionId
      __typename
    }
    __typename
  }
}"#;

// The operation name the Atlassian gateway uses for routing and CSRF validation.
const OPERATION_NAME: &str = "useGetContextTokenMutation";

// ============================================================================
// Error type
// ============================================================================

// `MintFctError` is our custom error type for this module — equivalent to
// `SpikeError` in the Python spike. It wraps a human-readable message string.
//
// `#[derive(Debug)]` auto-generates code to print this error in debug output.
// `thiserror::Error` is used via the `#[error(...)]` attribute to implement
// the standard `std::error::Error` trait automatically.
#[derive(Debug, thiserror::Error)]
pub enum MintFctError {
    // `{0}` means "print the first (and only) field of this variant".
    #[error("{0}")]
    Config(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// A convenience alias so we don't have to write `Result<T, MintFctError>`
// everywhere — we can just write `Result<T>`.
type Result<T> = std::result::Result<T, MintFctError>;

// ============================================================================
// CLI arguments for the `mint-fct` subcommand
// ============================================================================

// This struct is what clap will populate when the user runs:
//   fsrt mint-fct --app-dir ./my-app --config ./cfg.yaml
//
// `#[derive(Debug, clap::Args)]`:
//   - `Debug`      → lets us print the struct for logging/debugging
//   - `clap::Args` → tells clap to parse these fields from CLI arguments
#[derive(Debug, clap::Args)]
pub struct MintFctArgs {
    /// Forge app directory containing manifest.yml
    // `#[arg(long)]` means this is a `--app-dir` flag (not a positional arg).
    // `value_hint = DirPath` tells shells to autocomplete with directory names.
    #[arg(long, value_hint = clap::ValueHint::DirPath)]
    pub app_dir: PathBuf,

    /// Path to the FCT spike YAML config file
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub config: PathBuf,

    /// Print request details but do not call GraphQL
    // `default_value_t = false` means `--dry-run` defaults to false (off).
    // The user opts in by passing `--dry-run`.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

// ============================================================================
// Config file structs
// ============================================================================
// These structs mirror the shape of the YAML config files in scripts/.
// `serde_yaml` will fill them in automatically when we call
// `serde_yaml::from_str(&yaml_text)`.

// Top-level config — everything in the YAML file.
//
// `#[derive(Debug, Deserialize)]`:
//   - `Debug`       → printable for logging
//   - `Deserialize` → serde can fill this from YAML/JSON
//
// `#[serde(default)]` on a field means "if this key is missing from the YAML,
// use the type's Default value" (e.g. None for Option, empty string for String).
#[derive(Debug, Deserialize, Serialize)]
pub struct MintFctConfig {
    // Which Atlassian product this config targets. Only "confluence" is
    // supported right now, matching the Python spike.
    #[serde(default = "default_product")]
    pub product: String,

    // The Atlassian GraphQL gateway URL, e.g.
    // "https://lhe2.atlassian.net/gateway/api/graphql"
    pub graphql_endpoint: String,

    // Optional: override the default GraphQL mutation. If absent, we use
    // DEFAULT_CONFLUENCE_MUTATION above.
    pub mutation: Option<String>,

    // Auth credentials — how to authenticate the HTTP request.
    pub auth: AuthConfig,

    // Confluence-specific IDs (cloud_id, installation_id, etc.)
    // `Option` because a future product (e.g. Jira) might use a different key.
    pub confluence: Option<ConfluenceConfig>,

    // The GraphQL variables template. This is an arbitrary JSON/YAML object
    // containing `${...}` placeholders that get substituted at runtime.
    // `Option` because we fall back to a hardcoded default if absent.
    pub variables: Option<JsonValue>,
}

// A helper function used by `#[serde(default = "default_product")]` above.
// serde needs a function (not a literal) to produce the default value.
fn default_product() -> String {
    "confluence".to_string()
}

// Auth section of the config — mirrors the `auth:` block in the YAML files.
// Supports two auth types:
//   "raw_cookie"      — paste the full Cookie header from Burp/DevTools
//   "basic_api_token" — Atlassian API token (email + token file)
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthConfig {
    // The auth type string from YAML: "raw_cookie" or "basic_api_token".
    // We default to "raw_cookie" if not specified.
    #[serde(rename = "type", default = "default_auth_type")]
    pub auth_type: String,

    // --- raw_cookie fields ---
    // The full Cookie header value, either inline or read from a file.
    pub raw_cookie: Option<String>,
    pub raw_cookie_file: Option<String>,

    // --- basic_api_token fields ---
    // The Atlassian account email and API token (read from a file).
    pub email: Option<String>,
    pub api_token: Option<String>,
    pub api_token_file: Option<String>,
}

fn default_auth_type() -> String {
    "raw_cookie".to_string()
}

// Confluence-specific config values — mirrors the `confluence:` block in YAML.
// All fields are `Option<String>` because the minimal config only requires
// a few of them (cloud_id, installation_id, environment_id).
// `Serialize` is needed here because we convert ConfluenceConfig into a
// serde_json::Value to build the template context in build_variables().
// Without it, `serde_json::to_value(config.confluence.clone())` won't compile.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfluenceConfig {
    pub cloud_id: Option<String>,
    pub account_id: Option<String>,
    pub content_id: Option<String>,
    pub space_key: Option<String>,
    pub space_id: Option<String>,
    pub installation_id: Option<String>,
    pub environment_id: Option<String>,
    pub environment_type: Option<String>,
    pub local_id: Option<String>,
    pub module_key: Option<String>,
    pub site_url: Option<String>,
}

// ============================================================================
// Manifest context
// ============================================================================
// This struct holds the values we extract from the Forge app's manifest.yml.
// It's equivalent to the dict returned by `extract_manifest_context()` in
// the Python spike.

#[derive(Debug, Clone)]
pub struct ManifestContext {
    // Full ARI, e.g. "ari:cloud:ecosystem::app/8bdd65d0-..."
    pub app_id: String,
    // Just the UUID part after the last "/", e.g. "8bdd65d0-..."
    // Used in the extensionId ARI construction.
    pub app_id_bare: String,
    // App name from manifest (optional — not all manifests set it)
    pub app_name: Option<String>,
    // The key of the module we're minting an FCT for, e.g. "forge-remote-app-node"
    pub module_key: Option<String>,
    // The module type, e.g. "macro", "globalPage", "issuePanel"
    pub module_type: Option<String>,
}

// ============================================================================
// extract_manifest_context()
// ============================================================================
// Reads a parsed ForgeManifest and a raw YAML value (same file, parsed twice)
// and returns a ManifestContext.
// Equivalent to `extract_manifest_context()` in the Python spike.
//
// Why parse twice?
//   ForgeManifest (from forge_loader) gives us typed access to public fields
//   like `app.id` and `app.name`. But the `modules` fields (macros, globalPage,
//   etc.) are private — they are internal to forge_loader and not exposed to us.
//   Rather than modifying forge_loader, we parse the same YAML a second time as
//   a raw `serde_json::Value` (an untyped JSON/YAML tree) and walk it ourselves
//   to find the module key. This is exactly what the Python spike did — it just
//   walked the raw dict with `manifest["modules"]["macro"][0]["key"]`.
//
// If `module_key` is Some, we use it directly without auto-detection.
// If None, we auto-detect the first suitable module in a preferred order.
pub fn extract_manifest_context(
    manifest: &ForgeManifest<'_>,
    raw_manifest: &JsonValue,
    module_key: Option<&str>,
) -> ManifestContext {
    let app_id = manifest.app.id.to_string();

    // Strip the ARI prefix to get the bare UUID.
    // "ari:cloud:ecosystem::app/8bdd65d0-..." → "8bdd65d0-..."
    // If there's no "/" in the id, use the whole string as-is.
    let app_id_bare = app_id
        .rsplit('/')
        .next()
        .unwrap_or(&app_id)
        .to_string();

    let app_name = manifest.app.name.map(|s| s.to_string());

    // Auto-detect the module to mint an FCT for by walking the raw YAML tree.
    let (detected_key, detected_type) = detect_module(raw_manifest, module_key);

    ManifestContext {
        app_id,
        app_id_bare,
        app_name,
        module_key: detected_key,
        module_type: detected_type,
    }
}

// Helper: walks the raw YAML/JSON manifest value to find a module key+type.
// Returns (Option<module_key>, Option<module_type>) as owned Strings.
//
// The raw manifest looks like this as a JSON tree:
//   {
//     "app": { "id": "ari:...", "name": "..." },
//     "modules": {
//       "macro": [{ "key": "my-macro", ... }],
//       "confluence:globalPage": [{ "key": "my-page", ... }],
//       ...
//     }
//   }
// We try each preferred module type in order, matching the Python spike's
// `preferred_types` list.
fn detect_module(
    raw_manifest: &JsonValue,
    requested_key: Option<&str>,
) -> (Option<String>, Option<String>) {
    // If the caller supplied a specific key, use it directly.
    // We still try to infer the type from the manifest, but if we can't find
    // it, we return the key with no type — the server will validate it.
    if let Some(key) = requested_key {
        let module_type = find_type_for_key(raw_manifest, key);
        return (Some(key.to_string()), module_type);
    }

    // Auto-detection: try each module type in preferred order.
    // Each tuple is (YAML key in manifest, module type string for the FCT).
    let preferred: &[(&str, &str)] = &[
        ("macro",                    "macro"),
        ("confluence:globalPage",    "globalPage"),
        ("confluence:spacePage",     "spacePage"),
        ("jira:globalPage",          "globalPage"),
        ("jira:issuePanel",          "issuePanel"),
        ("jira:projectPage",         "globalPage"),
    ];

    let modules = match raw_manifest.get("modules") {
        Some(m) => m,
        None => return (None, None),
    };

    for (yaml_key, module_type) in preferred {
        // Look up the module list, e.g. modules["macro"] → array of module objects
        if let Some(arr) = modules.get(yaml_key).and_then(|v| v.as_array()) {
            // Take the first entry and read its "key" field.
            if let Some(key) = arr.first().and_then(|m| m.get("key")).and_then(|k| k.as_str()) {
                return (Some(key.to_string()), Some(module_type.to_string()));
            }
        }
    }

    // No suitable module found — return (None, None).
    // run_mint_fct() will print a warning but continue.
    (None, None)
}

// Helper: given a specific key, find which module type it belongs to.
fn find_type_for_key(raw_manifest: &JsonValue, key: &str) -> Option<String> {
    let type_map: &[(&str, &str)] = &[
        ("macro",                    "macro"),
        ("confluence:globalPage",    "globalPage"),
        ("confluence:spacePage",     "spacePage"),
        ("jira:globalPage",          "globalPage"),
        ("jira:issuePanel",          "issuePanel"),
        ("jira:projectPage",         "globalPage"),
    ];

    let modules = raw_manifest.get("modules")?;

    for (yaml_key, module_type) in type_map {
        if let Some(arr) = modules.get(yaml_key).and_then(|v| v.as_array()) {
            for module in arr {
                if module.get("key").and_then(|k| k.as_str()) == Some(key) {
                    return Some(module_type.to_string());
                }
            }
        }
    }
    None
}

// ============================================================================
// render_template()
// ============================================================================
// Walks a JSON value tree and replaces every "${dotted.path}" placeholder
// with the value found at that path in the template context.
//
// Equivalent to `render_template()` in the Python spike.
//
// The `context` is a JSON object with two top-level keys:
//   { "manifest": { ... }, "config": { ... } }
// So "${manifest.app_id_bare}" looks up context["manifest"]["app_id_bare"].
pub fn render_template(value: &JsonValue, context: &JsonValue) -> JsonValue {
    match value {
        // Recurse into objects: render each value in the map.
        JsonValue::Object(map) => {
            let rendered: serde_json::Map<String, JsonValue> = map
                .iter()
                .map(|(k, v)| (k.clone(), render_template(v, context)))
                .collect();
            JsonValue::Object(rendered)
        }

        // Recurse into arrays: render each element.
        JsonValue::Array(arr) => {
            JsonValue::Array(arr.iter().map(|v| render_template(v, context)).collect())
        }

        // For strings: find and replace all ${...} placeholders.
        JsonValue::String(s) => render_string(s, context),

        // For all other types (numbers, booleans, null): pass through unchanged.
        other => other.clone(),
    }
}

// Replaces ${...} placeholders in a single string value.
// If the *entire* string is one placeholder (e.g. "${config.confluence.cloud_id}"),
// we return the resolved value as-is (preserving its original type — could be
// a number, boolean, etc.).
// If the placeholder is embedded in a larger string, we stringify the resolved value.
fn render_string(s: &str, context: &JsonValue) -> JsonValue {
    // Build the regex once. The pattern matches "${" + anything except "}" + "}".
    // `unwrap()` is safe here because the pattern is a compile-time constant.
    let re = Regex::new(r"\$\{([^}]+)\}").unwrap();

    // Check if the entire string is a single placeholder — e.g. "${manifest.app_id}".
    // `re.captures(s)` returns the capture groups if there's a match.
    if let Some(caps) = re.captures(s) {
        // `caps[0]` is the full match, `caps[1]` is the first capture group (the path).
        if caps[0] == *s {
            // The whole string is the placeholder — return the resolved value directly.
            let path = &caps[1];
            return get_path(context, path).cloned().unwrap_or(JsonValue::Null);
        }
    }

    // Otherwise, replace each placeholder with its string representation.
    let result = re.replace_all(s, |caps: &regex::Captures<'_>| {
        let path = &caps[1];
        match get_path(context, path) {
            Some(JsonValue::String(v)) => v.clone(),
            Some(JsonValue::Null) | None => String::new(),
            Some(v) => v.to_string(), // numbers, booleans become their string form
        }
    });

    JsonValue::String(result.into_owned())
}

// Walks a JSON value by a dotted path string.
// "config.confluence.cloud_id" → context["config"]["confluence"]["cloud_id"]
// Returns None if any segment of the path doesn't exist.
fn get_path<'a>(context: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let mut cur = context;
    for part in path.split('.') {
        cur = cur.get(part)?; // `?` returns None immediately if the key is missing
    }
    Some(cur)
}

// ============================================================================
// load_secret_from_config()
// ============================================================================
// Reads a secret value from one of two sources (in priority order):
//   1. Inline value in the config (e.g. `raw_cookie: "eyJ..."`)
//   2. A file path           (e.g. `raw_cookie_file: "./session-cookie.txt"`)
//
// Equivalent to `load_secret_from_config()` in the Python spike.
fn load_secret_from_config(
    inline: Option<&str>,
    file_path: Option<&str>,
) -> Result<Option<String>> {
    // 1. Inline value takes highest priority.
    if let Some(v) = inline {
        if !v.is_empty() {
            return Ok(Some(v.to_string()));
        }
    }

    // 2. Read from a file.
    if let Some(path) = file_path {
        if !path.is_empty() {
            let contents = fs::read_to_string(path)
                .map_err(|e| MintFctError::Config(
                    format!("Could not read secret file '{}': {}", path, e)
                ))?;
            return Ok(Some(contents.trim().to_string()));
        }
    }

    // Neither source had a value.
    Ok(None)
}

// ============================================================================
// build_auth_headers()
// ============================================================================
// Reads the `auth:` section of the config and returns the HTTP headers needed
// to authenticate the request.
//
// Returns a HashMap<String, String> — a map of header name → header value.
// Supports two auth types matching the YAML configs in scripts/:
//   "raw_cookie"      — full Cookie header pasted from Burp/DevTools
//   "basic_api_token" — Atlassian API token encoded as HTTP Basic auth
//
// Equivalent to `build_auth_headers()` in the Python spike.
pub fn build_auth_headers(auth: &AuthConfig) -> Result<HashMap<String, String>> {
    // `HashMap::new()` creates an empty key→value map.
    let mut headers = HashMap::new();

    println!("\n=== Auth material ===");
    println!("WARNING: Do not paste this output into public tickets, logs, or chat.");

    match auth.auth_type.as_str() {
        // ------------------------------------------------------------------
        // raw_cookie: paste the full Cookie header value from Burp/DevTools.
        // This is a string like:
        //   "tenant.session.token=eyJ...; atlassian.xsrf.token=5748..."
        // The gateway validates the full cookie context, so the whole string
        // must be present exactly as captured.
        // ------------------------------------------------------------------
        "raw_cookie" => {
            // Try the inline value first, then fall back to reading a file.
            let raw = load_secret_from_config(
                auth.raw_cookie.as_deref(),      // .as_deref() converts Option<String> → Option<&str>
                auth.raw_cookie_file.as_deref(),
            )?
            .ok_or_else(|| MintFctError::Config(
                "auth.type=raw_cookie requires either `raw_cookie` (inline) or `raw_cookie_file` in the config".into()
            ))?;

            // Truncate the printed value for safety — never log a full token.
            println!("Cookie (first 80 chars): {}...", &raw[..raw.len().min(80)]);
            headers.insert("Cookie".to_string(), raw.trim().to_string());
        }

        // ------------------------------------------------------------------
        // basic_api_token: Atlassian API token auth.
        // The gateway accepts HTTP Basic auth with base64("email:api_token").
        // Generate a token at: https://id.atlassian.com/manage-profile/security/api-tokens
        // ------------------------------------------------------------------
        "basic_api_token" => {
            // Email must be set inline in the config (no file — it's not a secret).
            let email = auth.email.as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| MintFctError::Config(
                    "auth.type=basic_api_token requires `email` in the config".into()
                ))?;

            // API token is a secret — read from inline value or a file.
            let token = load_secret_from_config(
                auth.api_token.as_deref(),
                auth.api_token_file.as_deref(),
            )?
            .ok_or_else(|| MintFctError::Config(
                "auth.type=basic_api_token requires either `api_token` (inline) or `api_token_file` in the config".into()
            ))?;

            // HTTP Basic auth format: base64-encode "email:token".
            // This is the standard way Atlassian REST APIs accept API tokens.
            let credentials = format!("{}:{}", email.trim(), token.trim());
            let encoded = B64.encode(credentials.as_bytes());

            println!("Basic auth email: {}", email.trim());
            // Only print the first 20 chars of the encoded credential.
            println!("Authorization: Basic {}... (truncated)", &encoded[..encoded.len().min(20)]);
            headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
        }

        other => {
            return Err(MintFctError::Config(format!(
                "Unsupported auth.type: '{}'. Valid types: raw_cookie, basic_api_token",
                other
            )));
        }
    }

    Ok(headers)
}

// ============================================================================
// build_variables()
// ============================================================================
// Builds the final GraphQL variables by rendering the template from the config
// (or a minimal default) against the manifest + config context.
//
// Equivalent to `build_variables()` in the Python spike.
pub fn build_variables(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
) -> Result<JsonValue> {
    // Build the template context matching the Python spike exactly:
    //
    //   context = {
    //       "manifest": manifest_context,   ← ManifestContext fields
    //       "config":   config,             ← the WHOLE config dict
    //   }
    //
    // This means ${config.confluence.cloud_id} resolves as:
    //   context["config"]["confluence"]["cloud_id"]
    //
    // because the whole MintFctConfig is at "config", which has a "confluence"
    // key inside it — exactly matching the YAML config file structure.
    //
    // We serialise MintFctConfig to a JsonValue so it can be walked by
    // render_template(). The `#[derive(Serialize)]` on MintFctConfig and
    // ConfluenceConfig makes this possible.
    let config_value = serde_json::to_value(config)
        .unwrap_or(JsonValue::Object(Default::default()));

    let context = serde_json::json!({
        "manifest": {
            "app_id":      manifest_ctx.app_id,
            "app_id_bare": manifest_ctx.app_id_bare,
            "app_name":    manifest_ctx.app_name,
            "module_key":  manifest_ctx.module_key,
            "module_type": manifest_ctx.module_type,
        },
        "config": config_value,
    });

    // Use the variables from the config file, or fall back to the minimal default.
    let template: JsonValue = if let Some(vars) = &config.variables {
        vars.clone()
    } else {
        // Minimal default — same as the Python spike's fallback.
        serde_json::json!({
            "cloudId": "${config.cloud_id}",
            "input": {
                "contextIds": ["ari:cloud:confluence::site/${config.cloud_id}"],
                "extensionSpecificContexts": {
                    "appVersion": "1.0.0",
                    "extensionId": "ari:cloud:ecosystem::extension/${manifest.app_id_bare}/${config.environment_id}/static/${manifest.module_key}",
                    "extensionType": "xen:macro",
                    "installationId": "${config.installation_id}",
                    "context": {
                        "type": "${manifest.module_type}",
                        "environmentId": "${config.environment_id}",
                        "extension": { "type": "${manifest.module_type}" }
                    }
                }
            }
        })
    };

    // Render all ${...} placeholders in the template.
    let rendered = render_template(&template, &context);

    // Make sure the result is still an object (not a string or array).
    if !rendered.is_object() {
        return Err(MintFctError::Config(
            "Rendered GraphQL variables must be a JSON object".into(),
        ));
    }

    Ok(rendered)
}

// ============================================================================
// post_graphql()
// ============================================================================
// Sends the GraphQL mutation to the Atlassian gateway and returns
// (http_status_code, response_body_text).
//
// Equivalent to `post_graphql()` in the Python spike.
// This is the ONLY function in this module that uses `ureq`.
pub fn post_graphql(
    endpoint: &str,
    auth_headers: &HashMap<String, String>,
    query: &str,
    variables: &JsonValue,
) -> Result<(u16, String)> {
    // Extract the origin (scheme + host) from the endpoint URL for CSRF headers.
    // "https://lhe2.atlassian.net/gateway/api/graphql" → "https://lhe2.atlassian.net"
    let origin = endpoint
        .split('/')
        .take(3) // ["https:", "", "lhe2.atlassian.net"]
        .collect::<Vec<_>>()
        .join("/");

    // Append the operation name as a query param — the gateway uses this for routing.
    let url = format!("{}?q={}", endpoint, OPERATION_NAME);

    // Build the request body as a JSON object.
    let body = serde_json::json!({
        "operationName": OPERATION_NAME,
        "query": query,
        "variables": variables,
    });

    // Start building the ureq request.
    // `ureq::post(&url)` creates a POST request builder.
    // Each `.set(name, value)` adds an HTTP header.
    let mut request = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .set("Origin", &origin)
        .set("Referer", &format!("{}/", origin))
        .set("X-Experimentalapi", "confluence-agg-beta")
        .set("X-Apollo-Operation-Name", OPERATION_NAME)
        .set(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        );

    // Add the auth headers (Cookie or Authorization) from build_auth_headers().
    for (name, value) in auth_headers {
        request = request.set(name, value);
    }

    // `.send_json()` serialises the body to JSON and sends the POST request.
    // ureq returns `Err` for HTTP errors (4xx, 5xx) — we handle both cases.
    match request.send_json(&body) {
        Ok(response) => {
            let status = response.status();
            // `.into_string()` reads the full response body as a UTF-8 string.
            let text = response
                .into_string()
                .map_err(|e| MintFctError::Http(e.to_string()))?;
            Ok((status, text))
        }
        Err(ureq::Error::Status(code, response)) => {
            // HTTP error response (4xx/5xx) — still read the body for error details.
            let text = response
                .into_string()
                .unwrap_or_else(|_| "<unreadable response body>".to_string());
            Ok((code, text))
        }
        Err(e) => {
            // Network-level error (DNS failure, timeout, TLS error, etc.)
            Err(MintFctError::Http(e.to_string()))
        }
    }
}

// ============================================================================
// run_mint_fct()
// ============================================================================
// Top-level entry point for the `fsrt mint-fct` subcommand.
// Equivalent to `main()` in the Python spike.
// Called from `main.rs` after clap parses the CLI arguments.
pub fn run_mint_fct(args: &MintFctArgs) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // --- 1. Load and parse the YAML config file ---
    let config_text = fs::read_to_string(&args.config)?;
    let config: MintFctConfig = serde_yaml::from_str(&config_text)?;

    // Validate: only "confluence" is supported right now.
    if config.product != "confluence" {
        return Err(MintFctError::Config(
            "This subcommand is Confluence-only. Set `product: confluence` in your config.".into(),
        )
        .into());
    }

    // --- 2. Load and parse manifest.yml from the app directory ---
    let mut manifest_path = args.app_dir.join("manifest.yaml");
    if !manifest_path.exists() {
        manifest_path = args.app_dir.join("manifest.yml");
    }
    if !manifest_path.exists() {
        return Err(MintFctError::Config(format!(
            "Could not find manifest.yml or manifest.yaml in {}",
            args.app_dir.display()
        ))
        .into());
    }

    let manifest_text = fs::read_to_string(&manifest_path)?;

    // Parse the manifest twice from the same text string:
    //
    // 1. As ForgeManifest — gives us typed access to public fields (app.id, app.name).
    //    Uses forge_loader's struct which has lifetime parameters borrowing from manifest_text.
    let manifest: ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    // 2. As a raw serde_json::Value — lets us walk the `modules` tree freely,
    //    since those fields are private in ForgeManifest and can't be accessed directly.
    //    serde_yaml can deserialise YAML into a serde_json::Value because both
    //    formats share the same data model (objects, arrays, strings, numbers).
    let raw_manifest: JsonValue = serde_yaml::from_str(&manifest_text)?;

    // --- 3. Extract manifest context ---
    // The optional module_key from the config overrides auto-detection.
    let config_module_key = config
        .confluence
        .as_ref()
        .and_then(|c| c.module_key.as_deref());

    let manifest_ctx = extract_manifest_context(&manifest, &raw_manifest, config_module_key);

    // --- 4. Build GraphQL variables (render the template) ---
    let variables = build_variables(&config, &manifest_ctx)?;

    // --- 5. Determine which mutation to use ---
    let query = config
        .mutation
        .as_deref()
        .unwrap_or(DEFAULT_CONFLUENCE_MUTATION);

    // --- 6. Build auth headers ---
    let auth_headers = build_auth_headers(&config.auth)?;

    // --- Print diagnostic info (same as Python spike's stdout output) ---
    println!("\n=== Derived manifest context ===");
    println!("Manifest path: {}", manifest_path.display());
    println!("  app_id:      {}", manifest_ctx.app_id);
    println!("  app_id_bare: {}", manifest_ctx.app_id_bare);
    println!("  app_name:    {:?}", manifest_ctx.app_name);
    println!("  module_key:  {:?}", manifest_ctx.module_key);
    println!("  module_type: {:?}", manifest_ctx.module_type);

    println!("\n=== GraphQL endpoint ===");
    println!("{}", config.graphql_endpoint);

    println!("\n=== GraphQL mutation ===");
    println!("{}", query);

    println!("\n=== GraphQL variables ===");
    println!("{}", serde_json::to_string_pretty(&variables)?);

    // --- 7. Dry-run exit ---
    if args.dry_run {
        println!("\nDry run requested — not sending GraphQL request.");
        return Ok(());
    }

    // --- 8. Send the GraphQL request ---
    let (status, response_text) = post_graphql(
        &config.graphql_endpoint,
        &auth_headers,
        query,
        &variables,
    )?;

    println!("\n=== GraphQL response ===");
    println!("HTTP status: {}", status);

    // Try to pretty-print the response as JSON.
    match serde_json::from_str::<JsonValue>(&response_text) {
        Ok(parsed) => {
            println!("{}", serde_json::to_string_pretty(&parsed)?);

            // Surface the FCT JWT if present — the happy path.
            let fct = parsed
                .get("data")
                .and_then(|d| d.get("confluence_generateForgeContextToken"));

            if let Some(fct_obj) = fct {
                let success = fct_obj.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                let token_obj = fct_obj.get("forgeContextToken");
                let errors = fct_obj.get("errors").and_then(|v| v.as_array());

                if success {
                    if let Some(token) = token_obj {
                        println!("\n=== SUCCESS: Forge Context Token ===");
                        println!("jwt:         {}", token.get("jwt").and_then(|v| v.as_str()).unwrap_or("<missing>"));
                        println!("expiresAt:   {:?}", token.get("expiresAt"));
                        println!("extensionId: {:?}", token.get("extensionId"));
                    }
                } else if let Some(errs) = errors {
                    println!("\n[!] Server returned errors:");
                    for err in errs {
                        println!("    - {}", err.get("message").and_then(|v| v.as_str()).unwrap_or("(no message)"));
                    }
                } else {
                    println!("\n[!] forgeContextToken is null — server accepted the request but returned no token.");
                }
            }
        }
        Err(_) => {
            // Response wasn't valid JSON — print as raw text.
            println!("{}", response_text);
        }
    }

    if (200..300).contains(&(status as u32)) {
        Ok(())
    } else {
        Err(MintFctError::Http(format!("Server returned HTTP {}", status)).into())
    }
}
