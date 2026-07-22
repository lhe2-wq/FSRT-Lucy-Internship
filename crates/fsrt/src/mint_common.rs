//! Shared types and functions used by both `mint_fct` and `mint_fit`.
//!
//! This module contains:
//!   - Config structs (deserialised from the YAML config files in `scripts/`)
//!   - Auth header construction
//!   - GraphQL HTTP POST via `ureq`
//!   - Template rendering
//!   - The core `mint_fct_jwt()` function, which both subcommands call

// ============================================================================
// Imports
// ============================================================================

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use forge_loader::manifest::ForgeManifest;

// ============================================================================
// Constants
// ============================================================================

// The default FCT mutation for Confluence apps.
pub const DEFAULT_CONFLUENCE_MUTATION: &str = r#"mutation useGetContextTokenMutation($cloudId: ID!, $input: ConfluenceForgeContextTokenRequestInput!) {
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

pub const CONFLUENCE_OPERATION_NAME: &str = "useGetContextTokenMutation";

// The default FCT mutation for global apps (Jira, Compass, Rovo, etc.).
// Calls globalApp_signForgeContextTokens on XIS (Xen Invocation Service).
// NOTE: Response returns a list of tokens (one per extensionContext entry).
pub const DEFAULT_GLOBAL_APP_MUTATION: &str = r#"mutation SignForgeContextToken($input: GlobalAppSignForgeContextTokensInput!) {
  globalApp_signForgeContextTokens(input: $input) {
    success
    errors {
      message
      __typename
    }
    tokens {
      jwt
      expiresAt
      extensionId
      __typename
    }
    __typename
  }
}"#;

pub const GLOBAL_APP_OPERATION_NAME: &str = "SignForgeContextToken";

// ============================================================================
// Error type
// ============================================================================

// `MintError` is the shared error type for both mint_fct and mint_fit.
// `thiserror::Error` auto-generates the Display and Error trait impls from
// the `#[error("...")]` attributes — no boilerplate needed.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
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

    // Returned when the FCT mint succeeds at the HTTP level but the server
    // reports a logical failure (e.g. bad cloud_id, bad installation_id).
    #[error("FCT minting failed: {0}")]
    FctFailed(String),
}

// Convenience alias — write `Result<T>` instead of `Result<T, MintError>`.
pub type Result<T> = std::result::Result<T, MintError>;

// ============================================================================
// Config structs
// ============================================================================
// These deserialise from the YAML config files in `scripts/`.
// Both `mint_fct` and `mint_fit` use the same YAML format.

// Which Atlassian product the FCT/FIT is being minted for.
// Controls which GraphQL mutation is used:
//   Confluence → confluence_generateForgeContextToken
//   GlobalApp  → globalApp_signForgeContextTokens
//
// Set via `product:` in the YAML config file:
//   product: confluence
//   product: global
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Product {
    Confluence,
    Global,
}

impl std::fmt::Display for Product {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Product::Confluence => write!(f, "confluence"),
            Product::Global => write!(f, "global"),
        }
    }
}

// `#[derive(Debug, Deserialize, Serialize)]`:
//   Debug       → printable for logging (`println!("{:?}", ...)`)
//   Deserialize → can be built from YAML text (`serde_yaml::from_str`)
//   Serialize   → can be turned into JSON (`serde_json::to_value`)
//                 needed because we embed the whole config as the template context
#[derive(Debug, Deserialize, Serialize)]
pub struct MintFctConfig {
    // Which Atlassian product to mint the token for.
    // Required — must be "confluence" or "global" in the YAML config.
    pub product: Product,

    // The Atlassian GraphQL gateway URL.
    // e.g. "https://lhe2.atlassian.net/gateway/api/graphql"
    pub graphql_endpoint: String,

    // Optional: override the default FCT GraphQL mutation.
    pub mutation: Option<String>,

    // Auth credentials — how to authenticate the HTTP request.
    pub auth: AuthConfig,

    // Confluence-specific IDs (cloud_id, installation_id, environment_id, etc.)
    // Required when product: confluence.
    pub confluence: Option<ConfluenceConfig>,

    // Global app IDs (installation_id, environment_id, etc.)
    // Required when product: global.
    pub global: Option<GlobalAppConfig>,

    // The GraphQL variables template — an arbitrary JSON/YAML object containing
    // `${...}` placeholders that get substituted at runtime.
    pub variables: Option<JsonValue>,
}

// The `auth:` section of the config.
// Supports two types matching the YAML config files in `scripts/`:
//   "raw_cookie"      — full Cookie header pasted from Burp/DevTools
//   "basic_api_token" — Atlassian API token (email + token file)
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthConfig {
    // YAML key is `type` — a reserved word in Rust, so we rename it.
    #[serde(rename = "type", default = "default_auth_type")]
    pub auth_type: String,

    // --- raw_cookie ---
    // The full Cookie header value, either inline or from a file.
    pub raw_cookie: Option<String>,
    pub raw_cookie_file: Option<String>,

    // --- basic_api_token ---
    // Email is not a secret — it's inline in the config.
    // API token is a secret — read from inline value or a file.
    pub email: Option<String>,
    pub api_token: Option<String>,
    pub api_token_file: Option<String>,
}

fn default_auth_type() -> String {
    "raw_cookie".to_string()
}

// The `confluence:` section of the config.
// `#[derive(Clone)]` — needed because we clone it when building the template context.
// `Serialize` — needed so `serde_json::to_value(config)` includes this struct.
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

// The `global:` section of the config — used when product: global.
// Mirrors the fields needed to build a GlobalAppSignForgeContextTokensInput.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GlobalAppConfig {
    pub cloud_id: Option<String>,
    pub installation_id: Option<String>,
    pub environment_id: Option<String>,
    pub environment_type: Option<String>,
    pub module_key: Option<String>,
}

// ============================================================================
// Manifest context
// ============================================================================
// What we extract from the Forge app's manifest.yml.
// Used to fill `${manifest.app_id_bare}`, `${manifest.module_key}`, etc.

#[derive(Debug, Clone)]
pub struct ManifestContext {
    // Full ARI: "ari:cloud:ecosystem::app/8bdd65d0-..."
    pub app_id: String,
    // Bare UUID after the last "/": "8bdd65d0-..."
    pub app_id_bare: String,
    pub app_name: Option<String>,
    pub module_key: Option<String>,
    pub module_type: Option<String>,
}

// ============================================================================
// extract_manifest_context()
// ============================================================================
// Reads a parsed ForgeManifest and returns a ManifestContext.
//
// Module/remote detection lives in forge_loader (see ForgeModules methods), so
// this works entirely off the typed manifest — the manifest is read from disk
// once and parsed once by the caller.
pub fn extract_manifest_context(
    manifest: &ForgeManifest<'_>,
    module_key: Option<&str>,
) -> ManifestContext {
    let app_id = manifest.app.id.to_string();

    // Strip the ARI prefix to get the bare UUID.
    // "ari:cloud:ecosystem::app/8bdd65d0-..." → "8bdd65d0-..."
    let app_id_bare = app_id
        .rsplit('/')
        .next()
        .unwrap_or(&app_id)
        .to_string();

    let app_name = manifest.app.name.map(|s| s.to_string());

    // Prefer a caller-supplied module key (inferring its type from the
    // manifest), otherwise auto-detect a supported module.
    let (detected_key, detected_type) = match module_key {
        Some(key) => (
            Some(key.to_string()),
            manifest
                .modules
                .fct_module_type_for_key(key)
                .map(|t| t.to_string()),
        ),
        None => match manifest.modules.detect_fct_module() {
            Some((key, module_type)) => (Some(key.to_string()), Some(module_type.to_string())),
            None => (None, None),
        },
    };

    ManifestContext {
        app_id,
        app_id_bare,
        app_name,
        module_key: detected_key,
        module_type: detected_type,
    }
}

// ============================================================================
// detect_remote_key()
// ============================================================================
// Walks the raw YAML manifest to find the `key` of the first declared remote.
//
// A remote in manifest.yml looks like:
//   remotes:
//     - key: my-remote-backend
//       baseUrl: https://my-backend.com
//       auth:
//         appUser: {}
//
// Returns None if no remotes are declared — the caller (run_mint_fit) will
// return a clear error in that case.
//
// An optional `override_key` (from the config) takes priority over
// auto-detection — needed for apps with multiple remotes.
pub fn detect_remote_key(
    manifest: &ForgeManifest<'_>,
    override_key: Option<&str>,
) -> Option<String> {
    // Config override takes priority over auto-detection.
    if let Some(key) = override_key {
        if !key.is_empty() {
            return Some(key.to_string());
        }
    }

    // Otherwise take the key of the first declared remote from the typed
    // manifest. Returns None if no remotes are declared or the first one has
    // no key.
    manifest
        .remotes
        .as_ref()?
        .first()
        .map(|remote| remote.key.clone())
        .filter(|key| !key.is_empty())
}

// ============================================================================
// load_secret_from_config()
// ============================================================================
// Reads a secret from one of two sources (in priority order):
//   1. Inline value in the config (e.g. `raw_cookie: "eyJ..."`)
//   2. A file path              (e.g. `raw_cookie_file: "./session-cookie.txt"`)
pub fn load_secret_from_config(
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
            let contents = fs::read_to_string(path).map_err(|e| {
                MintError::Config(format!("Could not read secret file '{}': {}", path, e))
            })?;
            return Ok(Some(contents.trim().to_string()));
        }
    }

    Ok(None)
}

// ============================================================================
// build_auth_headers()
// ============================================================================
// Reads the `auth:` section of the config and returns the HTTP headers needed
// to authenticate the request. Returns a HashMap<header_name, header_value>.
pub fn build_auth_headers(auth: &AuthConfig) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();

    println!("\n=== Auth material ===");
    println!("WARNING: Do not paste this output into public tickets, logs, or chat.");

    match auth.auth_type.as_str() {
        // ------------------------------------------------------------------
        // raw_cookie: the full Cookie header pasted from Burp/DevTools.
        // e.g. "tenant.session.token=eyJ...; atlassian.xsrf.token=5748..."
        // ------------------------------------------------------------------
        "raw_cookie" => {
            let raw = load_secret_from_config(
                auth.raw_cookie.as_deref(),
                auth.raw_cookie_file.as_deref(),
            )?
            .ok_or_else(|| MintError::Config(
                "auth.type=raw_cookie requires `raw_cookie` (inline) or `raw_cookie_file`".into(),
            ))?;

            // Only print the first 80 chars — never log a full session token.
            println!("Cookie (first 80 chars): {}...", &raw[..raw.len().min(80)]);
            headers.insert("Cookie".to_string(), raw.trim().to_string());
        }

        // ------------------------------------------------------------------
        // basic_api_token: Atlassian API token encoded as HTTP Basic auth.
        // The gateway accepts base64("email:api_token") in the Authorization header.
        // ------------------------------------------------------------------
        "basic_api_token" => {
            let email = auth
                .email
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    MintError::Config(
                        "auth.type=basic_api_token requires `email` in the config".into(),
                    )
                })?;

            let token = load_secret_from_config(
                auth.api_token.as_deref(),
                auth.api_token_file.as_deref(),
            )?
            .ok_or_else(|| MintError::Config(
                "auth.type=basic_api_token requires `api_token` (inline) or `api_token_file`".into(),
            ))?;

            // HTTP Basic auth: base64-encode "email:token"
            let credentials = format!("{}:{}", email.trim(), token.trim());
            let encoded = B64.encode(credentials.as_bytes());

            println!("Basic auth email: {}", email.trim());
            println!(
                "Authorization: Basic {}... (truncated)",
                &encoded[..encoded.len().min(20)]
            );
            headers.insert(
                "Authorization".to_string(),
                format!("Basic {}", encoded),
            );
        }

        other => {
            return Err(MintError::Config(format!(
                "Unsupported auth.type: '{}'. Valid types: raw_cookie, basic_api_token",
                other
            )));
        }
    }

    Ok(headers)
}

// ============================================================================
// render_template() and helpers
// ============================================================================
// Walks a JSON value tree and replaces every "${dotted.path}" placeholder
// with the value found at that path in the template context.

pub fn render_template(value: &JsonValue, context: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Object(map) => {
            let rendered = map
                .iter()
                .map(|(k, v)| (k.clone(), render_template(v, context)))
                .collect();
            JsonValue::Object(rendered)
        }
        JsonValue::Array(arr) => {
            JsonValue::Array(arr.iter().map(|v| render_template(v, context)).collect())
        }
        JsonValue::String(s) => render_string(s, context),
        other => other.clone(),
    }
}

fn render_string(s: &str, context: &JsonValue) -> JsonValue {
    let re = Regex::new(r"\$\{([^}]+)\}").unwrap();

    // If the entire string is a single placeholder, return the resolved value
    // preserving its original type (number, boolean, etc.)
    if let Some(caps) = re.captures(s) {
        if caps[0] == *s {
            let path = &caps[1];
            return get_path(context, path).cloned().unwrap_or(JsonValue::Null);
        }
    }

    // Otherwise replace each placeholder with its string representation.
    let result = re.replace_all(s, |caps: &regex::Captures<'_>| {
        let path = &caps[1];
        match get_path(context, path) {
            Some(JsonValue::String(v)) => v.clone(),
            Some(JsonValue::Null) | None => String::new(),
            Some(v) => v.to_string(),
        }
    });

    JsonValue::String(result.into_owned())
}

// Walks a JsonValue by a dotted path string.
// "config.confluence.cloud_id" → context["config"]["confluence"]["cloud_id"]
pub fn get_path<'a>(context: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let mut cur = context;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

// ============================================================================
// post_graphql()
// ============================================================================
// Sends a GraphQL POST request to the Atlassian gateway and returns
// (http_status_code, response_body_text).
// This is the ONLY place in the codebase that uses `ureq`.
pub fn post_graphql(
    endpoint: &str,
    operation_name: &str,
    auth_headers: &HashMap<String, String>,
    query: &str,
    variables: &JsonValue,
) -> Result<(u16, String)> {
    // Extract origin from the endpoint URL for CSRF headers.
    // "https://lhe2.atlassian.net/gateway/api/graphql" → "https://lhe2.atlassian.net"
    let origin = endpoint
        .split('/')
        .take(3)
        .collect::<Vec<_>>()
        .join("/");

    // Append operation name as a query param — gateway uses this for routing.
    let url = format!("{}?q={}", endpoint, operation_name);

    let body = serde_json::json!({
        "operationName": operation_name,
        "query": query,
        "variables": variables,
    });

    // Build the ureq POST request.
    // `.set(name, value)` adds an HTTP header.
    // `ureq::post(&url)` returns a request builder.
    let mut request = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .set("Origin", &origin)
        .set("Referer", &format!("{}/", origin))
        .set("X-Experimentalapi", "confluence-agg-beta")
        .set("X-Apollo-Operation-Name", operation_name)
        .set(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        );

    // Add auth headers (Cookie or Authorization).
    for (name, value) in auth_headers {
        request = request.set(name, value);
    }

    // `.send_json()` serialises the body and sends the request.
    match request.send_json(&body) {
        Ok(response) => {
            let status = response.status();
            let text = response
                .into_string()
                .map_err(|e| MintError::Http(e.to_string()))?;
            Ok((status, text))
        }
        Err(ureq::Error::Status(code, response)) => {
            // HTTP 4xx/5xx — still read the body for error details.
            let text = response
                .into_string()
                .unwrap_or_else(|_| "<unreadable response body>".to_string());
            Ok((code, text))
        }
        Err(e) => Err(MintError::Http(e.to_string())),
    }
}

// ============================================================================
// load_manifest()
// ============================================================================
// Shared manifest loading logic — reads the manifest.yml (or .yaml) from an app
// directory exactly once and returns its raw text.
//
// The returned String must be kept alive by the caller because the typed
// `ForgeManifest` borrows from it. Callers parse it once via
// `serde_yaml::from_str` — module/remote details are then read through the
// typed accessors on `ForgeManifest`/`ForgeModules`, so the manifest is never
// parsed a second time.
pub fn load_manifest(app_dir: &PathBuf) -> Result<String> {
    let mut manifest_path = app_dir.join("manifest.yaml");
    if !manifest_path.exists() {
        manifest_path = app_dir.join("manifest.yml");
    }
    if !manifest_path.exists() {
        return Err(MintError::Config(format!(
            "Could not find manifest.yml or manifest.yaml in {}",
            app_dir.display()
        )));
    }

    Ok(fs::read_to_string(&manifest_path)?)
}

// ============================================================================
// build_variables()
// ============================================================================
// Builds the final FCT GraphQL variables by rendering the template from the
// config against the manifest + config context.
// Branches on config.product to build the correct variable shape for each API.
pub fn build_variables(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
) -> Result<JsonValue> {
    // Build the template context:
    //   { "manifest": {...}, "config": <whole MintFctConfig as JSON> }
    //
    // This means ${config.confluence.cloud_id} and ${config.global.cloud_id}
    // resolve correctly because MintFctConfig has both "confluence" and "global"
    // fields that serde serialises by name.
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

    // Use the variables template from the config if supplied — works for both
    // products. Otherwise fall back to a product-specific minimal default.
    let template: JsonValue = if let Some(vars) = &config.variables {
        vars.clone()
    } else {
        match config.product {
            Product::Confluence => serde_json::json!({
                "cloudId": "${config.confluence.cloud_id}",
                "input": {
                    "contextIds": ["ari:cloud:confluence::site/${config.confluence.cloud_id}"],
                    "extensionSpecificContexts": {
                        "appVersion": "1.0.0",
                        "extensionId": "ari:cloud:ecosystem::extension/${manifest.app_id_bare}/${config.confluence.environment_id}/static/${manifest.module_key}",
                        "extensionType": "xen:macro",
                        "installationId": "${config.confluence.installation_id}",
                        "context": {
                            "type": "${manifest.module_type}",
                            "environmentId": "${config.confluence.environment_id}",
                            "extension": { "type": "${manifest.module_type}" }
                        }
                    }
                }
            }),
            Product::Global => serde_json::json!({
                "input": {
                    "contextIds": ["ari:cloud:ecosystem::site/${config.global.cloud_id}"],
                    "extensionContexts": [{
                        "appVersion": "1.0.0",
                        "extensionId": "ari:cloud:ecosystem::extension/${manifest.app_id_bare}/${config.global.environment_id}/static/${manifest.module_key}",
                        "extensionType": "xen:globalPage",
                        "installationId": "${config.global.installation_id}",
                        "context": {}
                    }]
                }
            }),
        }
    };

    let rendered = render_template(&template, &context);

    if !rendered.is_object() {
        return Err(MintError::Config(
            "Rendered GraphQL variables must be a JSON object".into(),
        ));
    }

    Ok(rendered)
}

// ============================================================================
// mint_fct_jwt()
// ============================================================================
// The core FCT minting function — called by both `mint_fct::run_mint_fct()`
// and `mint_fit::run_mint_fit()`.
//
// Takes a fully-prepared config, manifest context, and auth headers, and
// returns the FCT JWT string on success.
//
// This separation is why mint_common.rs exists — both subcommands need to
// mint an FCT, but only mint_fct prints the result as the final output.
// mint_fit uses the JWT as an input to the FIT minting step.
pub fn mint_fct_jwt(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
    auth_headers: &HashMap<String, String>,
) -> Result<String> {
    // Select mutation and operation name based on product.
    let (default_mutation, operation_name, response_key) = match config.product {
        Product::Confluence => (
            DEFAULT_CONFLUENCE_MUTATION,
            CONFLUENCE_OPERATION_NAME,
            "confluence_generateForgeContextToken",
        ),
        Product::Global => (
            DEFAULT_GLOBAL_APP_MUTATION,
            GLOBAL_APP_OPERATION_NAME,
            "globalApp_signForgeContextTokens",
        ),
    };

    let query = config.mutation.as_deref().unwrap_or(default_mutation);

    let variables = build_variables(config, manifest_ctx)?;

    println!("\n=== FCT GraphQL variables ===");
    println!(
        "{}",
        serde_json::to_string_pretty(&variables)
            .unwrap_or_else(|_| "<serialisation error>".to_string())
    );

    let (status, body) = post_graphql(
        &config.graphql_endpoint,
        operation_name,
        auth_headers,
        query,
        &variables,
    )?;

    println!("\n=== FCT GraphQL response ===");
    println!("HTTP status: {}", status);

    // Parse and pretty-print the response.
    let parsed: JsonValue = serde_json::from_str(&body).map_err(|e| {
        println!("{}", body); // print raw body if not valid JSON
        MintError::Json(e)
    })?;
    println!("{}", serde_json::to_string_pretty(&parsed)?);

    // Navigate to the FCT JWT in the response tree using the product-specific key.
    // Confluence: data.confluence_generateForgeContextToken.forgeContextToken.jwt
    // Global:     data.globalApp_signForgeContextTokens.tokens[0].jwt
    let fct_obj = parsed
        .get("data")
        .and_then(|d| d.get(response_key));

    let success = fct_obj
        .and_then(|o| o.get("success"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !success {
        // Collect server-side error messages for a useful error.
        let errors: Vec<&str> = fct_obj
            .and_then(|o| o.get("errors"))
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect()
            })
            .unwrap_or_default();

        return Err(MintError::FctFailed(if errors.is_empty() {
            "Server returned success=false with no error messages".to_string()
        } else {
            errors.join("; ")
        }));
    }

    // Extract the JWT string — path differs by product:
    //   Confluence: .forgeContextToken.jwt  (single object)
    //   Global:     .tokens[0].jwt           (list, take first)
    let jwt = match config.product {
        Product::Confluence => fct_obj
            .and_then(|o| o.get("forgeContextToken"))
            .and_then(|t| t.get("jwt"))
            .and_then(|j| j.as_str())
            .ok_or_else(|| {
                MintError::FctFailed("forgeContextToken.jwt missing from response".to_string())
            })?,
        Product::Global => fct_obj
            .and_then(|o| o.get("tokens"))
            .and_then(|t| t.as_array())
            .and_then(|arr| arr.first())
            .and_then(|t| t.get("jwt"))
            .and_then(|j| j.as_str())
            .ok_or_else(|| {
                MintError::FctFailed("tokens[0].jwt missing from response".to_string())
            })?,
    };

    Ok(jwt.to_string())
}
