//! Shared minting foundation used across the pen-testing capabilities.
//!   - Config structs (deserialised from the `fsrt-remote.toml` config file)
//!   - Auth header construction
//!   - GraphQL HTTP POST via `ureq`
//!   - Template rendering
//!   - Environment resolution and the core `mint_fct_jwt()` entry point

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use forge_loader::manifest::ForgeManifest;
use tracing::{info, warn};

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

// Error types
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

    #[error("config error: {0}")]
    ConfigCrate(#[from] config::ConfigError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // Returned when the FCT mint succeeds at the HTTP level but the server
    // reports a logical failure.
    #[error("FCT minting failed: {0}")]
    FctFailed(String),

    #[error("{0}")]
    CookieExpired(String),
}

pub type Result<T> = std::result::Result<T, MintError>;

// Config structs, deserialised from the `fsrt-remote.toml` config file.
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

#[derive(Debug, Deserialize, Serialize)]
pub struct MintFctConfig {
    // Required: which Atlassian product to mint the token for.
    pub product: Product,

    // Atlassian site subdomain where GraphQL gateway URL is derived.
    pub site_id: String,

    // Optional: override the default FCT GraphQL mutation.
    pub mutation: Option<String>,

    // Auth credentials — how to authenticate the HTTP request.
    pub auth: AuthConfig,

    // App/site IDs (top-level; formerly the `[global]` section).
    pub cloud_id: Option<String>,
    pub installation_id: Option<String>,
    pub environment_id: Option<String>,
    pub environment_type: Option<String>,
    pub module_key: Option<String>,
    // Forge environment slot used to look up
    pub environment_key: Option<String>,

    // The GraphQL variables template.
    pub variables: Option<JsonValue>,
}

impl MintFctConfig {
    // Derives the Atlassian GraphQL gateway URL from `site_id`.
    pub fn graphql_endpoint(&self) -> String {
        format!(
            "https://{}.atlassian.net/gateway/api/graphql",
            self.site_id
        )
    }
}

// `auth` section of the config, either session cookie or API token
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthConfig {
    // Config key is `type`, renamed
    #[serde(rename = "type", default = "default_auth_type")]
    pub auth_type: String,

    // The full Cookie header value, either inline or from a file.
    pub raw_cookie: Option<String>,
    pub raw_cookie_file: Option<String>,

    pub email: Option<String>,
    // API token is a secret — read from inline value or a file.
    pub api_token: Option<String>,
    pub api_token_file: Option<String>,
}

fn default_auth_type() -> String {
    "raw_cookie".to_string()
}

// The Atlassian product an FCT is being minted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FctProduct {
    Confluence,
    Jira,
    JiraServiceManagement,
}

impl FctProduct {
    // Maps a manifest product-namespace prefix or `None` if unrecognised.
    fn from_manifest_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "confluence" => Some(FctProduct::Confluence),
            "jira" => Some(FctProduct::Jira),
            "jiraServiceManagement" => Some(FctProduct::JiraServiceManagement),
            _ => None,
        }
    }

    // The site context ARI resource-owner segment.
    //
    // NOTE: Update for other products like Bitbucket:
    // it uses a *workspace* ARI (`ari:cloud:bitbucket::workspace/<workspaceId>`).
    fn ari_owner(self) -> &'static str {
        match self {
            FctProduct::Confluence => "confluence",
            FctProduct::Jira => "jira",
            FctProduct::JiraServiceManagement => "jira-servicedesk",
        }
    }

    // Builds the site-scoped context ARI carried in the global-app FCT request's
    // `contextIds`.
    fn context_ari(self, cloud_id: &str) -> String {
        format!("ari:cloud:{}::site/{cloud_id}", self.ari_owner())
    }
}

// Manifest context
#[derive(Debug, Clone)]
pub struct ManifestContext {
    // Full ARI: "ari:cloud:ecosystem::app/8bdd65d0-..."
    pub app_id: String,
    // Bare UUID after the last "/": "8bdd65d0-..."
    pub app_id_bare: String,
    pub app_name: Option<String>,
    pub module_key: Option<String>,
    pub module_type: Option<String>,
    // Product that declared the module, resolved from the manifest key prefix.
    pub product: FctProduct,
    // Resolved from the Forge platform via fetch_app_environment().
    pub environment_id: Option<String>,
    pub app_version: Option<String>,
}

// Reads a parsed ForgeManifest and returns a ManifestContext.
pub fn extract_manifest_context(
    manifest: &ForgeManifest<'_>,
    module_key: &str,
) -> Result<ManifestContext> {
    let app_id = manifest.app.id.to_string();

    let app_id_bare = app_id.rsplit('/').next().unwrap_or(&app_id).to_string();

    let app_name = manifest.app.name.map(|s| s.to_string());

    let (module_type, product_prefix) =
        manifest.modules.fct_module_for_key(module_key).ok_or_else(|| {
            let available = manifest.modules.fct_module_keys();
            let hint = if available.is_empty() {
                "the manifest declares no FCT-capable modules".to_string()
            } else {
                format!(
                    "available module keys:\n{}",
                    available
                        .iter()
                        .map(|k| format!("  - {k}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            };
            MintError::Config(format!(
                "module_key '{module_key}' does not match any FCT-capable module in the manifest\n{hint}"
            ))
        })?;

    let product = FctProduct::from_manifest_prefix(product_prefix).ok_or_else(|| {
        MintError::Config(format!(
            "module '{module_key}' belongs to product namespace '{product_prefix}', \
             which is not supported for FCT minting"
        ))
    })?;

    Ok(ManifestContext {
        app_id,
        app_id_bare,
        app_name,
        module_key: Some(module_key.to_string()),
        module_type: Some(module_type.to_string()),
        product,
        environment_id: None,
        app_version: None,
    })
}

pub fn load_secret_from_config(
    inline: Option<&str>,
    file_path: Option<&str>,
) -> Result<Option<String>> {
    if let Some(v) = inline
        && !v.is_empty()
    {
        return Ok(Some(v.to_string()));
    }

    if let Some(path) = file_path
        && !path.is_empty()
    {
        let contents = fs::read_to_string(path).map_err(|e| {
            MintError::Config(format!("Could not read secret file '{}': {}", path, e))
        })?;
        return Ok(Some(contents.trim().to_string()));
    }

    Ok(None)
}

// Reads the `auth:` section of the config and returns the HTTP headers needed
// to authenticate the request.
pub fn build_auth_headers(auth: &AuthConfig) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();

    info!("building auth headers from config — this uses sensitive credentials");

    match auth.auth_type.as_str() {
        "raw_cookie" => {
            let raw = load_secret_from_config(
                auth.raw_cookie.as_deref(),
                auth.raw_cookie_file.as_deref(),
            )?
            .ok_or_else(|| {
                MintError::Config(
                    "auth.type=raw_cookie requires `raw_cookie` (inline) or `raw_cookie_file`"
                        .into(),
                )
            })?;

            info!(bytes = raw.len(), "loaded session cookie");

            if let Some(secs_ago) = cookie_expired_secs_ago(&raw) {
                return Err(MintError::CookieExpired(format!(
                    "Session cookie EXPIRED {} ago. Renew it (e.g. re-copy the \
                     Cookie header from your browser/Burp into `raw_cookie` or \
                     the file referenced by `raw_cookie_file`), then retry.",
                    format_duration(secs_ago),
                )));
            }
            check_cookie_expiry(&raw);

            headers.insert("Cookie".to_string(), raw.trim().to_string());
        }

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

            let token =
                load_secret_from_config(auth.api_token.as_deref(), auth.api_token_file.as_deref())?
                    .ok_or_else(|| {
                        MintError::Config(
                    "auth.type=basic_api_token requires `api_token` (inline) or `api_token_file`"
                        .into(),
                )
                    })?;

            let credentials = format!("{}:{}", email.trim(), token.trim());
            let encoded = B64.encode(credentials.as_bytes());

            info!(email = %email.trim(), "using basic API token auth");
            headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
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

const SESSION_COOKIE_NAME: &str = "tenant.session.token";

fn extract_session_token(raw_cookie: &str) -> Option<&str> {
    for pair in raw_cookie.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(value);
        }
    }
    let trimmed = raw_cookie.trim();
    if !trimmed.contains('=') && trimmed.split('.').count() == 3 {
        return Some(trimmed);
    }
    None
}

fn decode_jwt_exp(token: &str) -> Option<i64> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload_bytes = B64_URL.decode(payload_b64).ok()?;
    let payload: JsonValue = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("exp")?.as_i64()
}

fn format_duration(seconds: i64) -> String {
    let seconds = seconds.abs();
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

// Definitive expiry check used to hard-fail before sending a stale cookie.
fn cookie_expired_secs_ago(raw_cookie: &str) -> Option<i64> {
    let token = extract_session_token(raw_cookie)?;
    let exp = decode_jwt_exp(token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (exp <= now).then_some(now - exp)
}

pub fn check_cookie_expiry(raw_cookie: &str) -> bool {
    let Some(token) = extract_session_token(raw_cookie) else {
        warn!(
            cookie_name = SESSION_COOKIE_NAME,
            "could not find session cookie — cannot check expiry"
        );
        return false;
    };

    let Some(exp) = decode_jwt_exp(token) else {
        warn!(
            cookie_name = SESSION_COOKIE_NAME,
            "could not read an `exp` claim (not a JWT?) — cannot check expiry"
        );
        return false;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if exp <= now {
        warn!(
            expired_ago = %format_duration(now - exp),
            exp,
            "session cookie EXPIRED — renew it before minting"
        );
        false
    } else {
        info!(
            expires_in = %format_duration(exp - now),
            exp,
            "session cookie valid"
        );
        true
    }
}

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
    // preserving its original type
    if let Some(caps) = re.captures(s)
        && caps[0] == *s
    {
        let path = &caps[1];
        return get_path(context, path).cloned().unwrap_or(JsonValue::Null);
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

pub fn get_path<'a>(context: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let mut cur = context;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

// Sends a GraphQL POST request to the Atlassian gateway and returns
// (http_status_code, response_body_text) using ureq.
pub fn post_graphql(
    endpoint: &str,
    operation_name: &str,
    auth_headers: &HashMap<String, String>,
    query: &str,
    variables: &JsonValue,
) -> Result<(u16, String)> {
    // Extract origin from the endpoint URL for CSRF headers.
    let origin = endpoint.split('/').take(3).collect::<Vec<_>>().join("/");

    let url = format!("{}?q={}", endpoint, operation_name);

    let body = serde_json::json!({
        "operationName": operation_name,
        "query": query,
        "variables": variables,
    });

    // Build the ureq POST request.
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

    for (name, value) in auth_headers {
        request = request.set(name, value);
    }

    match request.send_json(&body) {
        Ok(response) => {
            let status = response.status();
            let text = response
                .into_string()
                .map_err(|e| MintError::Http(e.to_string()))?;
            Ok((status, text))
        }
        Err(ureq::Error::Status(code, response)) => {
            let text = response
                .into_string()
                .unwrap_or_else(|_| "<unreadable response body>".to_string());
            Ok((code, text))
        }
        Err(e) => Err(MintError::Http(e.to_string())),
    }
}

// Loads and deserialises the `fsrt-remote.toml` config file into a
// `MintFctConfig` using the `config` crate (config-rs).
pub fn load_config(config_path: &std::path::Path) -> Result<MintFctConfig> {
    if !config_path.exists() {
        return Err(MintError::Config(format!(
            "Config file not found: {}",
            config_path.display()
        )));
    }

    let settings = config::Config::builder()
        .add_source(config::File::from(config_path))
        .build()?;

    let cfg: MintFctConfig = settings.try_deserialize()?;
    Ok(cfg)
}

// Resolve app's environmentId and versionId.
pub const PRODUCTION_ENVIRONMENT_KEY: &str = "production";
pub const DEFAULT_ENVIRONMENT_KEY: &str = "default";

pub const APP_ENVIRONMENT_QUERY: &str = r#"query GetAppEnvironment($appId: ID!, $envKey: String!) {
  app(id: $appId) {
    id
    name
    environmentByKey(key: $envKey) {
      id
      key
      type
      versions {
        nodes { version isLatest }
      }
    }
  }
}"#;
pub const APP_ENVIRONMENT_OPERATION_NAME: &str = "GetAppEnvironment";

// Result of the environment lookup.
#[derive(Debug, Clone)]
pub struct AppEnvironment {
    pub environment_id: String,
    pub app_version: Option<String>,
}

// Performs the GraphQL query and parses out the environment id + version.
pub fn fetch_app_environment(
    endpoint: &str,
    auth_headers: &HashMap<String, String>,
    app_id: &str,
    env_key: &str,
) -> Result<AppEnvironment> {
    let variables = serde_json::json!({
        "appId": app_id,
        "envKey": env_key,
    });

    let (status, body) = post_graphql(
        endpoint,
        APP_ENVIRONMENT_OPERATION_NAME,
        auth_headers,
        APP_ENVIRONMENT_QUERY,
        &variables,
    )?;

    let parsed: JsonValue = serde_json::from_str(&body).map_err(MintError::Json)?;

    let env = parsed
        .get("data")
        .and_then(|d| d.get("app"))
        .and_then(|a| a.get("environmentByKey"));

    let environment_id = env
        .and_then(|e| e.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            MintError::Config(format!(
                "Could not resolve environment '{}' for app {} (HTTP {}). \
                 Check the environment key, or set environment_id explicitly in the config.\n\
                 Response body: {}",
                env_key, app_id, status, body
            ))
        })?
        .to_string();

    let app_version = env
        .and_then(|e| e.get("versions"))
        .and_then(|v| v.get("nodes"))
        .and_then(|n| n.as_array())
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|node| {
                    node.get("isLatest")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                })
                .or_else(|| nodes.first())
        })
        .and_then(|node| node.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(AppEnvironment {
        environment_id,
        app_version,
    })
}

// High-level, opt-in resolver used by both subcommands.
pub fn resolve_environment(
    config: &MintFctConfig,
    manifest_ctx: &mut ManifestContext,
    auth_headers: &HashMap<String, String>,
) -> Result<()> {
    if let Some(id) = config.environment_id.clone() {
        manifest_ctx.environment_id = Some(id);
        return Ok(());
    }
    let env_key = config.environment_key.clone();

    let endpoint = config.graphql_endpoint();
    let app_env = match env_key {
        Some(key) => {
            fetch_app_environment(&endpoint, auth_headers, &manifest_ctx.app_id, &key)?
        }
        // No key configured: prefer "production", then fall back to "default".
        None => {
            match fetch_app_environment(
                &endpoint,
                auth_headers,
                &manifest_ctx.app_id,
                PRODUCTION_ENVIRONMENT_KEY,
            ) {
                Ok(env) => env,
                Err(prod_err) => {
                    warn!(
                        "environment '{}' not resolved ({}); falling back to '{}'",
                        PRODUCTION_ENVIRONMENT_KEY, prod_err, DEFAULT_ENVIRONMENT_KEY
                    );
                    fetch_app_environment(
                        &endpoint,
                        auth_headers,
                        &manifest_ctx.app_id,
                        DEFAULT_ENVIRONMENT_KEY,
                    )?
                }
            }
        }
    };

    manifest_ctx.environment_id = Some(app_env.environment_id);
    manifest_ctx.app_version = app_env.app_version;

    Ok(())
}

// Reads the manifest.yml (or .yaml) from an app directory.
pub fn load_manifest(app_dir: &Path) -> Result<String> {
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

// Builds the final FCT GraphQL variables.
pub fn build_variables(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
) -> Result<JsonValue> {
    let config_value =
        serde_json::to_value(config).unwrap_or(JsonValue::Object(Default::default()));

    // Resolve the product-correct site context ARI for the global-app shape.
    let cloud_id = config.cloud_id.as_deref().unwrap_or("");
    let context_ari = manifest_ctx.product.context_ari(cloud_id);

    let context = serde_json::json!({
        "manifest": {
            "app_id":         manifest_ctx.app_id,
            "app_id_bare":    manifest_ctx.app_id_bare,
            "app_name":       manifest_ctx.app_name,
            "module_key":     manifest_ctx.module_key,
            "module_type":    manifest_ctx.module_type,
            "environment_id": manifest_ctx.environment_id,
            "app_version":    manifest_ctx.app_version,
        },
        "config": config_value,
        "context_ari": context_ari,
    });

    let template: JsonValue = if let Some(vars) = &config.variables {
        vars.clone()
    } else {
        match config.product {
            Product::Confluence => serde_json::json!({
                "cloudId": "${config.cloud_id}",
                "input": {
                    // Product-resolved at runtime from the manifest.
                    "contextIds": ["${context_ari}"],
                    "extensionSpecificContexts": {
                        "appVersion": "${manifest.app_version}",
                        "extensionId": "ari:cloud:ecosystem::extension/${manifest.app_id_bare}/${manifest.environment_id}/static/${manifest.module_key}",
                        "extensionType": "xen:macro",
                        "installationId": "${config.installation_id}",
                        "context": {
                            "moduleKey": "${manifest.module_key}",
                            "type": "${manifest.module_type}",
                            "environmentId": "${manifest.environment_id}",
                            "extension": { "type": "${manifest.module_type}" }
                        }
                    }
                }
            }),
            Product::Global => serde_json::json!({
                "input": {
                    // Product-resolved at runtime from the manifest.
                    "contextIds": ["${context_ari}"],
                    "unlicensed": false,
                    "extensionContexts": [{
                        "appVersion": "${manifest.app_version}",
                        "extensionId": "ari:cloud:ecosystem::extension/${manifest.app_id_bare}/${manifest.environment_id}/static/${manifest.module_key}",
                        "extensionType": "xen:${manifest.module_type}",
                        "installationId": "${config.installation_id}",
                        "context": {
                            "moduleKey": "${manifest.module_key}",
                            "cloudId": "${config.cloud_id}",
                            "environmentId": "${manifest.environment_id}",
                            "type": "${manifest.module_type}",
                            "extension": { "type": "${manifest.module_type}" }
                        }
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

// Takes a fully-prepared config, manifest context, and auth headers, and
// returns the FCT JWT string on success.
pub fn mint_fct_jwt(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
    auth_headers: &HashMap<String, String>,
) -> Result<String> {
    mint_fct_jwt_opts(config, manifest_ctx, auth_headers, false)
}

// Same as `mint_fct_jwt`, but `quiet` suppresses variables/response diagnostics
pub fn mint_fct_jwt_opts(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
    auth_headers: &HashMap<String, String>,
    quiet: bool,
) -> Result<String> {
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

    if !quiet {
        info!(
            variables = %serde_json::to_string_pretty(&variables)
                .unwrap_or_else(|_| "<serialisation error>".to_string()),
            "FCT GraphQL variables"
        );
    }

    let (status, body) = post_graphql(
        &config.graphql_endpoint(),
        operation_name,
        auth_headers,
        query,
        &variables,
    )?;

    let parsed: JsonValue = serde_json::from_str(&body).map_err(|e| {
        warn!(response_body = %body, "FCT response was not valid JSON");
        MintError::Json(e)
    })?;
    if !quiet {
        info!(
            http_status = status,
            response = %serde_json::to_string_pretty(&parsed).unwrap_or_default(),
            "FCT GraphQL response"
        );
    }

    let fct_obj = parsed.get("data").and_then(|d| d.get(response_key));

    let success = fct_obj
        .and_then(|o| o.get("success"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !success {
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

    // Extract the JWT string — path differs by product
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

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn get_path_walks_nested_objects() {
        let ctx = json!({
            "config": { "confluence": { "cloud_id": "abc-123" } }
        });
        assert_eq!(
            get_path(&ctx, "config.confluence.cloud_id"),
            Some(&json!("abc-123"))
        );
    }

    #[test]
    fn get_path_returns_none_for_missing_key() {
        let ctx = json!({ "config": { "confluence": {} } });
        assert_eq!(get_path(&ctx, "config.confluence.missing"), None);
        assert_eq!(get_path(&ctx, "nope.at.all"), None);
    }

    #[test]
    fn render_whole_string_placeholder_preserves_type() {
        let ctx = json!({ "count": 7 });
        let template = json!("${count}");
        assert_eq!(render_template(&template, &ctx), json!(7));
    }

    #[test]
    fn render_embedded_placeholder_produces_string() {
        let ctx = json!({ "name": "world" });
        let template = json!("hello ${name}!");
        assert_eq!(render_template(&template, &ctx), json!("hello world!"));
    }

    #[test]
    fn render_missing_placeholder_becomes_empty_or_null() {
        let ctx = json!({});
        assert_eq!(render_template(&json!("${gone}"), &ctx), json!(null));
        assert_eq!(render_template(&json!("a${gone}b"), &ctx), json!("ab"));
    }

    #[test]
    fn render_recurses_into_objects_and_arrays() {
        let ctx = json!({ "id": "X1", "n": 2 });
        let template = json!({
            "outer": { "inner": "${id}" },
            "list": ["${n}", "lit"]
        });
        let expected = json!({
            "outer": { "inner": "X1" },
            "list": [2, "lit"]
        });
        assert_eq!(render_template(&template, &ctx), expected);
    }

    #[test]
    fn product_display_matches_config_values() {
        assert_eq!(Product::Confluence.to_string(), "confluence");
        assert_eq!(Product::Global.to_string(), "global");
    }

    #[test]
    fn format_duration_buckets() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(3 * 60), "3m");
        assert_eq!(format_duration(2 * 3600 + 5 * 60), "2h 5m");
        assert_eq!(format_duration(3 * 86_400 + 4 * 3600), "3d 4h");
        assert_eq!(format_duration(-45), "45s");
    }

    #[test]
    fn extract_manifest_context_resolves_module_type_for_key() {
        let json = r#"{
            "app": { "name": "My App", "id": "ari:cloud:ecosystem::app/abc-123" },
            "modules": {
                "macro": [ { "key": "my-macro", "function": "macroFn" } ]
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let ctx = extract_manifest_context(&manifest, "my-macro").unwrap();
        assert_eq!(ctx.app_id_bare, "abc-123");
        assert_eq!(ctx.module_key.as_deref(), Some("my-macro"));
        assert_eq!(ctx.module_type.as_deref(), Some("macro"));
    }

    #[test]
    fn extract_manifest_context_errors_on_unknown_module_key() {
        let json = r#"{
            "app": { "name": "My App", "id": "ari:cloud:ecosystem::app/abc-123" },
            "modules": {
                "macro": [ { "key": "my-macro", "function": "macroFn" } ]
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let err = extract_manifest_context(&manifest, "does-not-exist").unwrap_err();
        assert!(matches!(err, MintError::Config(_)), "got: {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("does-not-exist"));
        // The error suggests the actual module keys present in the manifest.
        assert!(msg.contains("available module keys"), "got: {msg}");
        assert!(msg.contains("my-macro"), "got: {msg}");
    }

    #[test]
    fn context_ari_uses_product_specific_resource_owner() {
        assert_eq!(
            FctProduct::Confluence.context_ari("cid"),
            "ari:cloud:confluence::site/cid"
        );
        assert_eq!(
            FctProduct::Jira.context_ari("cid"),
            "ari:cloud:jira::site/cid"
        );
        // JSM's site resource-owner is `jira-servicedesk` (per gateway
        // validateForgeContextAri / JiraServicedeskSiteAri), NOT `jira`.
        assert_eq!(
            FctProduct::JiraServiceManagement.context_ari("cid"),
            "ari:cloud:jira-servicedesk::site/cid"
        );
    }

    #[test]
    fn fct_product_maps_manifest_prefix() {
        assert_eq!(
            FctProduct::from_manifest_prefix("jiraServiceManagement"),
            Some(FctProduct::JiraServiceManagement)
        );
        assert_eq!(FctProduct::from_manifest_prefix("unknown"), None);
    }

    #[test]
    fn extract_manifest_context_resolves_product_from_manifest_prefix() {
        let json = r#"{
            "app": { "name": "My App", "id": "ari:cloud:ecosystem::app/abc-123" },
            "modules": {
                "macro": [ { "key": "conf-macro", "function": "macroFn" } ],
                "jira:globalPage": [ { "key": "jira-page", "function": "jiraFn" } ],
                "jiraServiceManagement:queuePage": [ { "key": "jsm-queue", "function": "jsmFn" } ]
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        assert_eq!(
            extract_manifest_context(&manifest, "conf-macro").unwrap().product,
            FctProduct::Confluence
        );
        assert_eq!(
            extract_manifest_context(&manifest, "jira-page").unwrap().product,
            FctProduct::Jira
        );
        assert_eq!(
            extract_manifest_context(&manifest, "jsm-queue").unwrap().product,
            FctProduct::JiraServiceManagement
        );
    }

    // Builds a minimal global-app config for build_variables tests.
    fn global_config(cloud_id: &str) -> MintFctConfig {
        MintFctConfig {
            product: Product::Global,
            site_id: "example".to_string(),
            mutation: None,
            auth: AuthConfig {
                auth_type: default_auth_type(),
                raw_cookie: Some("x".to_string()),
                raw_cookie_file: None,
                email: None,
                api_token: None,
                api_token_file: None,
            },
            cloud_id: Some(cloud_id.to_string()),
            installation_id: Some("inst-1".to_string()),
            environment_id: None,
            environment_type: None,
            module_key: None,
            environment_key: None,
            variables: None,
        }
    }

    #[test]
    fn graphql_endpoint_is_derived_from_site_id() {
        let cfg = global_config("cid");
        assert_eq!(
            cfg.graphql_endpoint(),
            "https://example.atlassian.net/gateway/api/graphql"
        );
    }

    fn manifest_ctx_for(product: FctProduct) -> ManifestContext {
        ManifestContext {
            app_id: "ari:cloud:ecosystem::app/abc-123".to_string(),
            app_id_bare: "abc-123".to_string(),
            app_name: Some("My App".to_string()),
            module_key: Some("mod".to_string()),
            module_type: Some("globalPage".to_string()),
            product,
            environment_id: Some("env-1".to_string()),
            app_version: Some("1".to_string()),
        }
    }

    #[test]
    fn build_variables_global_uses_resolved_product_ari() {
        // Jira app -> jira site ARI.
        let vars = build_variables(&global_config("cloud-jira"), &manifest_ctx_for(FctProduct::Jira))
            .unwrap();
        assert_eq!(
            vars["input"]["contextIds"][0],
            json!("ari:cloud:jira::site/cloud-jira")
        );

        // JSM app -> jira-servicedesk site ARI (not jira), proving no hardcoding.
        let vars = build_variables(
            &global_config("cloud-jsm"),
            &manifest_ctx_for(FctProduct::JiraServiceManagement),
        )
        .unwrap();
        assert_eq!(
            vars["input"]["contextIds"][0],
            json!("ari:cloud:jira-servicedesk::site/cloud-jsm")
        );
    }

    #[test]
    fn build_variables_confluence_uses_flat_ids() {
        let mut cfg = global_config("cloud-conf");
        cfg.product = Product::Confluence;
        let vars =
            build_variables(&cfg, &manifest_ctx_for(FctProduct::Confluence)).unwrap();
        // Flattened top-level cloud_id feeds the Confluence template.
        assert_eq!(vars["cloudId"], json!("cloud-conf"));
        assert_eq!(
            vars["input"]["contextIds"][0],
            json!("ari:cloud:confluence::site/cloud-conf")
        );
        assert_eq!(
            vars["input"]["extensionSpecificContexts"]["installationId"],
            json!("inst-1")
        );
    }
}
