//! Shared minting foundation used across the pen-testing capabilities.
//!   - Config structs: `FsrtRemoteConfig` (deserialised from `fsrt-remote.toml`)
//!     is converted into the runtime `MintFctConfig`
//!   - Auth header construction
//!   - GraphQL HTTP POST via `ureq`
//!   - Template rendering
//!   - Environment resolution and the core `mint_fct_jwt()` entry point

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64_URL};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fs;

use forge_loader::manifest::ForgeManifest;
use tracing::{info, warn};

// The default FCT mutation for global apps (`globalApp_signForgeContextTokens`).
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

/// File-facing configuration, deserialised directly from `fsrt-remote.toml`.
/// Convert into the runtime [`MintFctConfig`] via `From`/`Into`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsrtRemoteConfig {
    // Atlassian site domain (the full host, e.g. "your-site.atlassian.net")
    // from which the GraphQL gateway and tenant-info URLs are derived.
    pub site_domain: String,

    // Auth credentials — how to authenticate the HTTP request.
    pub auth: AuthConfig,

    // App/site IDs.
    pub installation_id: String, // required for now but will be changed in future pr
    pub environment_id: Option<String>,
    pub environment_type: Option<String>,
    // Forge environment slot used to look up the environment id.
    pub environment_key: Option<String>,
}

impl FsrtRemoteConfig {
    // Validates that user-supplied required fields are present and non-empty.
    pub fn validate(&self) -> Result<()> {
        let mut missing = Vec::new();

        if self.site_domain.trim().is_empty() {
            missing.push("site_domain");
        } else {
            parse_site_domain(&self.site_domain)?;
        }
        // serde guarantees the key exists (installation_id is a required String),
        // so this only needs to reject an empty / whitespace-only value.
        if self.installation_id.trim().is_empty() {
            missing.push("installation_id");
        }

        if missing.is_empty() {
            Ok(())
        } else {
            Err(MintError::Config(format!(
                "missing required config field(s): {}. Set them in the fsrt-remote.toml config file",
                missing.join(", ")
            )))
        }
    }
}

/// Runtime minting configuration, built from validated [`FsrtRemoteConfig`].
#[derive(Debug, Serialize)]
pub struct MintFctConfig {
    // Site domain (the full host, e.g. "your-site.atlassian.net").
    pub site_domain: String,

    // Auth credentials — how to authenticate the HTTP request.
    pub auth: AuthConfig,

    // Derived at runtime (never from the config file) via `resolve_cloud_id`.
    pub cloud_id: Option<String>,

    // App/site IDs and environment selectors, carried over from the file config.
    pub installation_id: String,
    pub environment_id: Option<String>,
    pub environment_type: Option<String>,
    pub environment_key: Option<String>,
}

impl TryFrom<FsrtRemoteConfig> for MintFctConfig {
    type Error = MintError;

    // Maps the file-facing config onto the runtime config.
    fn try_from(file: FsrtRemoteConfig) -> Result<Self> {
        let site_domain = parse_site_domain(&file.site_domain)?;
        Ok(MintFctConfig {
            site_domain,
            auth: file.auth,
            cloud_id: None,
            installation_id: file.installation_id,
            environment_id: file.environment_id,
            environment_type: file.environment_type,
            environment_key: file.environment_key,
        })
    }
}

fn parse_site_domain(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = url::Url::parse(&candidate)
        .map_err(|error| MintError::Config(format!("invalid site_domain '{trimmed}': {error}")))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(MintError::Config(format!(
            "invalid site_domain '{trimmed}': only http and https URLs are supported"
        )));
    }
    if parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(MintError::Config(format!(
            "invalid site_domain '{trimmed}': expected a host without credentials, path, query, or fragment"
        )));
    }

    let mut authority = parsed
        .host()
        .expect("host presence checked above")
        .to_string();
    if let Some(port) = parsed.port() {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    Ok(authority)
}

impl MintFctConfig {
    // `site_domain` is parsed and normalised while loading the config.
    fn host(&self) -> &str {
        &self.site_domain
    }

    pub fn graphql_endpoint(&self) -> String {
        format!("https://{}/gateway/api/graphql", self.host())
    }

    // The public tenant-info endpoint for this site, used to derive `cloud_id`.
    pub fn tenant_info_endpoint(&self) -> String {
        format!("https://{}/_edge/tenant_info", self.host())
    }

    // Populates `cloud_id` by deriving it from `site_domain` via the public
    // `_edge/tenant_info` endpoint.
    pub fn resolve_cloud_id(&mut self) -> Result<()> {
        if self.cloud_id.as_deref().unwrap_or("").trim().is_empty() {
            let cloud_id = fetch_cloud_id(&self.tenant_info_endpoint())?;
            info!(
                site_domain = %self.site_domain,
                cloud_id = %cloud_id,
                "derived cloud_id from site_domain via _edge/tenant_info"
            );
            self.cloud_id = Some(cloud_id);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub raw_cookie: Option<String>,
    pub raw_cookie_file: Option<String>,
}

// The Atlassian product an FCT is being minted for.
// ASK JOSH: what other products are there, and what is the easiest way to get an ARI?
// context_ari hardcodes pattern
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
    // Full FCT `extensionType` (e.g. "jira:issuePanel"; "xen:macro" for macros).
    pub extension_type: String,
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

    let extension_type = manifest.modules.fct_module_for_key(module_key).ok_or_else(|| {
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

    // Recover the product namespace from the extensionType for the context ARI.
    let product_prefix = if extension_type == "xen:macro" {
        "confluence" // special cases for Confluence macro
    } else {
        extension_type.split(':').next().unwrap_or_default()
    };

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
        extension_type: extension_type.to_owned(),
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

pub fn build_auth_headers(auth: &AuthConfig) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();

    info!("building auth headers from config — this uses sensitive credentials");

    let raw = load_secret_from_config(auth.raw_cookie.as_deref(), auth.raw_cookie_file.as_deref())?
        .ok_or_else(|| {
            MintError::Config(
                "auth requires a session cookie: set `raw_cookie` (inline) or `raw_cookie_file`"
                    .into(),
            )
        })?;

    info!(bytes = raw.len(), "loaded session cookie");

    match cookie_expiry(&raw) {
        Some(CookieExpiry::Expired(secs_ago)) => {
            return Err(MintError::CookieExpired(format!(
                "Session cookie EXPIRED {} ago. Renew it (e.g. re-copy the \
                 Cookie header from your browser/Burp into `raw_cookie` or \
                 the file referenced by `raw_cookie_file`), then retry.",
                format_duration(secs_ago),
            )));
        }
        Some(CookieExpiry::Valid(secs_remaining)) => info!(
            expires_in = %format_duration(secs_remaining),
            "session cookie valid"
        ),
        None => warn!(
            cookie_name = SESSION_COOKIE_NAME,
            "could not read the session cookie expiry — cannot check expiry"
        ),
    }

    headers.insert("Cookie".to_string(), normalize_cookie_header(&raw));

    Ok(headers)
}

const SESSION_COOKIE_NAME: &str = "tenant.session.token";

// Normalises the configured session cookie into a full `Cookie` header value.
fn normalize_cookie_header(raw_cookie: &str) -> String {
    let trimmed = raw_cookie.trim();

    if trimmed.contains('=') {
        trimmed.to_string()
    } else {
        format!("{SESSION_COOKIE_NAME}={trimmed}")
    }
}

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

enum CookieExpiry {
    Expired(i64),
    Valid(i64),
}

fn cookie_expiry(raw_cookie: &str) -> Option<CookieExpiry> {
    let token = extract_session_token(raw_cookie)?;
    let exp = decode_jwt_exp(token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if exp <= now {
        Some(CookieExpiry::Expired(now - exp))
    } else {
        Some(CookieExpiry::Valid(exp - now))
    }
}

// Replaces placeholders in JSON value tree.
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

    if let Some(caps) = re.captures(s)
        && caps[0] == *s
    {
        let path = &caps[1];
        return get_path(context, path).cloned().unwrap_or(JsonValue::Null);
    }

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

// Overall HTTP timeout for GraphQL gateway calls, so a hung server can't block the CLI.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// A ureq Agent configured with our request timeout, callers can read body for diagnostics.
fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into()
}

pub fn fetch_cloud_id(tenant_info_endpoint: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct TenantInfo {
        #[serde(rename = "cloudId")]
        cloud_id: Option<String>,
    }

    let mut response = http_agent()
        .get(tenant_info_endpoint)
        .call()
        .map_err(|e| MintError::Http(e.to_string()))?;

    let status = response.status();
    if status.as_u16() >= 400 {
        let text = response
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|_| "<unreadable response body>".to_string());
        return Err(MintError::Config(format!(
            "failed to derive cloud_id: {tenant_info_endpoint} returned HTTP {status}. \
             Check that `site_domain` is correct and reachable.\n\
             Response body: {text}"
        )));
    }

    let info: TenantInfo = response
        .body_mut()
        .read_json()
        .map_err(|e| MintError::Http(e.to_string()))?;

    info.cloud_id
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            MintError::Config(format!(
                "failed to derive cloud_id: no `cloudId` field in response from \
                 {tenant_info_endpoint}. Check that `site_domain` is correct."
            ))
        })
}

fn graphql_request(
    endpoint: &str,
    auth_headers: &HashMap<String, String>,
) -> ureq::RequestBuilder<ureq::typestate::WithBody> {
    let origin = endpoint.split('/').take(3).collect::<Vec<_>>().join("/");
    let mut request = http_agent().post(endpoint).header("Origin", &origin);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    request
}

fn graphql_body(operation_name: &str, query: &str, variables: &JsonValue) -> JsonValue {
    serde_json::json!({
        "operationName": operation_name,
        "query": query,
        "variables": variables,
    })
}

pub fn post_graphql(
    endpoint: &str,
    operation_name: &str,
    auth_headers: &HashMap<String, String>,
    query: &str,
    variables: &JsonValue,
) -> Result<(u16, String)> {
    let body = graphql_body(operation_name, query, variables);

    let mut response = graphql_request(endpoint, auth_headers)
        .send_json(&body)
        .map_err(|e| MintError::Http(e.to_string()))?;

    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|e| MintError::Http(e.to_string()))?;
    Ok((status, text))
}

pub fn post_graphql_json<T: serde::de::DeserializeOwned>(
    endpoint: &str,
    operation_name: &str,
    auth_headers: &HashMap<String, String>,
    query: &str,
    variables: &JsonValue,
) -> Result<(u16, T)> {
    let (status, text) = post_graphql(endpoint, operation_name, auth_headers, query, variables)?;
    if status >= 400 {
        return Err(MintError::Http(format!(
            "{operation_name} returned HTTP {status}. Response body: {text}"
        )));
    }

    let parsed = serde_json::from_str(&text)
        .map_err(|e| MintError::Http(format!("{operation_name} returned invalid JSON: {e}")))?;
    Ok((status, parsed))
}

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

    let file_cfg: FsrtRemoteConfig = settings.try_deserialize()?;
    file_cfg.validate()?;
    MintFctConfig::try_from(file_cfg)
}

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

#[derive(Debug, Clone)]
pub struct AppEnvironment {
    pub environment_id: String,
    pub app_version: Option<String>,
}

fn deserialize_null_vec<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

// Typed view of the `globalApp_signForgeContextTokens` mutation response.
#[derive(Debug, Deserialize, Serialize)]
struct FctResponse {
    data: Option<FctData>,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FctData {
    #[serde(rename = "globalApp_signForgeContextTokens")]
    result: Option<FctResult>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FctResult {
    #[serde(default)]
    success: bool,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    errors: Vec<GraphqlError>,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    tokens: Vec<FctToken>,
}

#[derive(Debug, Deserialize, Serialize)]
struct GraphqlError {
    message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FctToken {
    jwt: Option<String>,
}

// Typed view of the `GetAppEnvironment` GraphQL response.
#[derive(Debug, Deserialize, Serialize)]
struct AppEnvResponse {
    data: Option<AppEnvData>,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AppEnvData {
    app: Option<AppNode>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AppNode {
    #[serde(rename = "environmentByKey")]
    environment_by_key: Option<EnvironmentNode>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EnvironmentNode {
    id: Option<String>,
    versions: Option<VersionsConnection>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VersionsConnection {
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    nodes: Vec<VersionNode>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VersionNode {
    version: Option<String>,
    #[serde(default, rename = "isLatest")]
    is_latest: bool,
}

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

    let (status, parsed): (u16, AppEnvResponse) = post_graphql_json(
        endpoint,
        APP_ENVIRONMENT_OPERATION_NAME,
        auth_headers,
        APP_ENVIRONMENT_QUERY,
        &variables,
    )?;

    let response = serde_json::to_string(&parsed)
        .unwrap_or_else(|_| "<unserializable typed response>".to_string());
    let unresolved = || {
        MintError::Config(format!(
            "Could not resolve environment '{env_key}' for app {app_id} (HTTP {status}). \
             Check the environment key, or set environment_id explicitly in the config.\n\
             Parsed response: {response}"
        ))
    };

    let env = parsed
        .data
        .and_then(|d| d.app)
        .and_then(|a| a.environment_by_key)
        .ok_or_else(unresolved)?;

    let environment_id = env.id.ok_or_else(unresolved)?;

    let app_version = env.versions.and_then(|versions| {
        versions
            .nodes
            .iter()
            .find(|node| node.is_latest)
            .or_else(|| versions.nodes.first())
            .and_then(|node| node.version.clone())
    });

    Ok(AppEnvironment {
        environment_id,
        app_version,
    })
}

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
        Some(key) => fetch_app_environment(&endpoint, auth_headers, &manifest_ctx.app_id, &key)?,
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

pub fn build_variables(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
) -> Result<JsonValue> {
    let config_value =
        serde_json::to_value(config).unwrap_or(JsonValue::Object(Default::default()));

    let cloud_id = config.cloud_id.as_deref().unwrap_or("");
    let context_ari = manifest_ctx.product.context_ari(cloud_id);

    let context = serde_json::json!({
        "manifest": {
            "app_id":         manifest_ctx.app_id,
            "app_id_bare":    manifest_ctx.app_id_bare,
            "app_name":       manifest_ctx.app_name,
            "module_key":     manifest_ctx.module_key,
            "extension_type": manifest_ctx.extension_type,
            "environment_id": manifest_ctx.environment_id,
            "app_version":    manifest_ctx.app_version,
        },
        "config": config_value,
        "context_ari": context_ari,
    });

    let template: JsonValue = serde_json::json!({
        "input": {
            // Product-resolved at runtime from the manifest.
            "contextIds": ["${context_ari}"],
            "unlicensed": false,
            "extensionContexts": [{
                "appVersion": "${manifest.app_version}",
                "extensionId": "ari:cloud:ecosystem::extension/${manifest.app_id_bare}/${manifest.environment_id}/static/${manifest.module_key}",
                "extensionType": "${manifest.extension_type}",
                "installationId": "${config.installation_id}",
                "context": {
                    "moduleKey": "${manifest.module_key}",
                    "cloudId": "${config.cloud_id}",
                    "environmentId": "${manifest.environment_id}",
                    "type": "${manifest.extension_type}",
                    "extension": { "type": "${manifest.extension_type}" }
                }
            }]
        }
    });

    let rendered = render_template(&template, &context);

    if !rendered.is_object() {
        return Err(MintError::Config(
            "Rendered GraphQL variables must be a JSON object".into(),
        ));
    }

    Ok(rendered)
}

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
    let (query, operation_name) = (DEFAULT_GLOBAL_APP_MUTATION, GLOBAL_APP_OPERATION_NAME);

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

    if !quiet {
        info!(http_status = status, response = %body, "FCT GraphQL response");
    }
    if status >= 400 {
        return Err(MintError::Http(format!(
            "{operation_name} returned HTTP {status}. Response body: {body}"
        )));
    }

    // Parse the response into typed structs once.
    let parsed: FctResponse = serde_json::from_str(&body).map_err(|e| {
        warn!(response_body = %body, "FCT response was not valid JSON");
        MintError::Json(e)
    })?;

    let result = parsed.data.and_then(|d| d.result).ok_or_else(|| {
        let messages = parsed
            .errors
            .into_iter()
            .filter_map(|error| error.message)
            .collect::<Vec<_>>();
        let detail = if messages.is_empty() {
            "response missing data.globalApp_signForgeContextTokens".to_string()
        } else {
            format!("GraphQL errors: {}", messages.join("; "))
        };
        MintError::FctFailed(detail)
    })?;

    if !result.success {
        let messages: Vec<String> = result
            .errors
            .into_iter()
            .filter_map(|e| e.message)
            .collect();

        return Err(MintError::FctFailed(if messages.is_empty() {
            "Server returned success=false with no error messages".to_string()
        } else {
            messages.join("; ")
        }));
    }

    result
        .tokens
        .into_iter()
        .next()
        .and_then(|t| t.jwt)
        .ok_or_else(|| MintError::FctFailed("tokens[0].jwt missing from response".to_string()))
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
    fn format_duration_buckets() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(3 * 60), "3m");
        assert_eq!(format_duration(2 * 3600 + 5 * 60), "2h 5m");
        assert_eq!(format_duration(3 * 86_400 + 4 * 3600), "3d 4h");
        assert_eq!(format_duration(-45), "45s");
    }

    #[test]
    fn extract_manifest_context_resolves_extension_type_for_key() {
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
        assert_eq!(ctx.extension_type, "xen:macro");
        assert_eq!(ctx.product, FctProduct::Confluence);
    }

    #[test]
    fn extract_manifest_context_uses_full_namespace_as_extension_type() {
        // Non-macro modules use their fully-qualified `product:moduleType` key
        // verbatim as the extensionType.
        let json = r#"{
            "app": { "name": "My App", "id": "ari:cloud:ecosystem::app/abc-123" },
            "modules": {
                "jira:issuePanel": [ { "key": "my-panel", "function": "panelFn" } ]
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let ctx = extract_manifest_context(&manifest, "my-panel").unwrap();
        assert_eq!(ctx.extension_type, "jira:issuePanel");
        assert_eq!(ctx.product, FctProduct::Jira);
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
            extract_manifest_context(&manifest, "conf-macro")
                .unwrap()
                .product,
            FctProduct::Confluence
        );
        assert_eq!(
            extract_manifest_context(&manifest, "jira-page")
                .unwrap()
                .product,
            FctProduct::Jira
        );
        assert_eq!(
            extract_manifest_context(&manifest, "jsm-queue")
                .unwrap()
                .product,
            FctProduct::JiraServiceManagement
        );
    }

    // Builds a minimal global-app config for build_variables tests.
    fn global_config(cloud_id: &str) -> MintFctConfig {
        MintFctConfig {
            site_domain: "example.atlassian.net".to_string(),
            auth: AuthConfig {
                raw_cookie: Some("x".to_string()),
                raw_cookie_file: None,
            },
            cloud_id: Some(cloud_id.to_string()),
            installation_id: "inst-1".to_string(),
            environment_id: None,
            environment_type: None,
            environment_key: None,
        }
    }

    // Builds a minimal, valid file-facing config (as if parsed from TOML).
    fn file_config() -> FsrtRemoteConfig {
        FsrtRemoteConfig {
            site_domain: "example.atlassian.net".to_string(),
            auth: AuthConfig {
                raw_cookie: Some("x".to_string()),
                raw_cookie_file: None,
            },
            installation_id: "inst-1".to_string(),
            environment_id: None,
            environment_type: None,
            environment_key: None,
        }
    }

    #[test]
    fn validate_flags_missing_required_fields() {
        // Complete file config passes.
        assert!(file_config().validate().is_ok());

        // Empty / whitespace-only installation_id is reported.
        let mut cfg = file_config();
        cfg.installation_id = "  ".to_string(); // whitespace counts as missing
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("installation_id"), "got: {err}");

        // Missing site_domain is reported.
        let mut cfg = file_config();
        cfg.site_domain = "   ".to_string();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("site_domain"), "got: {err}");
    }

    #[test]
    fn from_file_config_leaves_cloud_id_unset() {
        // Conversion must carry over user fields and leave cloud_id for runtime
        // derivation (never sourced from the file).
        let cfg = MintFctConfig::try_from(file_config()).unwrap();
        assert_eq!(cfg.cloud_id, None);
        assert_eq!(cfg.site_domain, "example.atlassian.net");
        assert_eq!(cfg.installation_id, "inst-1");
    }

    #[test]
    fn resolve_cloud_id_is_idempotent_once_set() {
        // Once cloud_id is populated, resolve_cloud_id() is a no-op and makes no
        // network call (a real fetch would require a reachable site).
        let mut cfg = global_config("cid");
        cfg.cloud_id = Some("already-derived".to_string());
        cfg.resolve_cloud_id().unwrap();
        assert_eq!(cfg.cloud_id.as_deref(), Some("already-derived"));
    }

    #[test]
    fn fct_response_arrays_accept_null() {
        let fct: FctResponse = serde_json::from_value(json!({
            "data": {
                "globalApp_signForgeContextTokens": {
                    "success": false,
                    "errors": null,
                    "tokens": null
                }
            },
            "errors": null
        }))
        .unwrap();
        assert!(fct.errors.is_empty());
        let result = fct.data.unwrap().result.unwrap();
        assert!(result.errors.is_empty());
        assert!(result.tokens.is_empty());
    }

    #[test]
    fn app_environment_response_arrays_accept_null() {
        let app_env: AppEnvResponse = serde_json::from_value(json!({
            "data": {
                "app": {
                    "environmentByKey": {
                        "id": "env-1",
                        "versions": { "nodes": null }
                    }
                }
            },
            "errors": null
        }))
        .unwrap();
        assert!(app_env.errors.is_empty());
        let nodes = app_env
            .data
            .unwrap()
            .app
            .unwrap()
            .environment_by_key
            .unwrap()
            .versions
            .unwrap()
            .nodes;
        assert!(nodes.is_empty());
    }

    #[test]
    fn config_file_valid_minimal_loads() {
        let file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        // A minimal valid config (cookie auth, no removed keys) loads cleanly and
        // leaves cloud_id unset for runtime derivation.
        std::fs::write(
            file.path(),
            r#"
site_domain = "example.atlassian.net"
installation_id = "inst-123"

[auth]
raw_cookie = "tenant.session.token=a.b.c"
"#,
        )
        .unwrap();
        let cfg = load_config(file.path()).expect("minimal config should load");

        assert_eq!(cfg.cloud_id, None);
        assert_eq!(cfg.installation_id, "inst-123");
    }

    #[test]
    fn config_file_rejects_cloud_id_key() {
        // cloud_id is not user-configurable; deny_unknown_fields rejects it.
        let err = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
site_domain = "example.atlassian.net"
cloud_id = "should-be-rejected"
installation_id = "inst-123"

[auth]
raw_cookie = "tenant.session.token=a.b.c"
"#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize::<FsrtRemoteConfig>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("cloud_id"), "got: {err}");
    }

    #[test]
    fn config_file_rejects_removed_keys() {
        // Removed keys must fail to parse rather than be silently ignored.
        // `product` at the top level.
        let err = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
site_domain = "example.atlassian.net"
installation_id = "inst-123"
product = "global"

[auth]
raw_cookie = "tenant.session.token=a.b.c"
"#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize::<FsrtRemoteConfig>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("product"), "got: {err}");

        // `type` inside [auth].
        let err = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
site_domain = "example.atlassian.net"
installation_id = "inst-123"

[auth]
type = "raw_cookie"
raw_cookie = "tenant.session.token=a.b.c"
"#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize::<FsrtRemoteConfig>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("type"), "got: {err}");
    }

    #[test]
    fn normalize_cookie_header_prefixes_bare_token() {
        // A bare 3-part JWT gets the cookie name prepended.
        assert_eq!(
            normalize_cookie_header("eyJhbGc.eyJzdWI.sIg"),
            "tenant.session.token=eyJhbGc.eyJzdWI.sIg"
        );
        // Surrounding whitespace is trimmed before prefixing.
        assert_eq!(
            normalize_cookie_header("  eyJhbGc.eyJzdWI.sIg  "),
            "tenant.session.token=eyJhbGc.eyJzdWI.sIg"
        );
    }

    #[test]
    fn config_file_rejects_module_key() {
        let err = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
site_domain = "example.atlassian.net"
installation_id = "inst-123"
module_key = "manifest-is-the-source-of-truth"

[auth]
raw_cookie = "tenant.session.token=a.b.c"
"#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize::<FsrtRemoteConfig>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("module_key"), "got: {err}");
    }

    #[test]
    fn normalize_cookie_header_leaves_full_cookie_untouched() {
        // Already-prefixed value is used verbatim (aside from trimming).
        assert_eq!(
            normalize_cookie_header("tenant.session.token=eyJhbGc.eyJzdWI.sIg"),
            "tenant.session.token=eyJhbGc.eyJzdWI.sIg"
        );
        // A multi-pair cookie string is left as-is.
        let full = "tenant.session.token=eyJhbGc.eyJzdWI.sIg; other=1";
        assert_eq!(normalize_cookie_header(full), full);
    }

    #[test]
    fn graphql_endpoint_is_derived_from_site_domain() {
        let cfg = global_config("cid");
        assert_eq!(
            cfg.graphql_endpoint(),
            "https://example.atlassian.net/gateway/api/graphql"
        );
    }

    #[test]
    fn tenant_info_endpoint_is_derived_from_site_domain() {
        let cfg = global_config("cid");
        assert_eq!(
            cfg.tenant_info_endpoint(),
            "https://example.atlassian.net/_edge/tenant_info"
        );
    }

    #[test]
    fn site_domain_is_normalised_for_endpoints() {
        // A scheme and/or trailing slash in site_domain must be tolerated.
        for raw in [
            "example.atlassian.net",
            "https://example.atlassian.net",
            "https://example.atlassian.net/",
            "  https://example.atlassian.net/  ",
            "http://example.atlassian.net",
        ] {
            let mut cfg = global_config("cid");
            cfg.site_domain = parse_site_domain(raw).unwrap();
            assert_eq!(
                cfg.graphql_endpoint(),
                "https://example.atlassian.net/gateway/api/graphql",
                "graphql endpoint for site_domain={raw:?}"
            );
            assert_eq!(
                cfg.tenant_info_endpoint(),
                "https://example.atlassian.net/_edge/tenant_info",
                "tenant_info endpoint for site_domain={raw:?}"
            );
        }
    }

    #[test]
    fn site_domain_rejects_non_host_url_components() {
        for raw in [
            "ftp://example.atlassian.net",
            "https://user@example.atlassian.net",
            "https://example.atlassian.net/wiki",
            "https://example.atlassian.net?query=value",
            "https://example.atlassian.net#fragment",
        ] {
            let err = parse_site_domain(raw).unwrap_err().to_string();
            assert!(err.contains("site_domain"), "input={raw:?}, error={err}");
        }
    }

    fn manifest_ctx_for(product: FctProduct) -> ManifestContext {
        ManifestContext {
            app_id: "ari:cloud:ecosystem::app/abc-123".to_string(),
            app_id_bare: "abc-123".to_string(),
            app_name: Some("My App".to_string()),
            module_key: Some("mod".to_string()),
            extension_type: "jira:globalPage".to_string(),
            product,
            environment_id: Some("env-1".to_string()),
            app_version: Some("1".to_string()),
        }
    }

    #[test]
    fn build_variables_global_uses_resolved_product_ari() {
        // Jira app -> jira site ARI.
        let vars = build_variables(
            &global_config("cloud-jira"),
            &manifest_ctx_for(FctProduct::Jira),
        )
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
    fn build_variables_confluence_uses_global_shape() {
        // A Confluence module now mints via the global-app shape, but still uses
        // the confluence-owned site ARI (product identity is preserved).
        let cfg = global_config("cloud-conf");
        let vars = build_variables(&cfg, &manifest_ctx_for(FctProduct::Confluence)).unwrap();

        // Global shape: no top-level `cloudId`, uses `input.extensionContexts`.
        assert!(vars.get("cloudId").is_none(), "got: {vars}");
        assert_eq!(
            vars["input"]["contextIds"][0],
            json!("ari:cloud:confluence::site/cloud-conf")
        );
        assert_eq!(
            vars["input"]["extensionContexts"][0]["installationId"],
            json!("inst-1")
        );
        // cloudId is carried in the nested context, not at the top level.
        assert_eq!(
            vars["input"]["extensionContexts"][0]["context"]["cloudId"],
            json!("cloud-conf")
        );
    }
}
