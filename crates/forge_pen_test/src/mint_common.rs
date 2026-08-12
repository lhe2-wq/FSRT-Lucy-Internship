//! Authentication, JWT, HTTP, and GraphQL support for FCT minting.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64_URL};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;
use std::fs;

use tracing::{info, warn};
use ureq::{
    Body, SendBody,
    http::{
        Request, Response,
        header::{COOKIE, HeaderValue, ORIGIN},
    },
    middleware::{Middleware, MiddlewareNext},
};

use crate::app_config::{AppConfig, ExtensionConfig};
#[cfg(test)]
use crate::fsrt_remote_config::FsrtRemoteConfig;

/// Errors returned by an authenticated GraphQL operation.
#[derive(Debug, thiserror::Error)]
pub enum GraphQLError {
    /// The request, response body, or HTTP status failed.
    #[error("HTTP error: {0}")]
    Http(String),

    /// The response body was not valid JSON for the expected response type.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The GraphQL response contained top-level errors or no data.
    #[error("GraphQL operation '{operation_name}' failed: {message}")]
    Graphql {
        operation_name: String,
        message: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("{0}")]
    Config(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Graphql(#[from] GraphQLError),

    #[error("FCT minting failed: {0}")]
    FctFailed(String),

    #[error("environment '{environment_key}' was not found for app {app_id}")]
    EnvironmentNotFound {
        environment_key: String,
        app_id: String,
    },

    #[error("{0}")]
    CookieExpired(String),
}

/// Structural and expiry status of a JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtValidity {
    /// The token is structurally valid and unexpired.
    Valid,
    /// The token is structurally valid but expired.
    Expired,
    /// The token is missing or structurally invalid.
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnvironmentSelection {
    Automatic,
    Key(String),
}

enum CookieExpiry {
    Expired(i64),
    Valid(i64),
}

#[derive(Deserialize)]
struct TenantInfo {
    #[serde(rename = "cloudId")]
    cloud_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse<T> {
    data: Option<T>,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    errors: Vec<GraphqlResponseError>,
}

#[derive(Debug, Deserialize)]
struct GraphqlResponseError {
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AppEnvData {
    app: Option<AppNode>,
}

#[derive(Debug, Deserialize)]
struct AppNode {
    #[serde(rename = "environmentByKey")]
    environment_by_key: Option<EnvironmentNode>,
}

#[derive(Debug, Deserialize)]
struct EnvironmentNode {
    id: Option<String>,
    versions: Option<VersionsConnection>,
}

#[derive(Debug, Deserialize)]
struct VersionsConnection {
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    nodes: Vec<VersionNode>,
}

#[derive(Debug, Deserialize)]
struct VersionNode {
    version: Option<String>,
    extensions: Option<ExtensionsConnection>,
}

#[derive(Debug, Deserialize)]
struct ExtensionsConnection {
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    nodes: Vec<DeployedExtension>,
}

#[derive(Debug, Clone, Deserialize)]
struct DeployedExtension {
    id: Option<String>,
    key: Option<String>,
    #[serde(rename = "extensionTypeKey")]
    extension_type_key: Option<String>,
}

const SESSION_COOKIE_NAME: &str = "tenant.session.token";
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const GRAPHQL_ENDPOINT: &str = "https://www.atlassian.net/gateway/api/graphql";
const GRAPHQL_ORIGIN: &str = "https://www.atlassian.net";
const PRODUCTION_ENVIRONMENT_KEY: &str = "production";
const DEFAULT_ENVIRONMENT_KEY: &str = "default";
const APP_ENVIRONMENT_OPERATION_NAME: &str = "GetAppEnvironment";
const APP_ENVIRONMENT_QUERY: &str = r#"query GetAppEnvironment($appId: ID!, $envKey: String!) {
  app(id: $appId) {
    environmentByKey(key: $envKey) {
      id
      versions(first: 1) {
        nodes {
          version
          extensions {
            nodes {
              id
              key
              extensionTypeKey
            }
          }
        }
      }
    }
  }
}"#;

struct GraphqlHeaders {
    cookie: HeaderValue,
}

impl GraphqlHeaders {
    fn new(cookie_header: String) -> Result<Self, MintError> {
        let cookie = HeaderValue::from_str(&cookie_header).map_err(|error| {
            MintError::Config(format!(
                "session cookie is not a valid HTTP header value: {error}"
            ))
        })?;
        Ok(Self { cookie })
    }
}

impl Middleware for GraphqlHeaders {
    fn handle(
        &self,
        mut request: Request<SendBody<'_>>,
        next: MiddlewareNext<'_>,
    ) -> Result<Response<Body>, ureq::Error> {
        if request.uri() == GRAPHQL_ENDPOINT {
            request
                .headers_mut()
                .insert(ORIGIN, HeaderValue::from_static(GRAPHQL_ORIGIN));
            request.headers_mut().insert(COOKIE, self.cookie.clone());
        }
        next.handle(request)
    }
}

pub(crate) fn build_cookie_header(raw_cookie_file: &str) -> Result<String, MintError> {
    let raw = fs::read_to_string(raw_cookie_file).map_err(|error| {
        MintError::Config(format!(
            "Could not read session cookie file '{raw_cookie_file}': {error}"
        ))
    })?;
    let raw = raw.trim().to_string();
    if raw.is_empty() {
        return Err(MintError::Config(format!(
            "Session cookie file '{raw_cookie_file}' is empty"
        )));
    }

    match cookie_expiry(&raw)? {
        CookieExpiry::Expired(secs_ago) => {
            return Err(MintError::CookieExpired(format!(
                "Session cookie EXPIRED {} ago. Renew it (e.g. re-copy the \
                 Cookie header from your browser/Burp into the file referenced \
                 by `raw_cookie_file`), then retry.",
                format_duration(secs_ago),
            )));
        }
        CookieExpiry::Valid(secs_remaining) => info!(
            expires_in = %format_duration(secs_remaining),
            "session cookie valid"
        ),
    }

    Ok(if raw.contains('=') {
        raw
    } else {
        format!("{SESSION_COOKIE_NAME}={raw}")
    })
}

pub(crate) fn decode_jwt_payload(token: &str) -> Option<JsonValue> {
    let mut segments = token.split('.');
    let header_b64 = segments.next()?;
    let payload_b64 = segments.next()?;
    let signature_b64 = segments.next()?;
    if header_b64.is_empty()
        || payload_b64.is_empty()
        || signature_b64.is_empty()
        || segments.next().is_some()
    {
        return None;
    }

    let header_bytes = B64_URL.decode(header_b64).ok()?;
    let header: JsonValue = serde_json::from_slice(&header_bytes).ok()?;
    if !header.is_object() {
        return None;
    }

    let signature = B64_URL.decode(signature_b64).ok()?;
    if signature.is_empty() {
        return None;
    }

    let payload_bytes = B64_URL.decode(payload_b64).ok()?;
    let payload: JsonValue = serde_json::from_slice(&payload_bytes).ok()?;
    payload.is_object().then_some(payload)
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

fn cookie_expiry(raw_cookie: &str) -> Result<CookieExpiry, MintError> {
    let token = raw_cookie
        .split(';')
        .find_map(|pair| {
            pair.trim()
                .strip_prefix(SESSION_COOKIE_NAME)?
                .strip_prefix('=')
        })
        .or_else(|| {
            let token = raw_cookie.trim();
            (!token.contains('=') && token.split('.').count() == 3).then_some(token)
        })
        .ok_or_else(|| {
            MintError::Config(format!(
                "session cookie does not contain a non-empty `{SESSION_COOKIE_NAME}` JWT"
            ))
        })?;
    let exp = decode_jwt_payload(token)
        .and_then(|payload| payload.get("exp")?.as_i64())
        .ok_or_else(|| {
            MintError::Config(
                "session cookie is not a structurally valid JWT with an integer `exp` claim".into(),
            )
        })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if exp <= now {
        Ok(CookieExpiry::Expired(now - exp))
    } else {
        Ok(CookieExpiry::Valid(exp - now))
    }
}

pub(crate) fn build_http_agent(cookie_header: String) -> Result<ureq::Agent, MintError> {
    let headers = GraphqlHeaders::new(cookie_header)?;
    Ok(ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .http_status_as_error(false)
        .middleware(headers)
        .build()
        .into())
}

pub(crate) fn fetch_cloud_id(agent: &ureq::Agent, site: &str) -> Result<String, MintError> {
    let tenant_info_url = format!("{site}/_edge/tenant_info");
    let mut response = agent
        .get(&tenant_info_url)
        .call()
        .map_err(|e| MintError::Http(e.to_string()))?;

    let status = response.status();
    if status.as_u16() >= 400 {
        let text = response
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|_| "<unreadable response body>".to_string());
        return Err(MintError::Config(format!(
            "failed to derive cloud_id: {tenant_info_url} returned HTTP {status}. \
             Check that `site` is correct and reachable.\n\
             Response body: {text}"
        )));
    }

    let info: TenantInfo = response
        .body_mut()
        .read_json()
        .map_err(|e| MintError::Http(e.to_string()))?;

    info.cloud_id
        .map(|cloud_id| cloud_id.trim().to_string())
        .filter(|cloud_id| !cloud_id.is_empty())
        .ok_or_else(|| {
            MintError::Config(
                "failed to derive cloud_id: no non-empty `cloudId` field in tenant info \
                 response. Check that `site` is correct."
                    .to_string(),
            )
        })
}

pub(crate) fn send_graphql<V>(
    agent: &ureq::Agent,
    operation_name: &str,
    query: &str,
    variables: &V,
) -> Result<(u16, String), GraphQLError>
where
    V: Serialize + ?Sized,
{
    let mut response = agent
        .post(GRAPHQL_ENDPOINT)
        .send_json(serde_json::json!({
            "operationName": operation_name,
            "query": query,
            "variables": variables,
        }))
        .map_err(|error| GraphQLError::Http(error.to_string()))?;

    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|error| GraphQLError::Http(error.to_string()))?;
    Ok((status, text))
}

pub(crate) fn post_graphql<V, T>(
    agent: &ureq::Agent,
    operation_name: &str,
    query: &str,
    variables: &V,
) -> Result<T, GraphQLError>
where
    V: Serialize + ?Sized,
    T: DeserializeOwned,
{
    let (status, body) = send_graphql(agent, operation_name, query, variables)?;
    if status >= 400 {
        return Err(GraphQLError::Http(format!(
            "{operation_name} returned HTTP {status}. Response body: {body}"
        )));
    }

    let response: GraphqlResponse<T> = serde_json::from_str(&body).map_err(|error| {
        warn!(operation_name, response_body = %body, "GraphQL response was not valid JSON");
        GraphQLError::Json(error)
    })?;
    if !response.errors.is_empty() {
        let messages = response
            .errors
            .into_iter()
            .filter_map(|error| error.message)
            .collect::<Vec<_>>();
        return Err(GraphQLError::Graphql {
            operation_name: operation_name.to_string(),
            message: if messages.is_empty() {
                "response contained errors without messages".to_string()
            } else {
                messages.join("; ")
            },
        });
    }

    response.data.ok_or_else(|| GraphQLError::Graphql {
        operation_name: operation_name.to_string(),
        message: "response missing data".to_string(),
    })
}

fn deserialize_null_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn parse_app_environment_response(
    data: AppEnvData,
    app_id: &str,
    env_key: &str,
) -> Result<(String, String, String, Vec<DeployedExtension>), MintError> {
    let app = data.app.ok_or_else(|| {
        MintError::Config(format!(
            "Could not query app {app_id} while resolving environment '{env_key}'"
        ))
    })?;

    let env = app
        .environment_by_key
        .ok_or_else(|| MintError::EnvironmentNotFound {
            environment_key: env_key.to_string(),
            app_id: app_id.to_string(),
        })?;

    let environment_id = env
        .id
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            MintError::Config(format!(
                "Environment '{env_key}' for app {app_id} returned no environment id"
            ))
        })?;

    let version = env
        .versions
        .as_ref()
        .and_then(|versions| versions.nodes.first())
        .ok_or_else(|| {
            MintError::Config(format!(
                "Environment '{env_key}' for app {app_id} has no deployed app version"
            ))
        })?;

    let app_version = version
        .version
        .as_deref()
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            MintError::Config(format!(
                "Environment '{env_key}' for app {app_id} has no deployed app version"
            ))
        })?;

    let extensions = version
        .extensions
        .as_ref()
        .map(|extensions| extensions.nodes.clone())
        .unwrap_or_default();

    Ok((env_key.to_string(), environment_id, app_version, extensions))
}

fn build_extension_configs(
    deployed_extensions: Vec<DeployedExtension>,
    app_id_bare: &str,
    environment_id: &str,
) -> Vec<ExtensionConfig> {
    deployed_extensions
        .into_iter()
        .filter_map(|extension| {
            let DeployedExtension {
                id,
                key,
                extension_type_key,
            } = extension;
            let extension_node_id = id.as_deref().unwrap_or("<missing id>");
            let result = (|| {
                let module_key = key.ok_or("missing key")?;
                let extension_type = extension_type_key.ok_or("missing extensionTypeKey")?;
                let extension_id = format!(
                    "ari:cloud:ecosystem::extension/{app_id_bare}/{environment_id}/static/{module_key}"
                );
                ExtensionConfig::new(extension_id, extension_type)
                    .map_err(|_| "invalid extension ID or type")
            })();

            match result {
                Ok(extension) => Some(extension),
                Err(reason) => {
                    warn!(
                        extension_node_id,
                        reason,
                        "skipping malformed extension response"
                    );
                    None
                }
            }
        })
        .collect()
}

fn select_app_environment<T, F>(
    selection: &EnvironmentSelection,
    mut fetch: F,
) -> Result<T, MintError>
where
    F: FnMut(&str) -> Result<T, MintError>,
{
    match selection {
        EnvironmentSelection::Key(key) => fetch(key),
        EnvironmentSelection::Automatic => match fetch(PRODUCTION_ENVIRONMENT_KEY) {
            Ok(env) => Ok(env),
            Err(MintError::EnvironmentNotFound { .. }) => {
                warn!(
                    "environment '{}' was not found; falling back to '{}'",
                    PRODUCTION_ENVIRONMENT_KEY, DEFAULT_ENVIRONMENT_KEY
                );
                fetch(DEFAULT_ENVIRONMENT_KEY)
            }
            Err(error) => Err(error),
        },
    }
}

pub(crate) fn resolve_app_config(
    agent: &ureq::Agent,
    selection: &EnvironmentSelection,
    product: String,
    cloud_id: String,
    installation_id: String,
    app_id: String,
    app_id_bare: String,
    module_key: String,
) -> Result<AppConfig, MintError> {
    let (environment_key, environment_id, app_version, deployed_extensions) =
        select_app_environment(selection, |key| {
            let variables = serde_json::json!({
                "appId": &app_id,
                "envKey": key,
            });
            let data: AppEnvData = post_graphql(
                agent,
                APP_ENVIRONMENT_OPERATION_NAME,
                APP_ENVIRONMENT_QUERY,
                &variables,
            )?;
            parse_app_environment_response(data, &app_id, key)
        })?;

    let context_id = format!("ari:cloud:{product}::site/{cloud_id}");
    let extensions = build_extension_configs(deployed_extensions, &app_id_bare, &environment_id);
    info!(
        product,
        app_id,
        app_id_bare,
        requested_module_key = module_key,
        extension_count = extensions.len(),
        environment_id,
        environment_key,
        endpoint = GRAPHQL_ENDPOINT,
        "resolved context"
    );

    AppConfig::new(context_id, app_version, extensions, installation_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct HeaderAssertions;

    impl Middleware for HeaderAssertions {
        fn handle(
            &self,
            request: Request<SendBody<'_>>,
            _next: MiddlewareNext<'_>,
        ) -> Result<Response<Body>, ureq::Error> {
            let (response_body, should_have_graphql_headers) = if request.uri() == GRAPHQL_ENDPOINT
            {
                (r#"{"data":{}}"#, true)
            } else {
                assert_eq!(
                    request.uri(),
                    "https://example.atlassian.net/_edge/tenant_info"
                );
                (r#"{"cloudId":"cloud-1"}"#, false)
            };

            let cookie = request
                .headers()
                .get(COOKIE)
                .and_then(|value| value.to_str().ok());
            let origin = request
                .headers()
                .get(ORIGIN)
                .and_then(|value| value.to_str().ok());
            if should_have_graphql_headers {
                assert_eq!(cookie, Some("tenant.session.token=test"));
                assert_eq!(origin, Some(GRAPHQL_ORIGIN));
            } else {
                assert_eq!(cookie, None);
                assert_eq!(origin, None);
            }

            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(Body::builder().data(response_body))
                .unwrap())
        }
    }

    const VALID_CONFIG: &str = r#"site = "https://example.atlassian.net"
product = "jira"
installation_id = "inst-123"
[auth]
raw_cookie_file = "./session-cookie.txt"
"#;

    #[test]
    fn format_duration_buckets() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(3 * 60), "3m");
        assert_eq!(format_duration(2 * 3600 + 5 * 60), "2h 5m");
        assert_eq!(format_duration(3 * 86_400 + 4 * 3600), "3d 4h");
        assert_eq!(format_duration(-45), "45s");
    }

    fn jwt_with_payload(payload: JsonValue) -> String {
        let header = B64_URL.encode(serde_json::json!({ "alg": "RS256" }).to_string());
        let payload = B64_URL.encode(payload.to_string());
        let signature = B64_URL.encode("signature");
        format!("{header}.{payload}.{signature}")
    }

    fn jwt_with_exp(exp: i64) -> String {
        jwt_with_payload(serde_json::json!({ "exp": exp }))
    }

    #[test]
    fn cookie_header_requires_a_readable_nonempty_file() {
        let missing = tempfile::tempdir()
            .unwrap()
            .path()
            .join("missing-cookie.txt");
        let err = build_cookie_header(missing.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("Could not read"), "got: {err}");

        let empty = tempfile::NamedTempFile::new().unwrap();
        let err = build_cookie_header(empty.path().to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("is empty"), "got: {err}");
    }

    #[test]
    fn cookie_header_rejects_malformed_missing_exp_and_expired_cookies() {
        let file = tempfile::NamedTempFile::new().unwrap();

        for (cookie, expected) in [
            ("not-a-jwt".to_string(), "does not contain"),
            (jwt_with_payload(json!({})), "structurally valid JWT"),
        ] {
            std::fs::write(file.path(), cookie).unwrap();
            let err = build_cookie_header(file.path().to_str().unwrap()).unwrap_err();
            assert!(err.to_string().contains(expected), "got: {err}");
        }

        std::fs::write(file.path(), jwt_with_exp(1)).unwrap();
        let err = build_cookie_header(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(err, MintError::CookieExpired(_)), "got: {err}");
    }

    #[test]
    fn cookie_header_accepts_and_normalizes_unexpired_cookies() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let jwt = jwt_with_exp(now + 60);
        let file = tempfile::NamedTempFile::new().unwrap();

        for (raw, expected) in [
            (jwt.clone(), format!("{SESSION_COOKIE_NAME}={jwt}")),
            (format!("  {jwt}  "), format!("{SESSION_COOKIE_NAME}={jwt}")),
            (
                format!("{SESSION_COOKIE_NAME}={jwt}; other=1"),
                format!("{SESSION_COOKIE_NAME}={jwt}; other=1"),
            ),
        ] {
            std::fs::write(file.path(), raw).unwrap();
            assert_eq!(
                build_cookie_header(file.path().to_str().unwrap()).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn http_agent_rejects_an_invalid_cookie_header() {
        let Err(error) = build_http_agent("tenant.session.token=test\ninjected=true".to_string())
        else {
            panic!("invalid cookie header should fail");
        };

        assert!(
            error.to_string().contains("valid HTTP header value"),
            "got: {error}"
        );
    }

    #[test]
    fn graphql_headers_are_scoped_to_the_graphql_endpoint() {
        let headers = GraphqlHeaders::new("tenant.session.token=test".to_string()).unwrap();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .middleware(headers)
            .middleware(HeaderAssertions)
            .build()
            .into();

        assert_eq!(
            fetch_cloud_id(&agent, "https://example.atlassian.net").unwrap(),
            "cloud-1"
        );
        let (status, body) = send_graphql(
            &agent,
            "Test",
            "query Test { value }",
            &json!({ "value": 1 }),
        )
        .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, r#"{"data":{}}"#);
    }

    fn response_agent(status: u16, body: impl Into<String>) -> ureq::Agent {
        let body = body.into();
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .middleware(
                move |_request: Request<SendBody<'_>>, _next: MiddlewareNext<'_>| {
                    Ok(Response::builder()
                        .status(status)
                        .header("Content-Type", "application/json")
                        .body(Body::builder().data(body.clone()))
                        .unwrap())
                },
            )
            .build()
            .into()
    }

    #[test]
    fn post_graphql_returns_typed_data_and_common_errors() {
        #[derive(Debug, Deserialize)]
        struct Data {
            value: u8,
        }

        let variables = json!({ "input": "test" });
        let data: Data = post_graphql(
            &response_agent(200, r#"{"data":{"value":7},"errors":null}"#),
            "Test",
            "query Test { value }",
            &variables,
        )
        .unwrap();
        assert_eq!(data.value, 7);

        for (status, body, expected) in [
            (500, "failure", "Response body: failure"),
            (200, "not JSON", "JSON error"),
            (
                200,
                r#"{"data":{"value":7},"errors":[{"message":"denied"}]}"#,
                "GraphQL operation 'Test' failed: denied",
            ),
            (
                200,
                r#"{"data":null,"errors":[]}"#,
                "GraphQL operation 'Test' failed: response missing data",
            ),
        ] {
            let error = post_graphql::<_, Data>(
                &response_agent(status, body),
                "Test",
                "query Test { value }",
                &variables,
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected), "got: {error}");
        }
    }

    #[test]
    fn tenant_info_requires_a_nonblank_cloud_id() {
        for (cloud_id, expected) in [
            (None, None),
            (Some(""), None),
            (Some("  "), None),
            (Some(" cloud-1 "), Some("cloud-1")),
        ] {
            let body = json!({ "cloudId": cloud_id }).to_string();
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .middleware(
                    move |_request: Request<SendBody<'_>>, _next: MiddlewareNext<'_>| {
                        Ok(Response::builder()
                            .status(200)
                            .header("Content-Type", "application/json")
                            .body(Body::builder().data(body.clone()))
                            .unwrap())
                    },
                )
                .build()
                .into();

            match expected {
                Some(expected) => assert_eq!(
                    fetch_cloud_id(&agent, "https://example.atlassian.net").unwrap(),
                    expected
                ),
                None => {
                    let error =
                        fetch_cloud_id(&agent, "https://example.atlassian.net").unwrap_err();
                    assert!(error.to_string().contains("cloud_id"), "got: {error}");
                }
            }
        }
    }

    fn parse_file_config(input: &str) -> Result<FsrtRemoteConfig, toml::de::Error> {
        toml::from_str(input)
    }

    fn environment(key: &str, id: &str, version: &str) -> (String, String, String) {
        (key.to_string(), id.to_string(), version.to_string())
    }

    fn deployed_environment_data_with_metadata(
        environment_id: JsonValue,
        version: JsonValue,
        extensions: JsonValue,
    ) -> AppEnvData {
        serde_json::from_value(json!({
            "app": {
                "environmentByKey": {
                    "id": environment_id,
                    "versions": {
                        "nodes": [{
                            "version": version,
                            "extensions": extensions
                        }]
                    }
                }
            }
        }))
        .unwrap()
    }

    fn deployed_environment_data(extensions: JsonValue) -> AppEnvData {
        deployed_environment_data_with_metadata(json!("env-1"), json!("2.0.0"), extensions)
    }

    fn extension(id: &str, key: &str, extension_type: &str) -> JsonValue {
        json!({ "id": id, "key": key, "extensionTypeKey": extension_type })
    }

    #[test]
    fn app_environment_nodes_accept_null() {
        let data: AppEnvData = serde_json::from_value(json!({
            "app": {
                "environmentByKey": {
                    "id": "env-1",
                    "versions": { "nodes": null }
                }
            }
        }))
        .unwrap();
        let nodes = data
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
    fn app_environment_requires_a_deployed_version() {
        let data: AppEnvData = serde_json::from_value(json!({
            "app": {
                "environmentByKey": {
                    "id": "env-1",
                    "versions": { "nodes": [] }
                }
            }
        }))
        .unwrap();

        let err = parse_app_environment_response(data, "app-1", "staging")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no deployed app version"), "got: {err}");
    }

    #[test]
    fn app_environment_builds_all_valid_extension_configs() {
        let data = deployed_environment_data(json!({
            "nodes": [
                extension(
                    "4657faf6-3fb3-489f-9262-2fc0ee58a743",
                    "first-module",
                    "jira:issuePanel"
                ),
                {
                    "id": null,
                    "key": "second-module",
                    "extensionTypeKey": "xen:macro"
                },
                { "id": "malformed-id", "key": "missing-type" }
            ]
        }));
        let (environment_key, environment_id, app_version, deployed_extensions) =
            parse_app_environment_response(data, "app-1", "production").unwrap();
        let extensions = build_extension_configs(deployed_extensions, "app-1", &environment_id);

        assert_eq!(environment_key, "production");
        assert_eq!(environment_id, "env-1");
        assert_eq!(app_version, "2.0.0");
        assert_eq!(extensions.len(), 2);
        assert_eq!(
            extensions
                .iter()
                .map(|extension| (extension.extension_id(), extension.extension_type()))
                .collect::<Vec<_>>(),
            [
                (
                    "ari:cloud:ecosystem::extension/app-1/env-1/static/first-module",
                    "jira:issuePanel"
                ),
                (
                    "ari:cloud:ecosystem::extension/app-1/env-1/static/second-module",
                    "xen:macro"
                )
            ]
        );
    }

    #[test]
    fn app_environment_normalizes_environment_id_and_version() {
        let data = deployed_environment_data_with_metadata(
            json!(" env-1 "),
            json!(" 2.0.0 "),
            json!({ "nodes": [extension("id", "module", "type")] }),
        );

        let (_, environment_id, app_version, _) =
            parse_app_environment_response(data, "app-1", "production").unwrap();

        assert_eq!(environment_id, "env-1");
        assert_eq!(app_version, "2.0.0");
    }

    #[test]
    fn app_environment_rejects_blank_environment_id_and_version() {
        for (environment_id, version, expected) in [
            (json!(" "), json!("2.0.0"), "environment id"),
            (json!("env-1"), json!(" "), "app version"),
        ] {
            let data = deployed_environment_data_with_metadata(
                environment_id,
                version,
                json!({ "nodes": [] }),
            );
            let error = parse_app_environment_response(data, "app-1", "production")
                .unwrap_err()
                .to_string();

            assert!(error.contains(expected), "got: {error}");
        }
    }

    #[test]
    fn null_or_missing_extension_nodes_produce_an_empty_snapshot() {
        for extensions in [JsonValue::Null, json!({ "nodes": null })] {
            let data = deployed_environment_data(extensions);
            let (_, _, _, extensions) =
                parse_app_environment_response(data, "app-1", "production").unwrap();
            assert!(extensions.is_empty());
        }
    }

    #[test]
    fn environment_query_requests_deployed_extension_metadata() {
        for field in ["extensions", "extensionTypeKey", "versions(first: 1)"] {
            assert!(APP_ENVIRONMENT_QUERY.contains(field), "missing {field}");
        }
        assert!(APP_ENVIRONMENT_QUERY.contains("environmentByKey(key: $envKey)"));
        assert!(!APP_ENVIRONMENT_QUERY.contains("isLatest"));
    }

    #[test]
    fn configured_environment_key_is_queried_without_fallback() {
        let mut queried = Vec::new();
        let selected =
            select_app_environment(&EnvironmentSelection::Key("staging".to_string()), |key| {
                queried.push(key.to_string());
                Ok(environment(key, "env-staging", "2.0.0"))
            })
            .unwrap();

        assert_eq!(queried, ["staging"]);
        assert_eq!(selected, environment("staging", "env-staging", "2.0.0"));
    }

    #[test]
    fn automatic_environment_falls_back_only_when_production_is_absent() {
        let mut queried = Vec::new();
        let selected = select_app_environment(&EnvironmentSelection::Automatic, |key| {
            queried.push(key.to_string());
            match key {
                PRODUCTION_ENVIRONMENT_KEY => Err(MintError::EnvironmentNotFound {
                    environment_key: key.to_string(),
                    app_id: "app-1".to_string(),
                }),
                DEFAULT_ENVIRONMENT_KEY => Ok(environment(key, "env-default", "1.0.0")),
                _ => unreachable!(),
            }
        })
        .unwrap();

        assert_eq!(
            queried,
            [PRODUCTION_ENVIRONMENT_KEY, DEFAULT_ENVIRONMENT_KEY]
        );
        assert_eq!(
            selected,
            environment(DEFAULT_ENVIRONMENT_KEY, "env-default", "1.0.0")
        );
    }

    #[test]
    fn automatic_environment_does_not_hide_production_query_errors() {
        let mut queried = Vec::new();
        let err = select_app_environment::<(), _>(&EnvironmentSelection::Automatic, |key| {
            queried.push(key.to_string());
            Err(MintError::Config("permission denied".to_string()))
        })
        .unwrap_err()
        .to_string();

        assert_eq!(queried, [PRODUCTION_ENVIRONMENT_KEY]);
        assert!(err.contains("permission denied"), "got: {err}");
    }

    #[test]
    fn config_file_valid_minimal_loads() {
        let file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(file.path(), VALID_CONFIG).unwrap();
        let cfg = FsrtRemoteConfig::from_path(file.path()).expect("minimal config should load");

        assert_eq!(cfg.product, "jira");
        assert_eq!(cfg.installation_id, "inst-123");
        assert_eq!(cfg.auth.raw_cookie_file, "./session-cookie.txt");
        assert_eq!(cfg.environment_key, None);
    }

    #[test]
    fn config_file_requires_non_environment_fields() {
        let cases = [
            ("site = \"https://example.atlassian.net\"\n", "site"),
            ("product = \"jira\"\n", "product"),
            ("installation_id = \"inst-123\"\n", "installation_id"),
            (
                "[auth]\nraw_cookie_file = \"./session-cookie.txt\"\n",
                "auth",
            ),
            (
                "raw_cookie_file = \"./session-cookie.txt\"\n",
                "raw_cookie_file",
            ),
        ];

        for (line, field) in cases {
            let err = parse_file_config(&VALID_CONFIG.replace(line, ""))
                .unwrap_err()
                .to_string();
            assert!(err.contains(field), "missing {field} in: {err}");
        }
    }

    #[test]
    fn config_file_rejects_unknown_fields() {
        for input in [
            VALID_CONFIG.replace("product =", "unknown = \"value\"\nproduct ="),
            VALID_CONFIG.replace(
                "raw_cookie_file =",
                "unknown = \"value\"\nraw_cookie_file =",
            ),
        ] {
            assert!(
                parse_file_config(&input)
                    .unwrap_err()
                    .to_string()
                    .contains("unknown field")
            );
        }
    }
}
