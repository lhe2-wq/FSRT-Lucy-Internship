//! Direct Forge resolver invocation support.

use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::{ForgePenTester, MintError};

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
const RESOLVER_ENTRY_POINT: &str = "resolver";

#[derive(Debug, Deserialize)]
struct InvokeData {
    #[serde(rename = "invokeExtension")]
    result: Option<InvokeResult>,
}

#[derive(Debug, Deserialize)]
struct InvokeResult {
    #[serde(default)]
    success: bool,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    errors: Vec<InvokeError>,
    response: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
struct InvokeError {
    message: Option<String>,
}

fn deserialize_null_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// Successful `invokeExtension` response.
#[derive(Debug, Clone, PartialEq)]
pub struct InvocationOutcome {
    response: Option<JsonValue>,
}

impl InvocationOutcome {
    /// Returns the backend response, when one was returned.
    pub fn response(&self) -> Option<&JsonValue> {
        self.response.as_ref()
    }
}

impl ForgePenTester<'_, '_> {
    /// Builds a useful default `payload.context` from resolved deployment data.
    pub fn default_invoke_context(&self, module_key: &str) -> Result<JsonValue, MintError> {
        let extension = self.config().extension_for_module_key(module_key)?;
        Ok(serde_json::json!({
            "appVersion": self.config().app_version(),
            "cloudId": self.config().cloud_id(),
            "environmentId": extension.environment_id(),
            "extension": { "type": extension.extension_type() },
            "moduleKey": extension.module_key(),
            "siteUrl": self.site(),
        }))
    }

    /// Builds the exact GraphQL variables used by `invokeExtension`.
    pub fn build_invoke_variables(
        &self,
        module_key: &str,
        function_key: &str,
        extension_payload: &JsonValue,
        context: &JsonValue,
        context_token: &str,
        invoke_async: bool,
    ) -> Result<JsonValue, MintError> {
        let extension = self.config().extension_for_module_key(module_key)?;
        let function_key = function_key.trim();
        if function_key.is_empty() {
            return Err(MintError::Config(
                "a non-empty resolver function key is required".to_string(),
            ));
        }
        if !context.is_object() {
            return Err(MintError::Config(
                "invocation context must be a JSON object".to_string(),
            ));
        }
        let context_token = context_token.trim();
        if context_token.is_empty() {
            return Err(MintError::Config(
                "a non-empty Forge Context Token is required for invocation".to_string(),
            ));
        }

        Ok(serde_json::json!({
            "input": {
                "async": invoke_async,
                "contextIds": [self.config().context_id()],
                "entryPoint": RESOLVER_ENTRY_POINT,
                "extensionId": extension.extension_id(),
                "payload": {
                    "call": {
                        "functionKey": function_key,
                        "payload": extension_payload,
                    },
                    "context": context,
                    "contextToken": context_token,
                }
            }
        }))
    }

    /// Mints or reuses an FCT and invokes a resolver-backed extension.
    pub fn invoke_extension(
        &self,
        module_key: &str,
        function_key: &str,
        extension_payload: &JsonValue,
        context: &JsonValue,
        context_token: Option<&str>,
        invoke_async: bool,
    ) -> Result<InvocationOutcome, MintError> {
        let minted_token;
        let context_token = match context_token {
            Some(token) => token,
            None => {
                minted_token = self.mint_fct(module_key)?;
                &minted_token
            }
        };
        let variables = self.build_invoke_variables(
            module_key,
            function_key,
            extension_payload,
            context,
            context_token,
            invoke_async,
        )?;
        let data: InvokeData =
            self.post_graphql(INVOKE_OPERATION_NAME, INVOKE_MUTATION, &variables)?;
        let result = data.result.ok_or_else(|| {
            MintError::InvocationFailed("response missing data.invokeExtension".to_string())
        })?;
        if !result.success {
            let messages = result
                .errors
                .into_iter()
                .filter_map(|error| error.message)
                .collect::<Vec<_>>();
            return Err(MintError::InvocationFailed(if messages.is_empty() {
                "server returned success=false without an error message".to_string()
            } else {
                messages.join("; ")
            }));
        }

        Ok(InvocationOutcome {
            response: result.response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_error_arrays_are_accepted() {
        let data: InvokeData = serde_json::from_value(serde_json::json!({
            "invokeExtension": {
                "success": true,
                "errors": null,
                "response": { "body": { "ok": true } }
            }
        }))
        .unwrap();

        let result = data.result.unwrap();
        assert!(result.success);
        assert!(result.errors.is_empty());
    }
}
