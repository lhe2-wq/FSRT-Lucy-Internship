//! Forge Invocation Token minting.

use serde::Deserialize;

use crate::{ForgePenTester, MintError};

const FIT_MUTATION: &str = r#"mutation SignInvocationTokenForUI($input: SignInvocationTokenForUIInput!) {
  signInvocationTokenForUI(input: $input) {
    forgeInvocationToken {
      jwt
      expiresAt
    }
  }
}"#;

const FIT_OPERATION_NAME: &str = "SignInvocationTokenForUI";

#[derive(Debug, Deserialize)]
struct FitData {
    #[serde(rename = "signInvocationTokenForUI")]
    result: Option<FitResult>,
}

#[derive(Debug, Deserialize)]
struct FitResult {
    #[serde(rename = "forgeInvocationToken")]
    token: Option<ForgeInvocationToken>,
}

/// A minted Forge Invocation Token.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ForgeInvocationToken {
    jwt: String,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
}

impl ForgeInvocationToken {
    /// Returns the FIT JWT.
    pub fn jwt(&self) -> &str {
        &self.jwt
    }

    /// Returns the server-provided expiry timestamp, when present.
    pub fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }
}

impl ForgePenTester<'_, '_> {
    /// Builds FIT signing variables without sending the mutation.
    pub fn build_fit_variables(
        &self,
        remote_key: &str,
        forge_context_token: &str,
    ) -> Result<serde_json::Value, MintError> {
        let remote_key = remote_key.trim();
        if remote_key.is_empty() {
            return Err(MintError::Config(
                "a non-empty remote key is required for FIT minting".to_string(),
            ));
        }
        let forge_context_token = forge_context_token.trim();
        if forge_context_token.is_empty() {
            return Err(MintError::Config(
                "a non-empty Forge Context Token is required for FIT minting".to_string(),
            ));
        }

        Ok(serde_json::json!({
            "input": {
                "forgeContextToken": forge_context_token,
                "remoteKey": remote_key,
            }
        }))
    }

    /// Mints an FCT for `module_key`, then exchanges it for a FIT.
    pub fn mint_fit(
        &self,
        module_key: &str,
        remote_key: &str,
    ) -> Result<ForgeInvocationToken, MintError> {
        let fct = self.mint_fct(module_key)?;
        let variables = self.build_fit_variables(remote_key, &fct)?;
        let data: FitData = self.post_graphql(FIT_OPERATION_NAME, FIT_MUTATION, &variables)?;

        let token = data.result.and_then(|result| result.token).ok_or_else(|| {
            MintError::FitFailed(
                "response missing data.signInvocationTokenForUI.forgeInvocationToken".to_string(),
            )
        })?;
        if token.jwt.trim().is_empty() {
            return Err(MintError::FitFailed(
                "response contained an empty Forge Invocation Token".to_string(),
            ));
        }
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_token_accessors_preserve_response_values() {
        let token: ForgeInvocationToken = serde_json::from_value(serde_json::json!({
            "jwt": "token",
            "expiresAt": "1234"
        }))
        .unwrap();

        assert_eq!(token.jwt(), "token");
        assert_eq!(token.expires_at(), Some("1234"));
    }
}
