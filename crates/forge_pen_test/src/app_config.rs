//! Finalized values for an FCT request.

use crate::mint_common::MintError;

/// A deployed Forge extension available for FCT minting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionConfig {
    extension_id: String,
    extension_type: String,
}

impl ExtensionConfig {
    pub(crate) fn new(extension_id: String, extension_type: String) -> Result<Self, MintError> {
        let extension_id = require_value("extension_id", extension_id)?;
        let extension_type = require_value("extension_type", extension_type)?;

        let valid_extension = extension_id
            .strip_prefix("ari:cloud:ecosystem::extension/")
            .is_some_and(|value| {
                let mut parts = value.split('/');
                matches!(
                    (
                        parts.next(),
                        parts.next(),
                        parts.next(),
                        parts.next(),
                        parts.next(),
                    ),
                    (Some(app_id), Some(environment_id), Some("static"), Some(module_key), None)
                        if !app_id.is_empty()
                            && !environment_id.is_empty()
                            && !module_key.is_empty()
                )
            });
        if !valid_extension {
            return Err(MintError::Config(format!(
                "invalid extension_id '{extension_id}': expected ari:cloud:ecosystem::extension/<app_id>/<environment_id>/static/<module_key>"
            )));
        }

        Ok(Self {
            extension_id,
            extension_type,
        })
    }

    /// Returns the extension ARI.
    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    /// Returns the deployed extension type.
    pub fn extension_type(&self) -> &str {
        &self.extension_type
    }

    /// Returns the module key encoded in the extension ARI.
    pub fn module_key(&self) -> &str {
        self.extension_id
            .rsplit_once('/')
            .map(|(_, module_key)| module_key)
            .expect("validated extension ID contains a module key")
    }

    /// Returns the environment ID encoded in the extension ARI.
    pub fn environment_id(&self) -> &str {
        self.extension_id
            .strip_prefix("ari:cloud:ecosystem::extension/")
            .and_then(|value| value.split('/').nth(1))
            .expect("validated extension ID contains an environment ID")
    }
}

/// Values required to build FCT mutation variables.
#[derive(Debug)]
pub struct AppConfig {
    context_id: String,
    app_version: String,
    extensions: Vec<ExtensionConfig>,
    installation_id: String,
}

impl AppConfig {
    pub(crate) fn new(
        context_id: String,
        app_version: String,
        extensions: Vec<ExtensionConfig>,
        installation_id: String,
    ) -> Result<Self, MintError> {
        let context_id = require_value("context_id", context_id)?;
        let app_version = require_value("app_version", app_version)?;
        let installation_id = require_value("installation_id", installation_id)?;

        let context = context_id
            .strip_prefix("ari:cloud:")
            .and_then(|value| value.split_once("::site/"));
        if !matches!(context, Some((product, cloud_id)) if !product.is_empty() && !cloud_id.is_empty() && !cloud_id.contains('/'))
        {
            return Err(MintError::Config(format!(
                "invalid context_id '{context_id}': expected ari:cloud:<product>::site/<cloud_id>"
            )));
        }

        Ok(Self {
            context_id,
            app_version,
            extensions,
            installation_id,
        })
    }

    /// Returns the context ARI.
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the deployed app version.
    pub fn app_version(&self) -> &str {
        &self.app_version
    }

    /// Returns all deployed extensions captured during tester construction.
    pub fn extensions(&self) -> &[ExtensionConfig] {
        &self.extensions
    }

    /// Returns the single deployed extension matching `module_key`.
    pub fn extension_for_module_key(
        &self,
        module_key: &str,
    ) -> Result<&ExtensionConfig, MintError> {
        let module_key = module_key.trim();
        if module_key.is_empty() {
            return Err(MintError::Config(
                "a non-empty module_key is required (usage: fsrt mint-fct <module_key>)"
                    .to_string(),
            ));
        }

        let mut matches = self
            .extensions
            .iter()
            .filter(|extension| extension.module_key() == module_key);
        let Some(extension) = matches.next() else {
            let available = if self.extensions.is_empty() {
                "none".to_string()
            } else {
                self.extensions
                    .iter()
                    .map(|extension| {
                        format!(
                            "{} (id: {})",
                            extension.module_key(),
                            extension.extension_id()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            return Err(MintError::Config(format!(
                "Module key '{module_key}' was not found in deployed extensions. Available extensions: {available}"
            )));
        };

        if let Some(duplicate) = matches.next() {
            let ids = std::iter::once(extension)
                .chain(std::iter::once(duplicate))
                .chain(matches)
                .map(ExtensionConfig::extension_id)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(MintError::Config(format!(
                "Module key '{module_key}' matched multiple deployed extensions. Extension ids: {ids}"
            )));
        }

        Ok(extension)
    }

    /// Returns the Forge installation ID.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Returns the product encoded in the context ARI.
    pub fn product(&self) -> &str {
        self.context_id
            .strip_prefix("ari:cloud:")
            .and_then(|value| value.split_once("::site/"))
            .map(|(product, _)| product)
            .expect("validated context ID contains a product")
    }

    /// Returns the cloud ID encoded in the context ARI.
    pub fn cloud_id(&self) -> &str {
        self.context_id
            .split_once("::site/")
            .map(|(_, cloud_id)| cloud_id)
            .expect("validated context ID contains a cloud ID")
    }

    /// Builds the shared FCT signing variables for a deployed module.
    pub fn build_fct_variables(&self, module_key: &str) -> Result<serde_json::Value, MintError> {
        let extension = self.extension_for_module_key(module_key)?;
        Ok(serde_json::json!({
            "input": {
                "contextIds": [self.context_id()],
                "extensionContexts": [{
                    "appVersion": self.app_version(),
                    "context": {},
                    "extensionId": extension.extension_id(),
                    "extensionType": extension.extension_type(),
                    "installationId": self.installation_id()
                }]
            }
        }))
    }
}

fn require_value(name: &str, value: String) -> Result<String, MintError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(MintError::Config(format!("{name} must not be empty")))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_ID: &str = "ari:cloud:ecosystem::extension/app-1/environment-1/static/first-module";
    const SECOND_ID: &str =
        "ari:cloud:ecosystem::extension/app-1/environment-1/static/second-module";

    fn extension(id: &str, extension_type: &str) -> ExtensionConfig {
        ExtensionConfig::new(id.into(), extension_type.into()).unwrap()
    }

    fn config(extensions: Vec<ExtensionConfig>) -> AppConfig {
        AppConfig::new(
            "ari:cloud:jira::site/cloud-1".into(),
            "1.0.0".into(),
            extensions,
            "installation-1".into(),
        )
        .unwrap()
    }

    #[test]
    fn extension_config_rejects_blank_values_and_malformed_ids() {
        for (id, extension_type, expected) in [
            (" ", "jira:issuePanel", "extension_id"),
            (FIRST_ID, " ", "extension_type"),
            ("invalid", "jira:issuePanel", "extension_id"),
        ] {
            let error = ExtensionConfig::new(id.into(), extension_type.into()).unwrap_err();
            assert!(error.to_string().contains(expected), "got: {error}");
        }
    }

    #[test]
    fn app_config_exposes_and_selects_multiple_extensions() {
        let config = config(vec![
            extension(FIRST_ID, "jira:issuePanel"),
            extension(SECOND_ID, "xen:macro"),
        ]);

        assert_eq!(config.extensions().len(), 2);
        assert_eq!(
            config
                .extension_for_module_key(" second-module ")
                .unwrap()
                .extension_type(),
            "xen:macro"
        );
        assert_eq!(config.product(), "jira");
        assert_eq!(config.cloud_id(), "cloud-1");
        assert_eq!(config.extensions()[0].module_key(), "first-module");
        assert_eq!(config.extensions()[0].environment_id(), "environment-1");
    }

    #[test]
    fn app_config_reports_empty_missing_and_duplicate_extensions() {
        for (extensions, module_key, expected) in [
            (vec![], "first-module", "Available extensions: none"),
            (
                vec![extension(FIRST_ID, "jira:issuePanel")],
                "missing-module",
                "first-module",
            ),
            (
                vec![
                    extension(FIRST_ID, "jira:issuePanel"),
                    extension(FIRST_ID, "jira:issuePanel"),
                ],
                "first-module",
                "multiple deployed extensions",
            ),
        ] {
            let error = config(extensions)
                .extension_for_module_key(module_key)
                .unwrap_err();
            assert!(error.to_string().contains(expected), "got: {error}");
        }
    }

    #[test]
    fn app_config_rejects_blank_values_and_malformed_context_aris() {
        for (context, version, installation, expected) in [
            (" ", "1.0.0", "installation-1", "context_id"),
            (
                "ari:cloud:jira::site/cloud-1",
                " ",
                "installation-1",
                "app_version",
            ),
            (
                "ari:cloud:jira::site/cloud-1",
                "1.0.0",
                " ",
                "installation_id",
            ),
            ("invalid", "1.0.0", "installation-1", "context_id"),
        ] {
            let error = AppConfig::new(context.into(), version.into(), vec![], installation.into())
                .unwrap_err();
            assert!(error.to_string().contains(expected), "got: {error}");
        }
    }
}
