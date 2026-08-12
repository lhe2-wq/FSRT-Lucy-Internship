use std::{fs, path::PathBuf};

use clap::{Args, ValueHint};

use crate::{Result, forge_project::find_manifest_path};

/// `mint-fct` arguments.
#[derive(Args, Debug)]
pub(crate) struct MintFctArgs {
    /// Deployed module key.
    #[arg(name = "MODULE_KEY")]
    module_key: String,

    /// Forge app directory.
    #[arg(long, default_value = ".", value_hint = ValueHint::DirPath)]
    app_dir: PathBuf,

    /// Path to `fsrt-remote.toml`.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// Query metadata and print variables without minting.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

impl MintFctArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        self.dry_run
    }
}

pub(super) fn run(args: &MintFctArgs) -> Result<()> {
    let manifest_path = find_manifest_path(&args.app_dir)?;
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest: forge_loader::manifest::ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let tester = forge_pen_test::ForgePenTester::new(&manifest, config, &args.module_key)?;
    if args.dry_run {
        let config = tester.config();
        let extension = config.extension_for_module_key(&args.module_key)?;
        let variables = serde_json::json!({
            "input": {
                "contextIds": [config.context_id()],
                "extensionContexts": [{
                    "appVersion": config.app_version(),
                    "context": {},
                    "extensionId": extension.extension_id(),
                    "extensionType": extension.extension_type(),
                    "installationId": config.installation_id()
                }]
            }
        });
        println!("{}", serde_json::to_string_pretty(&variables)?);
    } else {
        println!("{}", tester.mint_fct(&args.module_key)?);
    }

    Ok(())
}
