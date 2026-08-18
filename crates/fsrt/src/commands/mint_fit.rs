use std::{fs, path::PathBuf};

use clap::{Args, ValueHint};

use crate::{Result, forge_project::find_manifest_path};

/// `mint-fit` arguments.
#[derive(Args, Debug)]
pub(crate) struct MintFitArgs {
    /// Optional override. Required only when no supported manifest module can be detected.
    #[arg(name = "MODULE_KEY")]
    module_key: Option<String>,

    /// Optional override. Required only when no Forge Remote can be detected.
    #[arg(long)]
    remote_key: Option<String>,

    /// Optional. Reuse this FCT instead of minting one.
    #[arg(long)]
    fct: Option<String>,

    /// Optional. Forge app directory containing the manifest.
    #[arg(long, default_value = ".", value_hint = ValueHint::DirPath)]
    app_dir: PathBuf,

    /// Optional. Path to the required `fsrt-remote.toml` config.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// Optional. Resolve metadata and print variables without minting tokens.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

impl MintFitArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        self.dry_run
    }
}

pub(super) fn run(args: &MintFitArgs) -> Result<()> {
    let manifest_path = find_manifest_path(&args.app_dir)?;
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest: forge_loader::manifest::ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    let module_key = args
        .module_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .or_else(|| {
            manifest
                .modules
                .detect_fct_module()
                .map(|(module_key, _)| module_key)
        })
        .ok_or_else(|| {
            forge_pen_test::MintError::Config(
                "No supported Forge module was found; pass MODULE_KEY explicitly".to_string(),
            )
        })?;
    let remote_key = args
        .remote_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .or_else(|| manifest.detect_remote_key())
        .ok_or_else(|| {
            forge_pen_test::MintError::Config(
                "No Forge Remote was found; pass --remote-key explicitly".to_string(),
            )
        })?;
    let provided_fct = match args.fct.as_deref() {
        Some(fct) if fct.trim().is_empty() => {
            return Err(
                forge_pen_test::MintError::Config("--fct must not be empty".to_string()).into(),
            );
        }
        Some(fct) => Some(fct.trim()),
        None => None,
    };

    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let tester = forge_pen_test::ForgePenTester::new(&manifest, config, module_key)?;
    if args.dry_run {
        let fct_preview = if provided_fct.is_some() {
            "<provided FCT redacted>"
        } else {
            "<FCT JWT minted at runtime>"
        };
        let variables = tester.build_fit_variables(remote_key, fct_preview)?;
        println!("{}", serde_json::to_string_pretty(&variables)?);
    } else {
        let token = match provided_fct {
            Some(fct) => tester.mint_fit_with_fct(remote_key, fct)?,
            None => tester.mint_fit(module_key, remote_key)?,
        };
        println!("{}", token.jwt());
        if let Some(expires_at) = token.expires_at() {
            tracing::info!(expires_at, "minted Forge Invocation Token");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use crate::{Args as RootArgs, commands::Command};

    #[test]
    fn parses_fct_override() {
        let args = RootArgs::try_parse_from([
            "fsrt",
            "mint-fit",
            "module-key",
            "--remote-key",
            "backend",
            "--fct",
            "provided-token",
        ])
        .unwrap();

        let Some(Command::MintFit(args)) = args.command else {
            panic!("expected mint-fit command");
        };
        assert_eq!(args.fct.as_deref(), Some("provided-token"));
    }

    #[test]
    fn help_explains_required_and_optional_inputs() {
        let mut command = RootArgs::command();
        let help = command
            .find_subcommand_mut("mint-fit")
            .expect("mint-fit subcommand should exist")
            .render_long_help()
            .to_string();

        assert!(help.contains("Required at runtime:"));
        assert!(help.contains("Optional:"));
        assert!(help.contains("Required only when no supported manifest module can be detected"));
        assert!(help.contains("Required only when no Forge Remote can be detected"));
    }
}
