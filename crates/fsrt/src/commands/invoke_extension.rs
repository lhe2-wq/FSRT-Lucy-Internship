use std::{fs, path::PathBuf};

use clap::{Args, ValueHint};
use serde_json::Value as JsonValue;

use crate::{Result, forge_project::find_manifest_path};

/// `invoke-extension` arguments.
#[derive(Args, Debug)]
pub(crate) struct InvokeExtensionArgs {
    /// Resolver function key to invoke.
    #[arg(long, required = true)]
    function: String,

    /// Invocation payload as JSON.
    #[arg(long, required = true)]
    payload: String,

    /// Deployed module key. Defaults to the module wired to `--function`.
    #[arg(long)]
    module_key: Option<String>,

    /// Override `payload.context` with a JSON object.
    #[arg(long)]
    context: Option<String>,

    /// Reuse this FCT instead of minting one.
    #[arg(long)]
    fct: Option<String>,

    /// Invoke asynchronously when supported.
    #[arg(long = "async", default_value_t = false)]
    invoke_async: bool,

    /// Forge app directory.
    #[arg(long, default_value = ".", value_hint = ValueHint::DirPath)]
    app_dir: PathBuf,

    /// Path to `fsrt-remote.toml`.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// Resolve metadata and print variables without invoking the extension.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

impl InvokeExtensionArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        self.dry_run
    }
}

pub(super) fn run(args: &InvokeExtensionArgs) -> Result<()> {
    let payload: JsonValue = serde_json::from_str(&args.payload).map_err(|error| {
        forge_pen_test::MintError::Config(format!("--payload is not valid JSON: {error}"))
    })?;

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
                .detect_fct_module_for_function(args.function.trim())
                .map(|(module_key, _)| module_key)
        })
        .or_else(|| {
            manifest
                .modules
                .detect_fct_module()
                .map(|(module_key, _)| module_key)
        })
        .ok_or_else(|| {
            forge_pen_test::MintError::Config(
                "No supported Forge module was found; pass --module-key explicitly".to_string(),
            )
        })?;

    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let tester = forge_pen_test::ForgePenTester::new(&manifest, config, module_key)?;
    let context = match &args.context {
        Some(raw) => {
            let context: JsonValue = serde_json::from_str(raw).map_err(|error| {
                forge_pen_test::MintError::Config(format!("--context is not valid JSON: {error}"))
            })?;
            if !context.is_object() {
                return Err(forge_pen_test::MintError::Config(
                    "--context must be a JSON object".to_string(),
                )
                .into());
            }
            context
        }
        None => tester.default_invoke_context(module_key)?,
    };

    if args.dry_run {
        let variables = tester.build_invoke_variables(
            module_key,
            &args.function,
            &payload,
            &context,
            args.fct.as_deref().unwrap_or("<FCT JWT minted at runtime>"),
            args.invoke_async,
        )?;
        println!("{}", serde_json::to_string_pretty(&variables)?);
    } else {
        let outcome = tester.invoke_extension(
            module_key,
            &args.function,
            &payload,
            &context,
            args.fct.as_deref(),
            args.invoke_async,
        )?;
        match outcome.response() {
            Some(response) => println!("{}", serde_json::to_string_pretty(response)?),
            None => println!("null"),
        }
    }

    Ok(())
}
