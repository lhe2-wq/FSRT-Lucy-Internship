use clap::Subcommand;

use crate::Result;

pub(crate) mod mint_fct;
pub(crate) mod mint_fit;

/// CLI subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Mint an FCT for a deployed module.
    MintFct(mint_fct::MintFctArgs),

    /// Mint a Forge Invocation Token for a remote backend.
    MintFit(mint_fit::MintFitArgs),
}

impl Command {
    pub(crate) fn diagnostic_logging_requested(&self) -> bool {
        match self {
            Self::MintFct(args) => args.diagnostic_logging_requested(),
            Self::MintFit(args) => args.diagnostic_logging_requested(),
        }
    }

    pub(crate) fn run(&self) -> Result<()> {
        match self {
            Self::MintFct(args) => mint_fct::run(args),
            Self::MintFit(args) => mint_fit::run(args),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Command;
    use crate::Args;

    #[test]
    fn verbose_is_global() {
        for (argv, has_command) in [
            (vec!["fsrt", "--verbose"], false),
            (vec!["fsrt", "--verbose", "mint-fct", "module-key"], true),
            (vec!["fsrt", "mint-fct", "module-key", "--verbose"], true),
        ] {
            let args = Args::try_parse_from(argv).unwrap();
            assert!(args.verbose);
            assert_eq!(args.command.is_some(), has_command);
        }
    }

    #[test]
    fn debug_flags_remain_independent() {
        for flag in ["--debug", "-d"] {
            let args = Args::try_parse_from(["fsrt", flag])
                .unwrap_or_else(|err| panic!("{flag} should still parse: {err}"));

            assert!(args.debug);
            assert!(!args.verbose);
        }
    }

    #[test]
    fn mint_fct_dry_run_requests_diagnostic_logging() {
        let args = Args::try_parse_from(["fsrt", "mint-fct", "module-key", "--dry-run"])
            .expect("mint-fct dry-run should parse");

        assert!(!args.verbose);
        assert!(
            args.command
                .as_ref()
                .is_some_and(Command::diagnostic_logging_requested)
        );
    }
}
