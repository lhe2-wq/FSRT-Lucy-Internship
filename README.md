# FSRT - Forge Security Requirements Tester

[![Apache license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE) [![MIT license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE-MIT) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

A static analysis tool for finding common [Forge][1] vulnerabilities.

[1]: https://developer.atlassian.com/platform/forge "Forge platform"

## Usage

```text
Usage: fsrt [OPTIONS] [DIRS]... [COMMAND]

Arguments:
  [DIRS]...  The directory to scan. Assumes there is a `manifest.yaml` file in the top level directory, and that the source code is located in `src/`

Commands:
  mint-fct          Mint an FCT for a deployed module
  mint-fit          Mint a Forge Invocation Token for a remote backend
  invoke-extension  Invoke a resolver-backed extension
  mint-cookie       Harvest a browser session cookie (requires `--features mint_cookie`)

  Options:
    -d, --debug
        --dump-ir <DUMP_IR>                 Dump the IR for the specified function
    -dt, --dump-dt <DUMP_DOM_TREE>          Dump the Dominator Tree for the specified app
    -f, --function <FUNCTION>               A specific function to scan, must be an entrypoint specified in `manifest.yml`
    -h, --help                              Print help information
    -V, --version                           Print version information
    --verbose                               Print diagnostics to stderr
    --check-permissions                     Runs the permission checker
    --cached-permissions                    Uses cached swagger permissions to avoid redownloading them
    --cached-permissions-path <LOCATION>    Uses the designated cache location, otherwise selects ~/.cache dir
    --graphql-schema-path <LOCATION>        Uses the graphql schema in location; othwerwise selects ~/.config dir
```

Run `fsrt --help` or `fsrt <COMMAND> --help` for current options.

## Installation

You will need to install [Rust] to compile `FSRT`. You can install `Rust` through [Rustup] or through your distro's package manager. You will also
need [Cargo], which comes by default with most `Rust toolchains`.[^1]
latest stable release, and adding the toolchain

[^1]: Cargo is technically not required if you want to download every dependency, invoke `rustc`, and link everything manually. However, I wouldn't recommend doing this unless you're extremely bored.

[Rust]: https://www.rust-lang.org/
[Rustup]: https://github.com/rust-lang/rustup "Rustup"
[Cargo]: https://github.com/rust-lang/cargo

Installing from source:

```sh
git clone https://github.com/atlassian-labs/FSRT.git
cd FSRT
cargo install --path crates/fsrt --locked
```

or alternatively:

```text
cargo install --git https://github.com/atlassian-labs/FSRT --locked
```

## Forge tooling commands

The dynamic-testing commands share a TOML configuration (default
`./fsrt-remote.toml`) and deployment-resolution client. Start from
[`fsrt-remote.toml.example`](fsrt-remote.toml.example). See
[`FORGE_TOOLING.md`](FORGE_TOOLING.md) for the architecture, request flows, and
security boundaries.

- `mint-fct <MODULE_KEY>` mints a Forge Context Token for a deployed module.
- `mint-fit [MODULE_KEY]` mints an FCT and exchanges it for a Forge Invocation
  Token. Pass `--fct <JWT>` to exchange an existing FCT instead. The module and
  Forge Remote can be detected from `manifest.yml` or supplied explicitly.
- `invoke-extension --function <KEY> --payload <JSON>` invokes a resolver with a
  tester-controlled payload. Use `--dry-run` to inspect the request variables.
- `mint-cookie` drives Chrome to harvest `tenant.session.token`. Build FSRT with
  `--features mint_cookie` and supply the account password through
  `ATL_PASSWORD`; the password is never accepted as a CLI argument.

Dry runs resolve live deployment metadata but skip token signing and invocation.
`site` must be a full `https://<site>.atlassian.net` URL. `installation_id` and
`[auth].raw_cookie_file` are required. Cookie files and `fsrt-remote.toml`
contain authentication or tenant-specific data and must not be committed.

## Tests

To run the test suite:

```sh
cargo test
```

There are also two sample vulnerable Forge apps for testing. In the future these will be added to the test-suite, but
until then you can test `fsrt` by manually invoking:

```sh
fsrt ./test-apps/jira-damn-vulnerable-forge-app
```

Testing with a GraphQl Schema:

```sh
cargo test --features graphql_schema
```

## Contributions

Contributions to FSRT are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Copyright (c) 2022 Atlassian and others.

FSRT is dual licensed under the MIT and Apache 2.0 licenses.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[![With â¤ï¸ from Atlassian](https://raw.githubusercontent.com/atlassian-internal/oss-assets/master/banner-cheers.png)](https://www.atlassian.com)
