# FSRT - Forge Security Requirements Tester

[![Apache license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE) [![MIT license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE-MIT) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

A static analysis tool for finding common [Forge][1] vulnerabilities.

[1]: https://developer.atlassian.com/platform/forge "Forge platform"

## Usage

`fsrt` has two subcommands: `scan` (the default) and `mint-fct`.

### Scanning a Forge app for vulnerabilities

```sh
# Scan a specific directory
fsrt ./path/to/your-forge-app

# Scan with a specific GraphQL schema
fsrt --graphql-schema-path ./path/to/schema.graphql ./path/to/your-forge-app

# Scan and write results to a file instead of stdout
fsrt --out results.json ./path/to/your-forge-app

# Scan a specific entrypoint function only
fsrt --function myResolverFunction ./path/to/your-forge-app
```

Full options:

```text
Usage: fsrt [OPTIONS] [DIRS]... [COMMAND]

Arguments:
  [DIRS]...  The directory to scan. Assumes there is a `manifest.ya?ml` file in the top
             level directory, and that the source code is located in `src/`

Options:
  -d, --debug
      --dump-ir <DUMP_IR>                                  Dump the IR for the specified function
      --dump-dt <DUMP_DT>                                  Dump the Dominator Tree for specified file
  -f, --function <FUNCTION>                                A specific function to scan. Must be an
                                                           entrypoint specified in `manifest.yml`
      --appkey <APPKEY>                                    The Marketplace app key
  -o, --out <OUT>                                          A file to redirect output to
      --graphql-schema-path <GRAPHQL_SCHEMA_PATH>
      --no-cache                                           Disable cached permissions and re-download
                                                           Swagger files
      --cached-permissions-path <CACHED_PERMISSIONS_PATH>  Path to store or load cached permissions.
                                                           Defaults to `~/.cache/fsrt`
      --scanners <SCANNERS>                                List of scanners to enable. Defaults to all
      --scan-functions                                     Scan all function/closure bodies for
                                                           auth-header issues
  -h, --help                                               Print help
  -V, --version                                            Print version
```

### Minting a Forge Context Token (FCT) — `mint-fct`

The `mint-fct` subcommand is a Rust port of `scripts/mint_fct_spike.py`. It mints a
Forge Context Token (FCT) for a Confluence Forge app by sending a GraphQL mutation to
the Atlassian gateway. This is useful for security testing and local investigation of
FCT-authenticated endpoints.

```sh
fsrt mint-fct --app-dir <APP_DIR> --config <CONFIG> [--dry-run]
```

```text
Options:
      --app-dir <APP_DIR>  Forge app directory containing manifest.yml  [required]
      --config <CONFIG>    Path to the FCT config YAML file             [required]
      --dry-run            Print request details but do not call GraphQL
  -h, --help               Print help
```

#### Step 1 — Choose a config file

Two example config files are provided in `scripts/`:

| File | When to use |
|---|---|
| `scripts/mint_fct_min_info.confluence.yaml` | Start here — only the confirmed-required fields |
| `scripts/mint_fct_full_info.confluence.yaml` | Full field set, mirrors a live Burp capture |

Copy the one you want and fill in your values:

```sh
cp scripts/mint_fct_min_info.confluence.yaml my-config.yaml
```

#### Step 2 — Fill in the config

The config requires these values (see comments inside the file for how to find each one):

```yaml
product: confluence
graphql_endpoint: "https://YOUR-SITE.atlassian.net/gateway/api/graphql"

auth:
  # Option A: raw cookie from Burp/DevTools (~30 day lifetime, confirmed working)
  type: raw_cookie
  raw_cookie_file: "./session-cookie.txt"   # paste your full Cookie header here

  # Option B: Atlassian API token (generate at id.atlassian.com)
  # type: basic_api_token
  # email: "you@atlassian.com"
  # api_token_file: "./api-token.txt"

confluence:
  cloud_id: "..."          # curl https://YOUR-SITE.atlassian.net/_edge/tenant_info
  installation_id: "..."   # forge install list --json → installationId
  environment_id: "..."    # forge install list --json or forge environments list
```

#### Step 3 — Dry run first

Always verify the rendered request before sending it:

```sh
fsrt mint-fct \
  --app-dir ./path/to/your-forge-app \
  --config ./my-config.yaml \
  --dry-run
```

This prints the manifest context, the rendered GraphQL variables, and the auth headers
**without making any network request**. Verify the values look correct.

#### Step 4 — Mint the token

```sh
fsrt mint-fct \
  --app-dir ./path/to/your-forge-app \
  --config ./my-config.yaml
```

On success, the JWT is printed under `=== SUCCESS: Forge Context Token ===`.

> **WARNING:** The output includes auth material (cookies/tokens). Do not paste it into
> public tickets, logs, Slack, or chat.

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
