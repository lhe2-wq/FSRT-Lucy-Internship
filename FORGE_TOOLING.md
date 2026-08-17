# Forge Tooling Architecture

FSRT's dynamic-testing commands share one deployment snapshot and authenticated
GraphQL client from the `forge_pen_test` crate:

```text
fsrt command
  -> find and parse manifest.yml
  -> load fsrt-remote.toml
  -> validate the session cookie
  -> resolve tenant and deployed extension metadata
  -> build or send a typed GraphQL request
```

The commands are:

- `mint-fct`: signs a Forge Context Token for one deployed module.
- `mint-fit`: mints an FCT and exchanges it for a Forge Invocation Token tied
  to a Forge Remote.
- `invoke-extension`: mints or reuses an FCT and calls a resolver-backed
  extension with tester-controlled JSON.
- `mint-cookie`: optionally drives Chrome to harvest the browser session cookie
  consumed by the other commands.

## Ownership

`crates/fsrt` owns CLI parsing, manifest discovery, stdout, and process-level
errors. `crates/forge_pen_test` owns configuration validation, cookie and JWT
handling, tenant/deployment discovery, request construction, GraphQL transport,
and the FCT cache. `crates/forge_loader` exposes typed module and remote
metadata used for auto-detection.

`ForgePenTester::new` validates the site, manifest app ARI, cookie path,
environment selection, and requested module before returning. It then retains:

- one HTTP agent with GraphQL authentication middleware;
- the parsed Forge manifest;
- normalized site and resolved app configuration;
- all valid deployed extensions from the environment snapshot; and
- the most recently minted, structurally valid FCT.

Reconstruct the tester to observe a newer deployment.

## Request flows

### FCT

The tester selects the requested deployed module and submits
`globalApp_signForgeContextTokens`. The cache is replaced only when the returned
JWT is structurally valid and unexpired. Dry runs build the same variables but
do not submit the signing mutation.

### FIT

The command selects a module and Forge Remote from explicit arguments or the
manifest. It mints an FCT in memory and submits `signInvocationTokenForUI` with
that token and the remote key. The intermediate FCT is never written to disk.

### Extension invocation

The command selects the module wired to `--function` when possible. It builds
the resolver envelope expected by `invokeExtension`:

```text
payload.call.functionKey
payload.call.payload
payload.context
payload.contextToken
```

The context defaults to resolved deployment values and can be replaced with a
JSON object through `--context`. A captured FCT may be supplied through `--fct`;
otherwise the command mints one in memory.

### Cookie harvesting

The optional `mint_cookie` Cargo feature contains the asynchronous WebDriver
stack. The synchronous CLI creates a local Tokio runtime, drives a managed
Chrome session, writes `tenant.session.token` to the configured cookie file,
and restricts that file to owner read/write permissions on Unix. The command
never prints the credential value.

## Security boundaries

- `fsrt-remote.toml`, cookie files, and session-token notes are ignored.
- The cookie and `ATL_PASSWORD` must not be placed in command arguments, logs,
  tickets, commits, or chat.
- JWT inspection verifies structure and expiry, not cryptographic signatures.
- Atlassian remains responsible for authenticating the browser session and
  signing returned tokens.
- GraphQL authentication headers are attached only to the fixed Atlassian
  GraphQL endpoint, not tenant-info or unrelated requests.
