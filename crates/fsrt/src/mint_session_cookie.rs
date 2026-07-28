//! Native Rust port of `poc/mint_session_cookie_spike.py`.
//!
//! Harvests the Atlassian `tenant.session.token` cookie by driving a real
//! Chrome browser through the login flow, then writes it to `session-cookie.txt`
//! in the exact format the `raw_cookie` loader in `mint_common.rs` expects.
//!
//! ## Why this whole module is behind the `mint_cookie` Cargo feature
//! `thirtyfour` is an *async* WebDriver client and pulls in `tokio` plus a full
//! async HTTP stack. The rest of `fsrt` is synchronous (`fn main`, `ureq`), so
//! we keep this optional to avoid bloating default builds. Enable with:
//! `cargo run -p fsrt --features mint_cookie -- mint-cookie [--config ./cfg.toml] [--headed]`
//! (--config defaults to "./fsrt-remote.toml" in the current working directory)
//!
//! ## The sync/async bridge
//! The public entry point [`harvest_session_cookie`] is a *plain sync fn*. It
//! creates a **local** tokio runtime and uses `block_on` to run the async
//! WebDriver work as a single contained island — so async never leaks into the
//! rest of the binary. This is the "bridge" described in the design discussion.
//!
//! ## Prerequisite
//! A `chromedriver` must be listening (default `http://localhost:9515`). Start it
//! with `chromedriver --port=9515`. (thirtyfour talks W3C WebDriver to it, the
//! same way Python Selenium does.)

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;
use thirtyfour::ChromeCapabilities;
use thirtyfour::prelude::*;

use crate::mint_common::{MintError, MintFctConfig, Result};

// ── Constants (mirror the Python spike) ──────────────────────────────────────

const COOKIE_NAME: &str = "tenant.session.token";
const LOGIN_URL: &str = "https://id.atlassian.com/login";

// Fallbacks used only when the corresponding optional `[cookie]` field is
// omitted from the config. There is intentionally NO Default for HarvestConfig
// itself — it must always be constructed from fsrt-remote.toml.
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_VERIFY_WAIT_SECS: u64 = 120;

// ── Public configuration ─────────────────────────────────────────────────────

/// Options controlling a harvest run. Constructed exclusively via
/// [`HarvestConfig::from_remote_config`] — every field is sourced from
/// `fsrt-remote.toml` (plus the password, which is passed in separately from an
/// env var / prompt so it never lives in the config file).
#[derive(Debug, Clone)]
pub struct HarvestConfig {
    /// Atlassian account email to log in as (from `[cookie].username`).
    pub username: String,
    /// Account password. Sourced from an env var / prompt by the caller, never
    /// from the config, to keep it out of shell history and shared files.
    pub password: String,
    /// Tenant site where the cookie is minted — derived from the config's
    /// `graphql_endpoint` host (e.g. `https://<site>.atlassian.net`).
    pub site_url: String,
    /// Where to write the cookie file — from `auth.raw_cookie_file`.
    pub output: PathBuf,
    /// Run Chrome with a visible window (from `[cookie].headed`).
    pub headed: bool,
    /// Per-step element wait timeout (fixed internal default).
    pub timeout: Duration,
    /// How long to pause after login for a manual email-verification code
    /// (from `[cookie].verify_wait_secs`).
    pub verify_wait: Duration,
}

impl HarvestConfig {
    /// Build a [`HarvestConfig`] entirely from the loaded `fsrt-remote.toml`
    /// (`MintFctConfig`) plus the password (sourced separately).
    ///
    /// - `username`, `headed`, verify-wait come from `[cookie]`.
    /// - `site_url` is derived from `graphql_endpoint` (scheme + host).
    /// - `output` comes from `auth.raw_cookie_file` (the file the token loader
    ///   later reads), so mint-and-consume agree on one path.
    pub fn from_remote_config(config: &MintFctConfig, password: String) -> Result<Self> {
        let cookie = config.cookie.as_ref().ok_or_else(|| {
            MintError::Config(
                "session-cookie harvesting requires a `[cookie]` section in the \
                 config (at minimum `username`)."
                    .into(),
            )
        })?;

        // Derive the tenant site (scheme://host) from the GraphQL endpoint URL.
        let site_url = tenant_site_from_endpoint(&config.graphql_endpoint)?;

        // The output file is where the raw_cookie loader will read from later.
        let output = config
            .auth
            .raw_cookie_file
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| {
                MintError::Config(
                    "harvesting writes to `auth.raw_cookie_file`, which must be set \
                     in the config."
                        .into(),
                )
            })?;

        Ok(Self {
            username: cookie.username.clone(),
            password,
            site_url,
            output,
            headed: cookie.headed.unwrap_or(false),
            // Fixed internal per-step wait; not user-configurable.
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            verify_wait: Duration::from_secs(
                cookie.verify_wait_secs.unwrap_or(DEFAULT_VERIFY_WAIT_SECS),
            ),
        })
    }
}

/// Extract `scheme://host` from a full GraphQL endpoint URL, e.g.
/// `https://site.atlassian.net/gateway/api/graphql` → `https://site.atlassian.net`.
fn tenant_site_from_endpoint(endpoint: &str) -> Result<String> {
    // Split off scheme.
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| MintError::Config(format!("graphql_endpoint is not a URL: {endpoint}")))?;
    // Host is everything up to the first '/'.
    let host = rest.split('/').next().unwrap_or(rest);
    if host.is_empty() {
        return Err(MintError::Config(format!(
            "could not derive tenant host from graphql_endpoint: {endpoint}"
        )));
    }
    Ok(format!("{scheme}://{host}"))
}

// ── The sync → async bridge ──────────────────────────────────────────────────

/// Harvest the session cookie and write it to `config.output`.
///
/// This is a **synchronous** function: it spins up a local tokio runtime and
/// `block_on`s the async WebDriver work, so callers (e.g. `mint-fit`) don't need
/// to be async themselves. Returns the harvested token value on success.
pub fn harvest_session_cookie(config: &HarvestConfig) -> Result<String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| MintError::Config(format!("failed to start tokio runtime: {e}")))?;
    runtime.block_on(harvest_async(config))
}

// ── CLI: `fsrt mint-cookie` ──────────────────────────────────────────────────

/// Args for the `mint-cookie` subcommand.
#[derive(Debug, clap::Args)]
pub struct MintCookieArgs {
    #[arg(
        long,
        value_hint = clap::ValueHint::FilePath,
        default_value = "./fsrt-remote.toml",
        help = "OPTIONAL: config TOML path (reads [cookie], graphql_endpoint,\n\
                auth.raw_cookie_file)."
    )]
    pub config: std::path::PathBuf,

    #[arg(
        long,
        default_value_t = false,
        help = "OPTIONAL: show the browser window\n\
                (needed for email verification / bot-check; overrides [cookie].headed).\n\
                Default: false."
    )]
    pub headed: bool,
}

/// Entry point for `fsrt mint-cookie`.
///
/// Loads the config, reads the password from the `ATL_PASSWORD` env var (never a
/// CLI arg, to keep it out of shell history), builds a [`HarvestConfig`] purely
/// from the config, and runs the harvest.
pub fn run_mint_cookie(
    args: &MintCookieArgs,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let config = crate::mint_common::load_config(&args.config)?;

    // Password from env only — keeps the secret out of argv / shell history.
    let password = std::env::var("ATL_PASSWORD").map_err(|_| {
        MintError::Config(
            "ATL_PASSWORD env var is not set. Export the dummy account's password, \
             e.g. `export ATL_PASSWORD=...` (a leading space keeps it out of shell \
             history), then re-run."
                .into(),
        )
    })?;
    if password.is_empty() {
        return Err(Box::new(MintError::Config(
            "ATL_PASSWORD is set but empty.".into(),
        )));
    }

    let mut harvest = HarvestConfig::from_remote_config(&config, password)?;
    // The --headed flag overrides the config value when passed.
    if args.headed {
        harvest.headed = true;
    }

    println!("=== Harvesting session cookie ===");
    println!("  account: {}", harvest.username);
    println!("  tenant:  {}", harvest.site_url);
    println!("  output:  {}", harvest.output.display());
    println!("  headed:  {}", harvest.headed);

    harvest_session_cookie(&harvest)?;
    Ok(())
}

// Map any thirtyfour error into our MintError type.
fn wd_err(context: &str, e: WebDriverError) -> MintError {
    MintError::Http(format!("{context}: {e}"))
}

/// The full async harvest flow. Everything that `.await`s lives here.
async fn harvest_async(config: &HarvestConfig) -> Result<String> {
    let driver = build_driver(config).await?;

    // Run the flow, always quitting the browser afterwards (even on error) so we
    // don't leak a chromedriver session — the analog of the Python `finally`.
    let result = run_flow(&driver, config).await;
    let _ = driver.quit().await;

    let value = result?;
    write_cookie_file(&value, &config.output)?;

    let preview: String = value.chars().take(20).collect();
    println!("[+] Wrote {COOKIE_NAME} to {} (value: {preview}...)", config.output.display());
    println!(
        "    WARNING: this file is a bearer credential. It is gitignored; \
         do not paste it into tickets, logs, or chat."
    );
    Ok(value)
}

async fn run_flow(driver: &WebDriver, config: &HarvestConfig) -> Result<String> {
    println!("[*] Logging in as {} ...", config.username);
    do_login(driver, config).await?;
    println!("[*] Login submitted.");

    // Clicking "Continue" only *submits* the password — the post-login redirect
    // chain (id.atlassian.com -> account session established -> tenant reachable)
    // is still in flight. In a headed run the manual pause below absorbs that
    // time; headless has no pause, so we explicitly wait for the browser to leave
    // the login page before touching the tenant. Without this, harvest races
    // ahead and the tenant bounces us to home.atlassian.com before the session
    // is ready.
    wait_for_login_to_settle(driver, config).await;

    // In a headed run, also pause so the user can finish anything interactive in
    // the browser (e.g. type an email-verification code).
    if config.headed {
        wait_for_manual_step(driver, config).await;
    }

    println!("[*] Visiting tenant {} to mint the session cookie ...", config.site_url);
    harvest_cookie(driver, config).await
}

// ── Driver construction ──────────────────────────────────────────────────────

async fn build_driver(config: &HarvestConfig) -> Result<WebDriver> {
    let mut caps = ChromeCapabilities::new();

    if !config.headed {
        caps.add_arg("--headless=new")
            .map_err(|e| wd_err("set headless", e))?;
    }
    for arg in [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--window-size=1280,1024",
        // Reduce the automation fingerprint that risk-detection checks.
        "--disable-blink-features=AutomationControlled",
    ] {
        caps.add_arg(arg).map_err(|e| wd_err("add chrome arg", e))?;
    }

    // Drop the "Chrome is being controlled by automated software" tells.
    caps.add_exclude_switch("enable-automation")
        .map_err(|e| wd_err("exclude switch", e))?;

    // Managed driver: auto-download a chromedriver matching the locally-installed
    // Chrome and spawn/tear it down for us — the analog of Python Selenium
    // Manager, so there's no manual `chromedriver` prerequisite. `match_local`
    // pins the driver to the installed browser version.
    let driver = WebDriver::managed(caps)
        .match_local()
        .await
        .map_err(|e| {
            MintError::Http(format!(
                "could not start a managed Chrome WebDriver: {e}. Ensure Chrome is \
                 installed and the machine can download a matching chromedriver."
            ))
        })?;

    // Use polling waits with our configured per-step timeout.
    driver
        .set_implicit_wait_timeout(config.timeout)
        .await
        .map_err(|e| wd_err("set implicit wait", e))?;

    // Hide navigator.webdriver (the most-checked automation tell). Best-effort.
    let _ = driver
        .execute(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})",
            vec![],
        )
        .await;

    // Normalise the User-Agent to the *real* installed Chrome version instead of
    // hardcoding one (which goes stale) — and strip the "HeadlessChrome" marker
    // that headless mode advertises, which is an obvious automation tell. We read
    // the actual UA via CDP `Browser.getVersion` and, if needed, override it with
    // CDP `Network.setUserAgentOverride`. All best-effort: a failure here just
    // leaves the default UA in place.
    apply_realistic_user_agent(&driver).await;

    Ok(driver)
}

/// Derive a realistic User-Agent from the running Chrome and apply it, replacing
/// the tell-tale "HeadlessChrome" token with "Chrome". No-op on any CDP error.
async fn apply_realistic_user_agent(driver: &WebDriver) {
    let Ok(info) = driver
        .cdp()
        .send_raw("Browser.getVersion", json!({}))
        .await
    else {
        return;
    };
    let Some(ua) = info.get("userAgent").and_then(|v| v.as_str()) else {
        return;
    };

    // Only override if there's actually something to fix (headless marker).
    if ua.contains("HeadlessChrome") {
        let real_ua = ua.replace("HeadlessChrome", "Chrome");
        let _ = driver
            .cdp()
            .send_raw(
                "Network.setUserAgentOverride",
                json!({ "userAgent": real_ua }),
            )
            .await;
    }
}

// ── Login ────────────────────────────────────────────────────────────────────

async fn do_login(driver: &WebDriver, config: &HarvestConfig) -> Result<()> {
    driver
        .goto(LOGIN_URL)
        .await
        .map_err(|e| wd_err("navigate to login", e))?;

    // Step 1: email. The input's id is dynamic (e.g. "username-uid1"), so we
    // match on the stable name attribute instead.
    let email = query_clickable(driver, "input[name='username']", config.timeout)
        .await
        .map_err(|_| {
            MintError::Http(
                "timed out waiting for the email field. The login page may have \
                 changed, or a bot-check is blocking headless mode — retry headed."
                    .to_string(),
            )
        })?;
    type_into(&email, &config.username).await?;
    click_continue(driver, config.timeout).await?;

    // Step 2: password (revealed after the email step).
    let pw = query_clickable(driver, "input[name='password']", config.timeout)
        .await
        .map_err(|_| {
            MintError::Http(
                "timed out waiting for the password field. If this account uses \
                 SSO/MFA it cannot be driven here — use a plain password account."
                    .to_string(),
            )
        })?;
    type_into(&pw, &config.password).await?;
    click_continue(driver, config.timeout).await?;

    Ok(())
}

async fn click_continue(driver: &WebDriver, timeout: Duration) -> Result<()> {
    // Atlassian's submit button id has been "login-submit"; fall back to a
    // generic submit selector if that changes.
    for selector in ["#login-submit", "button[type='submit']"] {
        if let Ok(btn) = query_clickable(driver, selector, timeout).await {
            btn.click().await.map_err(|e| wd_err("click submit", e))?;
            return Ok(());
        }
    }
    Err(MintError::Http(
        "could not find the login submit button".to_string(),
    ))
}

// ── Cookie harvesting ────────────────────────────────────────────────────────

/// Wait for the post-login redirect to finish, i.e. for the browser to leave the
/// `id.atlassian.com` login page. This gives the account session time to be
/// established before we try to reach the tenant. Best-effort with a bounded
/// wait — if it doesn't move on in time, we proceed anyway and let the
/// harvest-loop's retries handle it.
async fn wait_for_login_to_settle(driver: &WebDriver, config: &HarvestConfig) {
    let deadline = std::time::Instant::now() + config.timeout;
    while std::time::Instant::now() < deadline {
        match driver.current_url().await {
            Ok(url) if !url.as_str().contains("id.atlassian.com") => {
                // Left the login/auth host — the redirect chain has progressed.
                return;
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Poll `get_named_cookie` in place (no navigation) until the cookie appears or
/// the timeout elapses. Returns the cookie value if found.
async fn poll_for_cookie(driver: &WebDriver, timeout: Duration) -> Option<String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(cookie) = driver.get_named_cookie(COOKIE_NAME).await
            && !cookie.value.is_empty()
        {
            return Some(cookie.value);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    None
}

/// Extract the bare host (e.g. `site.atlassian.net`) from a site URL for a
/// "are we still on the tenant?" check.
fn tenant_host(site_url: &str) -> &str {
    site_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(site_url)
}

async fn harvest_cookie(driver: &WebDriver, config: &HarvestConfig) -> Result<String> {
    // First, try the page login already left us on (a completed login usually
    // redirects straight to the tenant).
    if let Ok(cookie) = driver.get_named_cookie(COOKIE_NAME).await
        && !cookie.value.is_empty()
    {
        return Ok(cookie.value);
    }

    // Visit the tenant ONCE (where `tenant.session.token` is scoped), then poll
    // for the cookie IN PLACE. We deliberately do NOT re-`goto` every tick:
    // `goto` interrupts/restarts any in-flight redirect, which would repeatedly
    // kill the very handshake that mints the cookie before it can finish. Since
    // `wait_for_login_to_settle` already ran, the account session exists, so this
    // single load should stick on the tenant and complete.
    let tenant = format!("{}/", config.site_url.trim_end_matches('/'));
    driver
        .goto(&tenant)
        .await
        .map_err(|e| wd_err(&format!("navigate to tenant {tenant}"), e))?;

    if let Some(value) = poll_for_cookie(driver, config.timeout).await {
        return Ok(value);
    }

    // Conditional single retry: if after settling we got bounced OFF the tenant
    // host (e.g. to home.atlassian.com because the session still wasn't ready on
    // the first visit), navigate to the tenant one more time and poll again. This
    // is a deliberate, one-shot retry — not a blind reload loop.
    let on_tenant = driver
        .current_url()
        .await
        .map(|u| u.as_str().contains(tenant_host(&config.site_url)))
        .unwrap_or(false);
    if !on_tenant {
        let _ = driver.goto(&tenant).await;
        if let Some(value) = poll_for_cookie(driver, config.timeout).await {
            return Ok(value);
        }
    }

    // The cookie never appeared. In a headless run there's no window for the user
    // to intervene (e.g. complete an email-verification code, dismiss a consent
    // screen, or finish product setup), and these interactive steps are the most
    // common reason harvesting fails. Rather than rely on brittle screen
    // detection, point the user at --headed so they can see and handle whatever
    // the browser is showing.
    if !config.headed {
        return Err(MintError::Http(
            "could not obtain the session cookie in headless mode. This usually \
             means an interactive step is blocking login (email-verification code, \
             a consent screen, or product setup). Re-run with the `--headed` flag \
             so a browser window opens and you can complete it."
                .to_string(),
        ));
    }

    // Headed run: the user could see the browser, so give the detailed diagnostic
    // (what cookies were set and where we ended up) to help debug config issues.
    let last_url = driver
        .current_url()
        .await
        .map(|u| u.to_string())
        .unwrap_or_default();
    let mut have: Vec<String> = driver
        .get_all_cookies()
        .await
        .map(|cs| cs.into_iter().map(|c| c.name).collect())
        .unwrap_or_default();
    have.sort();
    let hint = if have.iter().any(|n| n == "cloud.session.token") {
        format!(
            " NOTE: 'cloud.session.token' IS present — you're logged in at the \
             account level but never reached the tenant. Check that site_url ({}) \
             is correct and this account has access.",
            config.site_url
        )
    } else {
        String::new()
    };
    Err(MintError::Http(format!(
        "'{COOKIE_NAME}' cookie was not found after visiting the tenant (last URL: \
         '{last_url}'). Cookies present: {have:?}.{hint}"
    )))
}

// ── Manual pause ─────────────────────────────────────────────────────────────

/// Pause after login so you can finish anything in the browser (e.g. type an
/// email-verification code if one appears). Complete whatever the browser shows,
/// then press ENTER here to continue. Auto-resumes after `verify_wait` so
/// unattended runs still make progress.
async fn wait_for_manual_step(driver: &WebDriver, config: &HarvestConfig) {
    // Show where login left the browser (informational).
    if let Ok(url) = driver.current_url().await {
        println!("[*] Current page: {url}");
    }
    let secs = config.verify_wait.as_secs();
    // Flush so the prompt is visible immediately (println! can be line-buffered
    // and appear "stuck" otherwise).
    print!(
        "[*] Finish any step in the browser, then press ENTER here to continue \
         (auto-resume after {secs}s)... "
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // The blocking stdin read runs on a dedicated thread so it doesn't stall the
    // async runtime.
    let read_line = tokio::task::spawn_blocking(|| {
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
    });

    tokio::select! {
        _ = read_line => println!("[*] Resuming (keypress)."),
        _ = tokio::time::sleep(config.verify_wait) => println!("[*] Resuming (timeout)."),
    }
}

// ── Small helpers ────────────────────────────────────────────────────────────

async fn query_clickable(
    driver: &WebDriver,
    css: &str,
    timeout: Duration,
) -> Result<WebElement> {
    driver
        .query(By::Css(css))
        .wait(timeout, Duration::from_millis(250))
        .and_clickable()
        .first()
        .await
        .map_err(|e| wd_err(&format!("wait for {css}"), e))
}

/// Focus, clear, then type the value. React inputs can ignore send_keys without
/// a focus click first, so we click before typing.
async fn type_into(field: &WebElement, text: &str) -> Result<()> {
    field.click().await.map_err(|e| wd_err("focus field", e))?;
    field.clear().await.map_err(|e| wd_err("clear field", e))?;
    field
        .send_keys(text)
        .await
        .map_err(|e| wd_err("type text", e))?;
    Ok(())
}

/// Write the cookie in the exact format the Rust `raw_cookie` loader expects:
/// the whole file is read, trimmed, and used verbatim as the `Cookie:` header,
/// so we write a single `name=value` pair.
fn write_cookie_file(value: &str, out_path: &Path) -> Result<()> {
    let contents = format!("{COOKIE_NAME}={value}");
    std::fs::write(out_path, contents)?;
    // Bearer credential — restrict to owner read/write (best-effort).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
