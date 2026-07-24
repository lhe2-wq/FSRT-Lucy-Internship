#!/usr/bin/env python3
"""Session-cookie harvesting spike for FSRT remote token minting.

This is intentionally a Python spike (like `mint_fct_spike.py`), not the final
FSRT implementation. Its job is to answer one question end-to-end:

    Can we automate an Atlassian browser login and harvest the
    `tenant.session.token` cookie into `./session-cookie.txt` so the Rust
    `fsrt mint-fct` / `mint-fit` subcommands (auth.type = "raw_cookie") can
    consume it?

Why a browser at all?
    `tenant.session.token` is a *browser session* artifact minted by Atlassian's
    login flow. There is no "download token" API — the only way to obtain one is
    to complete a real login and read the cookie the server set. It is also an
    HttpOnly cookie, so `document.cookie` cannot see it; we must use the
    WebDriver cookie API (`driver.get_cookie(...)`), which returns HttpOnly
    cookies too.

Why a dummy account?
    The token *is* your identity. Harvesting it writes a bearer credential to
    disk (`session-cookie.txt`). Use a throwaway account so a leak costs nothing
    and automated tooling never touches real data. A Proton-backed Atlassian ID
    account (plain username/password, no corporate SSO/MFA) is drivable by
    Selenium; SSO/MFA accounts are not.

Modelled on the Selenium login pattern from:
    https://github.com/atlassian-labs/Connect-Vulnerability-Scanner/blob/main/scan.py

The eventual production implementation should be ported into Rust (thirtyfour /
fantoccini) and wired into an `fsrt mint-cookie` subcommand, with XDG-based
storage. For the spike we hardcode the output path to `./session-cookie.txt`
and harvest only `tenant.session.token`.

Requirements:
    pip install selenium
    # plus a matching chromedriver on PATH (Selenium Manager usually auto-fetches it)

Usage:
    # Password via env (recommended — keeps it out of shell history):
    export ATL_PASSWORD='...'
    python poc/mint_session_cookie_spike.py

    # Or be prompted interactively:
    python poc/mint_session_cookie_spike.py

    # First run: use --headed to solve any bot-check / captcha manually.
    python poc/mint_session_cookie_spike.py --headed
"""

from __future__ import annotations

import argparse
import getpass
import os
import random
import sys
import time
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
except ImportError:  # pragma: no cover - dependency hint for the spike
    print(
        "error: selenium is not installed. Run:  pip install selenium",
        file=sys.stderr,
    )
    raise SystemExit(3)


# ---------------------------------------------------------------------------
# Defaults — spike hardcodes as requested.
# ---------------------------------------------------------------------------
DEFAULT_USERNAME = "testerlhe2-1@protonmail.com"
DEFAULT_OUTPUT = Path("./session-cookie.txt")
COOKIE_NAME = "tenant.session.token"

# The dummy account's tenant. tenant.session.token is ONLY minted/scoped on the
# specific *.atlassian.net site — not on id/home/start/admin.atlassian.com. This
# matches graphql_endpoint in fsrt-remote.toml.
DEFAULT_SITE_URL = "https://testerlhe2-1.atlassian.net"

# Atlassian ID login entry point. After auth this redirects to start.atlassian.com
# / the user's tenant, at which point the session cookie is set on *.atlassian.net.
LOGIN_URL = "https://id.atlassian.com/login"
# After login we visit these in order to land on a domain where
# tenant.session.token is scoped. The cookie is set on *.atlassian.net tenant
# domains; start.atlassian.com bounces you to your tenant, admin/home are
# fallbacks. get_cookie() only sees cookies for the CURRENT domain, so we must
# actually be on the right host when we read it.
POST_LOGIN_URLS = (
    "https://start.atlassian.com/",
    "https://home.atlassian.com/",
    "https://admin.atlassian.com/",
)


class SpikeError(Exception):
    """Raised for expected, user-facing spike failures."""


def build_driver(headed: bool, profile_dir: str | None = None) -> webdriver.Chrome:
    """Create a Chrome WebDriver.

    Selenium Manager (bundled with modern selenium) auto-resolves a matching
    chromedriver, so no manual driver path is needed in most environments.

    Atlassian login can bounce automated sessions back to /login. Two things
    help most:
      1. Reducing the obvious automation fingerprint (navigator.webdriver, the
         "Chrome is being controlled by automated software" infobar).
      2. A persistent --user-data-dir profile, so the browser looks like a
         returning, trusted device across runs (pass --profile-dir).
    """
    options = Options()
    if not headed:
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,1024")
    # Reduce automation fingerprint.
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    # A stable, non-default UA reduces the odds of a headless bot-check.
    options.add_argument(
        "--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
    # Persistent profile: makes the device look "remembered" to Atlassian and
    # can carry an already-trusted session across runs.
    if profile_dir:
        options.add_argument(f"--user-data-dir={os.path.abspath(profile_dir)}")

    try:
        driver = webdriver.Chrome(options=options)
    except Exception as e:  # pragma: no cover - environment dependent
        raise SpikeError(
            f"could not start Chrome WebDriver: {e}\n"
            "Ensure Google Chrome is installed and reachable by Selenium Manager."
        ) from e

    # Hide navigator.webdriver (the most-checked automation tell).
    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"},
        )
    except Exception:
        pass  # best-effort
    return driver


def do_login(driver: webdriver.Chrome, username: str, password: str, timeout: int) -> None:
    """Drive the two-step Atlassian ID login (email, then password)."""
    wait = WebDriverWait(driver, timeout)
    driver.get(LOGIN_URL)

    # Step 1: username / email.
    # NOTE: the email input's `id` is dynamic (e.g. "username-uid1"), so we match
    # on the stable name / data-testid instead.
    try:
        email_field = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "input[name='username']"))
        )
    except TimeoutException as e:
        raise SpikeError(
            "timed out waiting for the email field. The login page layout may "
            "have changed, or a bot-check is blocking headless mode — retry with --headed."
        ) from e
    _human_pause(0.4, 0.9)
    _type_into(email_field, username)
    _human_pause(0.5, 1.2)  # let React register the value before submitting
    _click_continue(driver, wait)

    # Step 2: password. Atlassian reveals this after the email is submitted; the
    # field exists in the DOM from the start but only becomes visible now.
    try:
        pw_field = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "input[name='password']"))
        )
    except TimeoutException as e:
        raise SpikeError(
            "timed out waiting for the password field. If this account uses SSO/MFA "
            "it cannot be driven by this spike — use a plain username/password dummy account."
        ) from e
    _human_pause(0.6, 1.3)
    _type_into(pw_field, password)
    _human_pause(0.5, 1.2)  # let React register the value before submitting
    _click_continue(driver, wait)


def _human_pause(lo: float, hi: float) -> None:
    """Sleep a random human-like interval."""
    time.sleep(random.uniform(lo, hi))


def _looks_like_verification(driver: webdriver.Chrome) -> bool:
    """Best-effort detection of an email-verification / challenge screen.

    Atlassian shows a code-entry step after login on a new/untrusted device.
    We look for a one-time-code input or common verification wording.
    """
    selectors = (
        "input[name='token']",
        "input[name='verificationCode']",
        "input[autocomplete='one-time-code']",
        "input[inputmode='numeric']",
        "input[data-testid='verification-code']",
    )
    for sel in selectors:
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, sel):
                if el.is_displayed():
                    return True
        except Exception:
            pass
    try:
        body = driver.find_element(By.TAG_NAME, "body").text.lower()
        for phrase in ("verification code", "verify your", "enter the code", "check your email"):
            if phrase in body:
                return True
    except Exception:
        pass
    return False


def wait_for_manual_step(driver: webdriver.Chrome, wait_seconds: int) -> None:
    """Pause after login so you can complete an email-verification code by hand.

    Behaviour:
      * If a verification/challenge screen is detected (or always, as a safety
        net), pause here.
      * Prefer waiting for you to press Enter (interactive terminals) so you
        finish exactly when ready.
      * If there's no interactive stdin (or you don't press Enter in time),
        auto-resume after `wait_seconds` so headless/unattended runs still work.
    """
    detected = _looks_like_verification(driver)
    if detected:
        print("[!] Looks like an email-verification / challenge screen.")
    else:
        print("[*] Pausing before harvest in case a verification step appears.")

    print(
        f"    Enter any code in the browser now. Press ENTER here to continue, "
        f"or I'll auto-resume in {wait_seconds}s..."
    )

    # If stdin isn't a real terminal (e.g. piped/CI), just sleep the fallback.
    if not sys.stdin or not sys.stdin.isatty():
        time.sleep(wait_seconds)
        return

    # Wait for Enter OR timeout, whichever comes first, without extra deps.
    try:
        import select

        ready, _, _ = select.select([sys.stdin], [], [], wait_seconds)
        if ready:
            sys.stdin.readline()  # consume the Enter keypress
            print("[*] Resuming (keypress).")
        else:
            print("[*] Resuming (timeout).")
    except Exception:
        # select() isn't available on some platforms (e.g. Windows) — fall back
        # to a plain blocking prompt with no timeout.
        try:
            input()
            print("[*] Resuming (keypress).")
        except EOFError:
            time.sleep(wait_seconds)


def _type_into(field, text: str) -> None:
    """Focus, then type char-by-char with small random delays.

    React inputs can ignore a bulk send_keys without a focus click, and
    instant typing looks robotic to risk detection — so we pace each keystroke.
    """
    field.click()
    _human_pause(0.2, 0.5)
    field.clear()
    for ch in text:
        field.send_keys(ch)
        time.sleep(random.uniform(0.05, 0.15))


def _click_continue(driver: webdriver.Chrome, wait: WebDriverWait) -> None:
    """Click the primary submit button on the current login step."""
    # Atlassian's submit button id has been "login-submit"; fall back to a
    # generic submit selector if that changes.
    for locator in (
        (By.ID, "login-submit"),
        (By.CSS_SELECTOR, "button[type='submit']"),
    ):
        try:
            btn = wait.until(EC.element_to_be_clickable(locator))
            btn.click()
            return
        except (TimeoutException, NoSuchElementException):
            continue
    raise SpikeError("could not find the login submit button")


def harvest_cookie(driver: webdriver.Chrome, timeout: int, site_url: str) -> str:
    """Wait for the session cookie to appear, then return its value.

    Uses the WebDriver cookie API (not document.cookie) so the HttpOnly
    tenant.session.token is visible.

    tenant.session.token is ONLY set on the specific tenant (site_url, e.g.
    https://<site>.atlassian.net). So we visit that FIRST; the generic
    home/start/admin domains only carry id-level cookies (cloud.session.token)
    and won't have it.
    """
    deadline = time.time() + timeout
    last_url = driver.current_url

    # First, try the page login already left us on (a completed verification
    # usually redirects straight to the tenant).
    cookie = driver.get_cookie(COOKIE_NAME)
    if cookie and cookie.get("value"):
        return cookie["value"]

    # Visit the actual tenant first (where the cookie is scoped), then fall back
    # to the generic domains.
    candidates = [site_url.rstrip("/") + "/", *POST_LOGIN_URLS]
    while time.time() < deadline:
        for url in candidates:
            try:
                driver.get(url)
            except Exception:
                continue
            last_url = driver.current_url
            # small settle so any redirect / SSO handshake to the tenant completes
            time.sleep(2)
            cookie = driver.get_cookie(COOKIE_NAME)
            if cookie and cookie.get("value"):
                return cookie["value"]
            if time.time() >= deadline:
                break
        time.sleep(1)

    # Help the user debug what *did* get set and where we ended up.
    have = sorted(c["name"] for c in driver.get_cookies())
    hint = ""
    if "cloud.session.token" in have:
        hint = (
            " NOTE: 'cloud.session.token' IS present — you're logged in at the "
            "account level, but never reached the tenant. Check that --site-url "
            f"({site_url}) is correct and that this account has access to it."
        )
    raise SpikeError(
        f"'{COOKIE_NAME}' cookie was not found after login (last URL: {last_url}). "
        f"Cookies present: {have}.{hint} "
        "Make sure login fully completed (enter the email verification code "
        "during the pause), and retry with --headed."
    )


def write_cookie_file(value: str, out_path: Path) -> None:
    """Write the cookie in the exact format the Rust raw_cookie loader expects.

    mint_common.rs reads the whole file, trims it, and uses it verbatim as the
    Cookie: header. So we write a single `name=value` pair.
    """
    contents = f"{COOKIE_NAME}={value}"
    out_path.write_text(contents, encoding="utf-8")
    # Bearer credential — restrict to owner read/write.
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass  # best-effort; not all filesystems support chmod


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Harvest the Atlassian tenant.session.token cookie into session-cookie.txt"
    )
    parser.add_argument(
        "--username",
        default=DEFAULT_USERNAME,
        help=f"Atlassian account email (default: {DEFAULT_USERNAME})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Where to write the cookie (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Run Chrome with a visible window (use to solve a bot-check on first run)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-step wait timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--profile-dir",
        default=None,
        help="Persistent Chrome user-data dir (e.g. ./chrome-profile). Reuses a "
             "trusted/remembered device across runs, which avoids login bounces.",
    )
    parser.add_argument(
        "--verify-wait",
        type=int,
        default=120,
        help="Seconds to pause after login for you to enter an email "
             "verification code in the browser. Press ENTER to resume early "
             "(default: 120).",
    )
    parser.add_argument(
        "--site-url",
        default=DEFAULT_SITE_URL,
        help=f"Tenant site where tenant.session.token is minted "
             f"(default: {DEFAULT_SITE_URL}). Must match your graphql_endpoint host.",
    )
    args = parser.parse_args()

    # Password: env var first (keeps it out of argv / shell history), else prompt.
    password = os.environ.get("ATL_PASSWORD")
    if not password:
        password = getpass.getpass(f"Password for {args.username}: ")
    if not password:
        print("error: no password provided", file=sys.stderr)
        return 2

    driver = None
    try:
        driver = build_driver(headed=args.headed, profile_dir=args.profile_dir)
        print(f"[*] Logging in as {args.username} ...")
        do_login(driver, args.username, password, args.timeout)
        print("[*] Login submitted.")
        # New/untrusted devices get an email-verification code step. Pause here
        # (on whatever page login left us on) so you can type the code into the
        # browser BEFORE we navigate away and look for the cookie.
        wait_for_manual_step(driver, args.verify_wait)
        print(f"[*] Visiting tenant {args.site_url} to mint the session cookie ...")
        value = harvest_cookie(driver, args.timeout, args.site_url)
        write_cookie_file(value, args.output)
        preview = value[:20] + "..." if len(value) > 20 else value
        print(f"[+] Wrote {COOKIE_NAME} to {args.output} (value: {preview})")
        print("    WARNING: this file is a bearer credential. It is gitignored; "
              "do not paste it into tickets, logs, or chat.")
        return 0
    except SpikeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        if driver is not None:
            driver.quit()


if __name__ == "__main__":
    raise SystemExit(main())
