#!/usr/bin/env python3
"""Confluence Forge Context Token minting spike.

This is intentionally a Python spike, not the final FSRT implementation. Its job is
quickly answering the EAS-4556 questions for Confluence:

- Can we call the Confluence FCT minting mutation?
- What input shape does the mutation require?
- What values can we derive from manifest.yml?
- What auth material is required?

The eventual production implementation should be ported into Rust and wired into a
native `fsrt mint-fct` clap subcommand that reuses forge_loader's manifest parser.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - dependency-free fallback for local spikes
    yaml = None


DEFAULT_CONFLUENCE_MUTATION = """
mutation useGetContextTokenMutation($cloudId: ID!, $input: ConfluenceForgeContextTokenRequestInput!) {
  confluence_generateForgeContextToken(cloudId: $cloudId, input: $input) {
    success
    errors {
      message
      __typename
    }
    forgeContextToken {
      jwt
      expiresAt
      extensionId
      __typename
    }
    __typename
  }
}
""".strip()

PLACEHOLDER_RE = re.compile(r"\$\{([^}]+)\}")


class SpikeError(Exception):
    """User-facing spike error."""


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in ("", "null", "Null", "NULL", "~"):
        return None
    if value in ("[]",):
        return []
    if value in ("{}",):
        return {}
    if value in ("true", "True", "TRUE"):
        return True
    if value in ("false", "False", "FALSE"):
        return False
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i]
    return line


def simple_yaml_load(text: str) -> dict[str, Any]:
    """Parse the small YAML subset used by this spike when PyYAML is unavailable.

    Supports nested mappings, lists of mappings, quoted/unquoted scalars, empty
    lists/maps, comments, and literal blocks introduced with `|`. This is not a
    general YAML parser; install PyYAML if the manifest/config uses advanced YAML.
    """

    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    lines = text.splitlines()
    i = 0

    while i < len(lines):
        raw = lines[i]
        i += 1
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue

        indent = len(raw) - len(raw.lstrip(" "))
        line = strip_comment(raw).strip()
        if not line:
            continue

        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise SpikeError("Invalid YAML indentation")
        parent = stack[-1][1]

        if line.startswith("- "):
            if not isinstance(parent, list):
                raise SpikeError("YAML list item found where parent is not a list")
            item_text = line[2:].strip()
            # If the item is a quoted scalar, parse it directly — don't treat colons
            # inside quoted strings as key-value separators.
            is_quoted = (item_text.startswith('"') and item_text.endswith('"')) or (
                item_text.startswith("'") and item_text.endswith("'")
            )
            if not is_quoted and ":" in item_text:
                key, value = item_text.split(":", 1)
                item: dict[str, Any] = {}
                parent.append(item)
                key = key.strip()
                value = value.strip()
                if value:
                    item[key] = parse_scalar(value)
                else:
                    item[key] = {}
                    stack.append((indent + 2, item[key]))
                stack.append((indent, item))
            else:
                parent.append(parse_scalar(item_text))
            continue

        if ":" not in line:
            raise SpikeError(f"Unsupported YAML line: {raw}")

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not isinstance(parent, dict):
            raise SpikeError("YAML mapping entry found where parent is not a mapping")

        if value == "|":
            block_lines: list[str] = []
            block_indent: int | None = None
            while i < len(lines):
                candidate = lines[i]
                if not candidate.strip():
                    block_lines.append("")
                    i += 1
                    continue
                candidate_indent = len(candidate) - len(candidate.lstrip(" "))
                if candidate_indent <= indent:
                    break
                if block_indent is None:
                    block_indent = candidate_indent
                block_lines.append(candidate[block_indent:])
                i += 1
            parent[key] = "\n".join(block_lines).rstrip("\n")
            continue

        if value:
            parent[key] = parse_scalar(value)
            continue

        # Decide container type by peeking at the next meaningful line.
        next_container: Any = {}
        for j in range(i, len(lines)):
            peek_raw = lines[j]
            if not peek_raw.strip() or peek_raw.lstrip().startswith("#"):
                continue
            peek_indent = len(peek_raw) - len(peek_raw.lstrip(" "))
            peek_line = strip_comment(peek_raw).strip()
            if peek_indent > indent and peek_line.startswith("- "):
                next_container = []
            break
        parent[key] = next_container
        stack.append((indent, next_container))

    return root


def load_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text)
    else:
        data = simple_yaml_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise SpikeError(f"Expected YAML object in {path}, got {type(data).__name__}")
    return data


def load_manifest(app_dir: Path) -> tuple[dict[str, Any], Path]:
    for name in ("manifest.yml", "manifest.yaml"):
        path = app_dir / name
        if path.exists():
            return load_yaml(path), path
    raise SpikeError(f"Could not find manifest.yml or manifest.yaml under {app_dir}")


def extract_manifest_context(manifest: dict[str, Any], module_key: str | None) -> dict[str, Any]:
    app = manifest.get("app") or {}
    modules = manifest.get("modules") or {}
    if not isinstance(app, dict):
        raise SpikeError("manifest.app must be an object")
    if not isinstance(modules, dict):
        raise SpikeError("manifest.modules must be an object")

    module_type = None
    module = None
    if module_key:
        for candidate_type, entries in modules.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict) and entry.get("key") == module_key:
                    module_type = candidate_type
                    module = entry
                    break
            if module is not None:
                break

    app_id = app.get("id")
    # Extract bare UUID from app ARI e.g. ari:cloud:ecosystem::app/8bdd65d0-... -> 8bdd65d0-...
    app_id_bare = app_id.split("/")[-1] if app_id and "/" in app_id else app_id

    return {
        "app_id": app_id,
        "app_id_bare": app_id_bare,
        "app_name": app.get("name"),
        "module_key": module_key,
        "module_type": module_type,
        "module": module,
    }


def get_path(data: dict[str, Any], dotted_path: str) -> Any:
    cur: Any = data
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise SpikeError(f"Unknown template variable: {dotted_path}")
        cur = cur[part]
    return cur


def render_template(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {k: render_template(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [render_template(v, context) for v in value]
    if not isinstance(value, str):
        return value

    full_match = PLACEHOLDER_RE.fullmatch(value)
    if full_match:
        return get_path(context, full_match.group(1))

    def replace(match: re.Match[str]) -> str:
        replacement = get_path(context, match.group(1))
        return "" if replacement is None else str(replacement)

    return PLACEHOLDER_RE.sub(replace, value)


def load_secret_from_config(auth: dict[str, Any], key: str, file_key: str, env_key: str) -> str | None:
    if key in auth and auth[key] is not None:
        return str(auth[key])
    if file_key in auth and auth[file_key]:
        secret_path = Path(auth[file_key])
        try:
            return secret_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError as e:
            raise SpikeError(f"Secret file does not exist: {secret_path}") from e
    if env_key in auth and auth[env_key]:
        env_name = str(auth[env_key])
        value = os.environ.get(env_name)
        if value is None:
            raise SpikeError(f"Environment variable {env_name} is not set")
        return value
    return None


def build_auth_headers(config: dict[str, Any]) -> dict[str, str]:
    auth = config.get("auth") or {}
    if not isinstance(auth, dict):
        raise SpikeError("config.auth must be an object")

    auth_type = auth.get("type", "session_cookie")
    headers: dict[str, str] = {}

    print("\n=== Sensitive auth material printed by request ===")
    print("This spike prints cookies/tokens by default. Do not paste this output into public places.")

    if auth_type == "raw_cookie":
        # Send the full browser cookie string as-is — needed because the gateway
        # validates the full cookie context (AWSALB, io, xsrf, tenant.session.token etc).
        # Paste the entire Cookie header value from Burp/DevTools into the file.
        raw = load_secret_from_config(auth, "raw_cookie", "raw_cookie_file", "raw_cookie_env")
        if not raw:
            raise SpikeError("auth.type=raw_cookie requires raw_cookie, raw_cookie_file, or raw_cookie_env")
        headers["Cookie"] = raw.strip()
        print(f"Cookie: {raw.strip()[:80]}... (truncated)")
        return headers

    if auth_type == "session_cookie":
        cookie = load_secret_from_config(auth, "session_cookie", "session_cookie_file", "session_cookie_env")
        if not cookie:
            raise SpikeError("auth.type=session_cookie requires session_cookie, session_cookie_file, or session_cookie_env")
        cookie_name = auth.get("cookie_name", "cloud.session.token")
        stripped = cookie.strip()
        # If the file already contains a full "name=value" cookie header, use it as-is.
        if "=" in stripped and stripped.startswith(f"{cookie_name}="):
            cookie_header = stripped
        elif "=" in stripped and not stripped.startswith("{"):
            # Looks like a raw key=value but for a different name — use as-is.
            cookie_header = stripped
        else:
            cookie_header = f"{cookie_name}={stripped}"
        headers["Cookie"] = cookie_header
        print(f"Cookie: {cookie_header}")
        # Optional XSRF token — the gateway expects it as part of the Cookie header
        # (matching how the Confluence frontend sends it).
        xsrf_token = auth.get("xsrf_token") or os.environ.get("XSRF_TOKEN")
        if xsrf_token and xsrf_token != "TODO-xsrf-token":
            headers["Cookie"] = f"{cookie_header}; atlassian.xsrf.token={xsrf_token}"
            print(f"XSRF token appended to Cookie header")
        return headers

    if auth_type == "bearer_token":
        token = load_secret_from_config(auth, "bearer_token", "bearer_token_file", "bearer_token_env")
        if not token:
            raise SpikeError("auth.type=bearer_token requires bearer_token, bearer_token_file, or bearer_token_env")
        headers["Authorization"] = f"Bearer {token}"
        print(f"Authorization: Bearer {token}")
        return headers

    if auth_type == "basic_api_token":
        email = auth.get("email") or os.environ.get(str(auth.get("email_env", "")))
        token = load_secret_from_config(auth, "api_token", "api_token_file", "api_token_env")
        if not email or not token:
            raise SpikeError("auth.type=basic_api_token requires email and api_token/api_token_file/api_token_env")
        raw = f"{email}:{token}"
        encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
        print(f"Basic auth email: {email}")
        print(f"Basic auth API token: {token}")
        print(f"Authorization: Basic {encoded}")
        return headers

    raise SpikeError(f"Unsupported auth.type: {auth_type}")


def build_variables(config: dict[str, Any], manifest_context: dict[str, Any]) -> dict[str, Any]:
    context = {
        "manifest": manifest_context,
        "config": config,
    }

    if "variables" in config:
        variables = config["variables"]
    else:
        # Minimal default variables matching ConfluenceForgeContextTokenRequestInput.
        # Adjust extensionSpecificContexts.context fields after inspecting real errors.
        variables = {
            "cloudId": "${config.confluence.cloud_id}",
            "input": {
                "contextIds": ["${config.confluence.content_id}"],
                "extensionSpecificContexts": {
                    "appVersion": "1.0.0",
                    "extensionId": "${manifest.app_id}",
                    "extensionType": "${manifest.module_type}",
                    "installationId": "${config.confluence.installation_id}",
                    "context": {
                        "moduleKey": "${manifest.module_key}",
                        "type": "${manifest.module_type}",
                        "contentId": "${config.confluence.content_id}",
                        "spaceKey": "${config.confluence.space_key}",
                        "siteUrl": "${config.confluence.site_url}",
                        "extension": {
                            "type": "${manifest.module_type}",
                        },
                    },
                },
            }
        }

    rendered = render_template(variables, context)
    if not isinstance(rendered, dict):
        raise SpikeError("Rendered GraphQL variables must be an object")
    return rendered


def post_graphql(endpoint: str, headers: dict[str, str], query: str, variables: dict[str, Any]) -> tuple[int, str]:
    # The gateway requires this exact operation name for routing/validation.
    operation_name = "useGetContextTokenMutation"
    body = json.dumps({"operationName": operation_name, "query": query, "variables": variables}).encode("utf-8")
    # The Atlassian GraphQL gateway validates the Origin header as a CSRF guard.
    # Extract the origin from the endpoint URL (scheme + host only).
    origin = "/".join(endpoint.split("/")[:3])  # e.g. https://lhe2.atlassian.net
    # Add ?q=<operationName> query param as the browser does.
    url = f"{endpoint}?q={operation_name}"
    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": origin,
        "Referer": origin + "/",
        "X-Experimentalapi": "confluence-agg-beta",
        "X-Apollo-Operation-Name": operation_name,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        **headers,
    }
    req = urllib.request.Request(url, data=body, headers=request_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Confluence FCT minting spike for FSRT")
    parser.add_argument("--app-dir", type=Path, required=True, help="Forge app directory containing manifest.yml")
    parser.add_argument("--config", type=Path, required=True, help="Confluence FCT spike YAML config")
    parser.add_argument("--dry-run", action="store_true", help="Print request details but do not call GraphQL")
    args = parser.parse_args()

    try:
        config = load_yaml(args.config)
        product = config.get("product", "confluence")
        if product != "confluence":
            raise SpikeError("This spike is Confluence-only. Set product: confluence")

        module_key = (config.get("confluence") or {}).get("module_key")
        manifest, manifest_path = load_manifest(args.app_dir)
        manifest_context = extract_manifest_context(manifest, module_key)
        variables = build_variables(config, manifest_context)
        query = config.get("mutation") or DEFAULT_CONFLUENCE_MUTATION
        endpoint = config.get("graphql_endpoint")
        if not endpoint:
            raise SpikeError("config.graphql_endpoint is required")
        headers = build_auth_headers(config)

        print("\n=== Derived manifest context ===")
        print(f"Manifest path: {manifest_path}")
        print(json.dumps(manifest_context, indent=2, sort_keys=True))

        print("\n=== GraphQL endpoint ===")
        print(endpoint)

        print("\n=== GraphQL mutation ===")
        print(query)

        print("\n=== GraphQL variables ===")
        print(json.dumps(variables, indent=2, sort_keys=True))

        if args.dry_run:
            print("\nDry run requested; not sending GraphQL request.")
            return 0

        status, response_text = post_graphql(endpoint, headers, query, variables)
        print("\n=== GraphQL response ===")
        print(f"HTTP status: {status}")
        try:
            parsed = json.loads(response_text)
            print(json.dumps(parsed, indent=2))
            # Surface the FCT jwt if present
            fct = (parsed.get("data") or {}).get("confluence_generateForgeContextToken") or {}
            token_obj = fct.get("forgeContextToken")
            errors = fct.get("errors") or []
            if fct.get("success") and token_obj and token_obj.get("jwt"):
                print("\n=== SUCCESS: Forge Context Token ===")
                print(f"jwt:         {token_obj['jwt']}")
                print(f"expiresAt:   {token_obj.get('expiresAt')}")
                print(f"extensionId: {token_obj.get('extensionId')}")
            elif errors:
                print("\n[!] Server returned errors:")
                for err in errors:
                    print(f"    - {err.get('message')}")
            elif token_obj is None:
                print("\n[!] forgeContextToken is null — server accepted the request but returned no token.")
                print("    Possible causes:")
                print("    - installationId does not match the app+site combination")
                print("    - extensionId (app ARI) does not match the installation")
                print("    - contentId is not accessible to this app")
                print("    - the app is not actually installed on this site/product")
        except json.JSONDecodeError:
            print(response_text)
        return 0 if 200 <= status < 300 else 1
    except SpikeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
