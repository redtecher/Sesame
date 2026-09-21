"""Agent tools: filesystem exploration + HTTP interaction for LLM agent."""

import fnmatch
import json
import re
from pathlib import Path

from sesame.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# OpenAI function-calling tool schemas
# ---------------------------------------------------------------------------

TOOL_SCHEMAS = [
    # --- Filesystem tools (Stage 1: analysis) ---
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Search for files in the firmware filesystem by glob pattern. Use to discover scripts, configs, and binaries.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern, e.g. '*.lua', '*auth*', 'dispatcher.lua', '*.conf'",
                    },
                    "directory": {
                        "type": "string",
                        "description": "Directory to search in (relative to rootfs), e.g. 'usr/lib/lua', 'www'. Default: root",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the content of a file from the firmware filesystem. Supports Lua, JS, Python, PHP, shell scripts, configs, etc. Use 'offset' to read later parts of large files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path relative to rootfs, e.g. 'usr/lib/lua/luci/dispatcher.lua'",
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Maximum characters to read (default 3000, max 6000)",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Character offset to start reading from (for reading later parts of large files). Default: 0.",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_files",
            "description": "Search for a text pattern in firmware files. Returns matching file paths and lines. Use to find auth-related code, function names, crypto keys.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Search pattern (keyword or regex), e.g. 'checkUser', 'sha1|md5', 'password', 'nonce'",
                    },
                    "directory": {
                        "type": "string",
                        "description": "Directory to search in (relative to rootfs). Default: root",
                    },
                    "file_glob": {
                        "type": "string",
                        "description": "Only search files matching this glob, e.g. '*.lua', '*.js'. Default: all text files",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results (default 30)",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    # --- Runtime tools (Stage 3: recovery analysis) ---
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send an HTTP request to the rehosted firmware. Use for login attempts, page probes, following redirects, and obtaining session cookies/tokens.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL path, e.g. '/cgi-bin/cstecgi.cgi', '/cgi-bin/luci/admin/login'",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method: GET or POST (default POST)",
                    },
                    "body": {
                        "description": "Request body: key-value pairs (object) for form/json, or raw string for XML/SOAP",
                    },
                    "content_type": {
                        "type": "string",
                        "description": "Content type: 'form' (default), 'json', or 'xml' for raw XML/SOAP body",
                    },
                    "cookies": {
                        "type": "object",
                        "description": "Cookies to send with the request, e.g. {\"SESSION_ID\": \"value\"}",
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Whether to follow HTTP redirects (default true)",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_navigate",
            "description": "Navigate the browser to a URL and return the rendered page content. Use for analyzing login pages, detecting form structures, and inspecting JavaScript-rendered content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL path to navigate to, e.g. '/login.html', '/cgi-bin/luci/'",
                    },
                    "extract_cookies": {
                        "type": "boolean",
                        "description": "If true, return all browser cookies (default false)",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_login",
            "description": "Perform interactive login using browser automation. Use when HTTP requests fail due to JavaScript requirements, CSRF tokens, or complex login flows. The browser will fill username/password fields and submit the form, then return session cookies.",
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to fill in the login form",
                    },
                    "password": {
                        "type": "string",
                        "description": "Password to fill in the login form",
                    },
                    "login_url": {
                        "type": "string",
                        "description": "URL of the login page (default: /login.html)",
                    },
                },
                "required": ["username", "password"],
            },
        },
    },
]

# --- Execution tools (Stage 4: bypass execution) ---
SHELL_EXEC_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "shell_exec",
        "description": "Execute a command inside the QEMU VM shell. Returns exit code, stdout, stderr. Use for modifying config, restarting services, writing files.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute in the QEMU VM",
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in seconds (default 15)",
                },
            },
            "required": ["command"],
        },
    },
}

CHECK_RESULT_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "check_result",
        "description": "Verify bypass success by sending an HTTP request and analyzing the response for success/failure indicators. Use after executing bypass commands.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to check (e.g. login endpoint or a post-auth page)",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (default GET)",
                },
                "body": {
                    "description": "Request body for login attempts",
                },
                "expected_success": {
                    "type": "string",
                    "description": "What to look for to confirm success (e.g. 'token in JSON', 'Set-Cookie header')",
                },
            },
            "required": ["url"],
        },
    },
}

# Filesystem-only tool schemas (for Stage 1)
FILESYSTEM_TOOL_SCHEMAS = TOOL_SCHEMAS[:3]
# Runtime tool schemas (for Stage 3)
RUNTIME_TOOL_SCHEMAS = TOOL_SCHEMAS[3:]
# All tools
ALL_TOOL_SCHEMAS = TOOL_SCHEMAS
# Execution tools (for Stage 4 — includes shell_exec + check_result)
EXECUTION_TOOL_SCHEMAS = ALL_TOOL_SCHEMAS + [SHELL_EXEC_TOOL_SCHEMA, CHECK_RESULT_TOOL_SCHEMA]
ALL_TOOL_SCHEMAS = TOOL_SCHEMAS

# File extensions considered text-readable
_TEXT_EXTENSIONS = {
    ".lua", ".py", ".php", ".sh", ".js", ".html", ".htm", ".css", ".json",
    ".xml", ".yaml", ".yml", ".conf", ".cfg", ".ini", ".txt", ".md",
    ".asp", ".aspx", ".cgi", ".pl", ".rb", ".tcl", ".conf",
    ".properties", ".toml", ".csv",
}


def execute_tool(rootfs_path: str, name: str, arguments: dict, bundle=None) -> str:
    """Dispatch a tool call and return the result string."""
    try:
        if name == "search_files":
            return _search_files(rootfs_path, arguments)
        elif name == "read_file":
            return _read_file(rootfs_path, arguments)
        elif name == "grep_files":
            return _grep_files(rootfs_path, arguments)
        elif name == "http_request":
            return _http_request(arguments, bundle)
        elif name == "browser_navigate":
            return _browser_navigate(arguments, bundle)
        elif name == "browser_login":
            return _browser_login(arguments, bundle)
        elif name == "shell_exec":
            return _shell_exec(arguments, bundle)
        elif name == "check_result":
            return _check_result(arguments, bundle)
        else:
            return f"Unknown tool: {name}"
    except Exception as e:
        logger.warning(f"Tool error ({name}): {e}")
        return f"Tool error ({name}): {e}"


# ---------------------------------------------------------------------------
# Filesystem tools
# ---------------------------------------------------------------------------

def _search_files(rootfs_path: str, args: dict) -> str:
    pattern = args.get("pattern", "*")
    directory = args.get("directory", "")
    max_results = 30

    root = Path(rootfs_path) / directory if directory else Path(rootfs_path)
    if not root.exists():
        return f"Directory not found: {directory}"

    matches = []
    try:
        for item in root.rglob(pattern):
            if item.is_file() and len(matches) >= max_results:
                break
            if item.is_file():
                rel = item.relative_to(rootfs_path)
                size = item.stat().st_size
                matches.append(f"{rel} ({size} bytes)")
    except PermissionError:
        pass

    if not matches:
        return f"No files matching '{pattern}' found in {directory or '/'}"

    header = f"Found {len(matches)} files matching '{pattern}' in {directory or '/'}:\n"
    return header + "\n".join(matches)


def _read_file(rootfs_path: str, args: dict) -> str:
    path = args.get("path", "")
    max_chars = min(args.get("max_chars", 3000), 6000)
    offset = max(args.get("offset", 0), 0)

    full_path = Path(rootfs_path) / path.lstrip("/")
    if not full_path.exists():
        return f"File not found: {path}"
    if not full_path.is_file():
        return f"Not a file: {path}"
    if full_path.stat().st_size > 200 * 1024:
        return f"File too large ({full_path.stat().st_size} bytes): {path}"

    # Check if there's a decompiled version available (for Fate/Z encrypted Lua)
    decompiled_content = _try_read_decompiled(rootfs_path, path, max_chars, offset)
    if decompiled_content is not None:
        return decompiled_content

    ext = full_path.suffix.lower()
    if ext not in _TEXT_EXTENSIONS and ext:
        if full_path.stat().st_size > 50 * 1024:
            return f"Binary file (.{ext}): {path}"

    try:
        content = full_path.read_text(errors="ignore")
    except Exception as e:
        return f"Cannot read file: {e}"

    # Detect Fate/Z encrypted content (header is \x1bFate/Z)
    if content and "Fate/Z" in content[:30]:
        return f"--- {path} ({full_path.stat().st_size} bytes) ---\n[ENCRYPTED] Fate/Z encrypted. No decompiled version."

    # Apply offset
    if offset > 0:
        content = content[offset:]

    truncated = len(content) > max_chars
    content = content[:max_chars]

    offset_info = f" (offset={offset})" if offset > 0 else ""
    header = f"--- {path} ({full_path.stat().st_size} bytes{offset_info}) ---\n"
    footer = "\n... (truncated)" if truncated else ""
    return header + content + footer


# Global decompiled cache directory — set by pipeline before agent runs
_decompiled_cache_dir: str = ""


def set_decompiled_cache(cache_dir: str) -> None:
    """Set the directory containing decompiled Lua files."""
    global _decompiled_cache_dir
    _decompiled_cache_dir = cache_dir


def _try_read_decompiled(rootfs_path: str, rel_path: str, max_chars: int, offset: int = 0) -> str | None:
    """Try to read a decompiled version of a Lua file from cache."""
    if not _decompiled_cache_dir:
        return None

    # Only relevant for .lua files
    if not rel_path.endswith(".lua"):
        return None

    # Check if original is Fate/Z encrypted
    full_path = Path(rootfs_path) / rel_path.lstrip("/")
    try:
        with open(full_path, "rb") as f:
            if f.read(7) != b"\x1bFate/Z":
                return None  # Not encrypted, use normal read
    except Exception:
        return None

    # Look for decompiled version
    decompiled = Path(_decompiled_cache_dir) / rel_path.lstrip("/")
    if not decompiled.exists():
        return f"--- {rel_path} ({full_path.stat().st_size} bytes) ---\n[ENCRYPTED] Fate/Z encrypted Lua — decompilation not available for this file."

    try:
        content = decompiled.read_text(errors="ignore")
    except Exception:
        return None

    # Apply offset
    if offset > 0:
        content = content[offset:]

    truncated = len(content) > max_chars
    content = content[:max_chars]

    header = f"--- {rel_path} ({full_path.stat().st_size} bytes, decompiled) ---\n"
    footer = "\n... (truncated)" if truncated else ""
    return header + content + footer


def _grep_files(rootfs_path: str, args: dict) -> str:
    pattern = args.get("pattern", "")
    directory = args.get("directory", "")
    file_glob = args.get("file_glob", "")
    max_results = min(args.get("max_results", 30), 60)

    root = Path(rootfs_path) / directory if directory else Path(rootfs_path)
    if not root.exists():
        return f"Directory not found: {directory}"

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        regex = re.compile(re.escape(pattern), re.IGNORECASE)

    results = []

    # Build candidate file list from rootfs
    if file_glob:
        candidates = list(root.rglob(file_glob))
    else:
        candidates = []
        for ext in sorted(_TEXT_EXTENSIONS):
            candidates.extend(root.rglob(f"*{ext}"))

    for item in candidates:
        if not item.is_file():
            continue
        if item.stat().st_size > 200 * 1024:
            continue
        if len(results) >= max_results:
            break

        rel = item.relative_to(rootfs_path)

        # For .lua files, check if there's a decompiled version to search instead
        search_item = item
        is_decompiled = False
        if _decompiled_cache_dir and item.suffix.lower() == ".lua":
            try:
                with open(item, "rb") as f:
                    if f.read(7) == b"\x1bFate/Z":
                        decompiled = Path(_decompiled_cache_dir) / str(rel).lstrip("/")
                        if decompiled.exists():
                            search_item = decompiled
                            is_decompiled = True
            except Exception:
                pass

        try:
            content = search_item.read_text(errors="ignore")
            for i, line in enumerate(content.splitlines(), 1):
                if regex.search(line):
                    suffix = " [decompiled]" if is_decompiled else ""
                    results.append(f"{rel}:{i}{suffix}: {line.strip()[:150]}")
                    if len(results) >= max_results:
                        break
        except Exception:
            continue

    if not results:
        return f"No matches for '{pattern}' in {directory or '/'}"

    header = f"Found {len(results)} matches for '{pattern}' in {directory or '/'}:\n"
    return header + "\n".join(results)


# ---------------------------------------------------------------------------
# Runtime tools
# ---------------------------------------------------------------------------

def _http_request(args: dict, bundle) -> str:
    """Send an HTTP request to the rehosted firmware and return the response details."""
    if not bundle or not bundle.http:
        return "Error: HTTP access not available (no bundle.http)"

    url = args.get("url", "")
    method = (args.get("method") or "POST").upper()
    body = args.get("body") or {}
    content_type = args.get("content_type") or "form"
    cookies = args.get("cookies") or {}
    follow_redirects = args.get("follow_redirects", True)

    try:
        if method == "GET":
            response = bundle.http.get_with_cookies(url, cookies) if cookies else bundle.http.get(url)
        elif content_type == "xml":
            # Raw XML/SOAP body — body can be a string
            xml_body = body if isinstance(body, str) else str(body)
            # Extract SOAPAction from args or body hints
            headers = {"Content-Type": "text/xml"}
            if isinstance(body, str):
                # Try to infer SOAPAction from XML content
                import re as _re
                action_match = _re.search(r'<(\w+) xmlns="http://purenetworks.com/HNAP1/', xml_body)
                if action_match:
                    headers["SOAPAction"] = f'"http://purenetworks.com/HNAP1/{action_match.group(1)}"'
            response = bundle.http.client.post(
                bundle.http.base_url.rstrip("/") + "/" + url.lstrip("/"),
                content=xml_body.encode(),
                headers=headers,
                cookies=cookies or None,
            )
        elif content_type == "json":
            clean_body = {k: v for k, v in body.items() if not (isinstance(v, str) and v.startswith("<"))} if isinstance(body, dict) else body
            response = bundle.http.client.post(
                bundle.http.base_url.rstrip("/") + "/" + url.lstrip("/"),
                content=json.dumps(clean_body).encode(),
                headers={"Content-Type": "application/json"},
                cookies=cookies or None,
            )
        else:
            clean_body = {k: v for k, v in body.items() if not (isinstance(v, str) and v.startswith("<"))} if isinstance(body, dict) else body
            response = bundle.http.post_with_cookies(url, data=clean_body, cookies=cookies) if cookies else bundle.http.post(url, data=clean_body)

        status = response.status_code
        resp_body = response.text
        set_cookie = response.headers.get("Set-Cookie", "")
        location = response.headers.get("Location", "")

        result_parts = [f"HTTP {status}"]
        if set_cookie:
            result_parts.append(f"Set-Cookie: {set_cookie}")
        if location:
            result_parts.append(f"Location: {location}")

        # For large HTML responses, extract key elements (form actions, API URLs)
        if len(resp_body) > 2000 and ("<html" in resp_body[:500].lower() or "<!doctype" in resp_body[:500].lower()):
            import re as _re
            snippets = [resp_body[:800]]
            # Extract form actions
            for m in _re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', resp_body, _re.IGNORECASE):
                snippets.append(f"[FORM ACTION]: {m.group(1)}")
            # Extract build_url / API endpoint patterns
            for m in _re.finditer(r'build_url\(["\']([^)]+)["\']?\)', resp_body):
                snippets.append(f"[ROUTE]: {m.group(1)}")
            # Extract $.post / $.ajax URLs
            for m in _re.finditer(r'\$\.(?:post|ajax)\s*\(\s*["\']([^"\']+)["\']', resp_body):
                snippets.append(f"[AJAX URL]: {m.group(1)}")
            # Extract Encrypt references
            for m in _re.finditer(r'Encrypt\.\w+', resp_body):
                if m.group() not in str(snippets):
                    snippets.append(f"[JS]: {m.group()}")
            result_parts.append(f"Body ({len(resp_body)} chars, summarized):\n" + "\n".join(snippets))
        else:
            result_parts.append(f"Body ({len(resp_body)} chars): {resp_body[:3000]}")

        # Follow redirects if requested
        if follow_redirects and status in {301, 302} and location:
            try:
                redir_resp = bundle.http.get_with_cookies(location, cookies) if cookies else bundle.http.get(location)
                redir_cookie = redir_resp.headers.get("Set-Cookie", "")
                result_parts.append(f"\n--- Redirect {redir_resp.status_code} -> {location} ---")
                if redir_cookie:
                    result_parts.append(f"Set-Cookie: {redir_cookie}")
                result_parts.append(f"Body ({len(redir_resp.text)} chars): {redir_resp.text[:1000]}")
            except Exception as e:
                result_parts.append(f"Redirect follow failed: {e}")

        logger.info(f"  http_request: {method} {url} -> {status}, Set-Cookie={'yes' if set_cookie else 'no'}")
        return "\n".join(result_parts)

    except Exception as e:
        return f"HTTP request error: {e}"


def _browser_navigate(args: dict, bundle) -> str:
    """Navigate the browser to a URL and return rendered page content."""
    if not bundle or not getattr(bundle, "browser", None):
        return "Error: Browser not available"

    url = args.get("url", "")
    extract_cookies = args.get("extract_cookies", False)

    try:
        browser = bundle.browser
        full_url = bundle.input.web_url.rstrip("/") + "/" + url.lstrip("/") if not url.startswith("http") else url
        result = browser.navigate(full_url)

        parts = [f"Status: {result.status}", f"Final URL: {result.final_url}"]
        if result.content_snippet:
            parts.append(f"Content ({len(result.content_snippet)} chars):\n{result.content_snippet[:2000]}")
        if extract_cookies:
            cookies = browser.get_cookies()
            parts.append(f"Cookies: {json.dumps(cookies)}")
        if result.error:
            parts.append(f"Error: {result.error}")

        return "\n".join(parts)
    except Exception as e:
        return f"Browser navigate error: {e}"


def _browser_login(args: dict, bundle) -> str:
    """Perform interactive login using browser automation."""
    if not bundle or not getattr(bundle, "browser", None):
        return "Error: Browser not available"

    username = args.get("username", "")
    password = args.get("password", "")
    login_url = args.get("login_url", "/login.html")

    if not username or not password:
        return "Error: username and password are required"

    try:
        browser = bundle.browser
        base_url = bundle.input.web_url.rstrip("/")
        full_url = base_url + "/" + login_url.lstrip("/") if not login_url.startswith("http") else login_url

        logger.info(f"  browser_login: navigating to {full_url}")

        # Navigate to login page
        nav_result = browser.navigate(full_url)
        if nav_result.status == "error":
            return f"Failed to load login page: {nav_result.error}"

        # Try to find and fill login form
        # Common field selectors
        username_selectors = [
            'input[name="username"]',
            'input[name="user"]',
            'input[id="username"]',
            'input[type="text"]',
            '#username',
            '#user',
        ]

        password_selectors = [
            'input[name="password"]',
            'input[name="pass"]',
            'input[id="password"]',
            'input[type="password"]',
            '#password',
            '#pass',
        ]

        # Try to fill username field
        username_filled = False
        for selector in username_selectors:
            try:
                browser._page.fill(selector, username, timeout=2000)
                username_filled = True
                logger.info(f"  browser_login: filled username with selector {selector}")
                break
            except Exception:
                continue

        if not username_filled:
            return "Error: Could not find username field on login page"

        # Try to fill password field
        password_filled = False
        for selector in password_selectors:
            try:
                browser._page.fill(selector, password, timeout=2000)
                password_filled = True
                logger.info(f"  browser_login: filled password with selector {selector}")
                break
            except Exception:
                continue

        if not password_filled:
            return "Error: Could not find password field on login page"

        # Try to submit form
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Login")',
            'button:has-text("login")',
            'button:has-text("Sign in")',
            '#login-button',
            '.login-button',
        ]

        submitted = False
        for selector in submit_selectors:
            try:
                browser._page.click(selector, timeout=2000)
                browser._page.wait_for_load_state("networkidle", timeout=10000)
                submitted = True
                logger.info(f"  browser_login: clicked submit with selector {selector}")
                break
            except Exception:
                continue

        if not submitted:
            # Try form submit via Enter key
            try:
                browser._page.press('input[type="password"]', "Enter")
                browser._page.wait_for_load_state("networkidle", timeout=10000)
                logger.info("  browser_login: submitted via Enter key")
            except Exception as e:
                return f"Error: Could not submit login form: {e}"

        # Wait a bit for any post-login redirects
        import time
        time.sleep(2)

        # Check result
        current_url = browser.get_current_url()
        cookies = browser.get_cookies()
        page_text = browser.get_page_text()[:1000]

        # Determine success
        success_indicators = [
            "login" not in current_url.lower(),
            any(name in cookies for name in ["sessionid", "session", "token", "auth", "sysauth"]),
            any(word in page_text.lower() for word in ["logout", "dashboard", "welcome"]),
        ]

        failure_indicators = [
            any(word in page_text.lower() for word in ["invalid", "incorrect", "failed", "error"]),
        ]

        if any(success_indicators) and not any(failure_indicators):
            logger.info(f"  browser_login: SUCCESS - cookies={list(cookies.keys())}")
            return (
                f"Login successful!\n"
                f"Current URL: {current_url}\n"
                f"Cookies: {json.dumps(cookies)}\n"
                f"Page preview: {page_text[:500]}"
            )
        else:
            logger.warning(f"  browser_login: FAILED - current_url={current_url}")
            return (
                f"Login may have failed\n"
                f"Current URL: {current_url}\n"
                f"Cookies: {json.dumps(cookies)}\n"
                f"Page preview: {page_text[:500]}"
            )

    except Exception as e:
        logger.error(f"  browser_login error: {e}")
        return f"Browser login error: {e}"


def _shell_exec(args: dict, bundle) -> str:
    """Execute a command in the QEMU VM shell."""
    if not bundle or not getattr(bundle, "qemu", None):
        return "Error: QEMU connection not available (no bundle.qemu)"

    command = args.get("command", "")
    timeout = args.get("timeout", 15.0)

    try:
        result = bundle.qemu.exec(command, timeout=timeout)
        parts = []
        if result.stdout:
            parts.append(f"stdout: {result.stdout[:3000]}")
        if result.stderr:
            parts.append(f"stderr: {result.stderr[:500]}")
        parts.append(f"exit_code: {result.exit_code}")
        if result.timed_out:
            parts.append("WARNING: command timed out")
        logger.info(f"  shell_exec: {command[:80]} -> exit={result.exit_code}")
        return "\n".join(parts)
    except Exception as e:
        logger.warning(f"  shell_exec error: {e}")
        return f"shell_exec error: {e}"


def _check_result(args: dict, bundle) -> str:
    """Send HTTP request and analyze response for bypass success indicators."""
    # First get the raw HTTP response
    http_result = _http_request(args, bundle)

    # Add automated analysis
    expected = args.get("expected_success", "")
    analysis = []

    # Success indicators
    if "Set-Cookie:" in http_result:
        analysis.append("SUCCESS INDICATOR: Cookie was set (Set-Cookie header found)")
    if '"token"' in http_result or '"stok"' in http_result:
        analysis.append("SUCCESS INDICATOR: Token found in JSON response")
    if '"code":0' in http_result or '"code": 0' in http_result:
        analysis.append("SUCCESS INDICATOR: Response code is 0 (success)")
    if '"url"' in http_result and ("stok" in http_result.lower() or "token" in http_result.lower()):
        analysis.append("SUCCESS INDICATOR: URL with token in response")

    # Failure indicators
    if "302" in http_result[:50] and "login" in http_result.lower():
        analysis.append("FAILURE: Redirected to login page")
    elif "302" in http_result[:50] or "301" in http_result[:50]:
        analysis.append("POSSIBLE FAILURE: Redirect response")
    if '"code":401' in http_result or '"code": 401' in http_result:
        analysis.append("FAILURE: 401 Unauthorized in response body")
    if "not auth" in http_result.lower():
        analysis.append("FAILURE: 'not auth' in response")
    if "invalid" in http_result.lower() and "token" in http_result.lower():
        analysis.append("FAILURE: Invalid token")

    if analysis:
        http_result += "\n\n--- Auto Analysis ---\n" + "\n".join(analysis)
    return http_result
