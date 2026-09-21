"""LLM stage prompts and context assemblers for 3-stage reasoning pipeline."""

from pathlib import Path


def assemble_stage1_context(surface, settings) -> str:
    endpoints_summary = []
    for ep in surface.endpoints[:32]:
        hints_str = ", ".join(f"{k}={v}" for k, v in ep.hints.items()) if ep.hints else ""
        endpoints_summary.append(f"  {ep.method} {ep.url} [{', '.join(ep.tags)}] {hints_str}".strip())

    key_assets = []
    for asset in surface.frontend_assets:
        name = asset.path.lower()
        if any(k in name for k in ["topicurl", "config.js", "common.js", "layout.js", "login", "main.js"]):
            try:
                content = Path(asset.path).read_text(errors="ignore")
                key_assets.append(f"\n--- {asset.path} (first 800 chars) ---\n{content[:800]}")
            except Exception:
                key_assets.append(f"\n--- {asset.path} (unreadable) ---")
            if len(key_assets) >= 6:
                break

    configs_summary = []
    for c in surface.config_sources[:12]:
        configs_summary.append(f"  {c.source_type}: {c.path} evidence={c.evidence[:3]}")

    binary_parts = _assemble_binary_analysis(surface)

    parts = [
        "=== ENDPOINTS ===",
        "\n".join(endpoints_summary),
        "\n=== KEY FRONTEND ASSETS ===",
        *key_assets,
        "\n=== CONFIG SOURCES ===",
        "\n".join(configs_summary),
    ]
    if binary_parts:
        parts.append("\n=== BINARY ANALYSIS (from radare2) ===")
        parts.extend(binary_parts)

    return "\n".join(parts)[:8000]


def _assemble_binary_analysis(surface) -> list[str]:
    parts = []
    for binary in surface.web_binaries[:3] + surface.cgi_binaries[:5]:
        analysis = binary.analysis
        if not analysis or analysis.arch == "unknown":
            continue
        block = f"\n--- {binary.name} ({analysis.arch}, {analysis.bits}-bit, {analysis.endian}) ---"
        if analysis.auth_strings:
            strings = ", ".join(repr(s) for s in analysis.auth_strings[:12])
            block += f"\n  auth-related strings: [{strings}]"
        if analysis.auth_functions:
            funcs = ", ".join(analysis.auth_functions[:8])
            block += f"\n  auth-related functions: [{funcs}]"
        if analysis.key_imports:
            imports = ", ".join(analysis.key_imports[:10])
            block += f"\n  key imports: [{imports}]"
        if analysis.auth_decompilation:
            block += f"\n  decompilation:\n{analysis.auth_decompilation[:500]}"
        parts.append(block)
    return parts


STAGE1_PROMPT = """You are a firmware security researcher analyzing an IoT router's authentication system from extracted filesystem, binary reverse engineering, and live HTTP probe data.

Your task: Identify the authentication architecture. Based on the endpoints, JavaScript code, config sources, AND binary analysis (if present), determine:

1. What type of auth system is this? (form-based CGI, token-based API, HTTP Basic, custom protocol, etc.)
2. What is the exact login URL, method, and parameters?
3. How does the session work after login? (cookie name, token header, etc.)
4. Where might credentials be stored? (nvram, config file, hardcoded, etc.)
5. What are the default credentials to try?
6. What happens after successful login? (redirect URL, cookie set, etc.)
7. How are post-auth API calls dispatched? (CGI with topic param, REST path, etc.)

**Known auth architecture patterns** (match against what you find):
- **GoAhead**: /goform/formLogin, Cookie: session_id=VALUE, common in MIPS routers
- **Boa**: HTTP Basic or /cgi-bin/ form handlers, common in older D-Link/Netgear
- **LuCI/uhttpd**: Lua session store in /tmp/luci-sessions/, login via /cgi-bin/luci/...
- **HNAP**: SOAP at /HNAP1/ with HMAC challenge, common in D-Link/Linksys
- **CSTE custom CGI**: /cgi-bin/cstecgi.cgi with topicurl dispatch
- **mini_httpd**: HTTP Basic auth or custom CGI

**Also check for bypass conditions**:
- Hardcoded backdoor accounts (base64 strings, user:pass pairs in binary)
- Debug mode flags (debug_mode, bypass_auth, no_auth in code)
- Unauthenticated admin endpoints (paths without auth checks)
- Predictable session cookie generation (md5 of timestamp, fixed tokens)
- Auth check logic flaws (if authenticated || debug_mode)

If BINARY ANALYSIS section is present, use it to understand:
- The auth-check functions and their logic (from decompilation)
- How credentials are verified (strcmp patterns, nvram lookups)
- Session cookie format and validation
- Any hardcoded credentials or backdoor paths in the binary

Output ONLY valid JSON matching this schema:
{{
  "auth_type": "string describing auth architecture type",
  "login_url": "exact URL for login request",
  "login_method": "POST or GET",
  "login_content_type": "form or json",
  "login_params": {{"key": "value template, use <placeholder> for unknowns"}},
  "session_mechanism": "description of how sessions work",
  "session_cookie_name": "expected cookie name if cookie-based",
  "credential_storage": "where credentials are stored",
  "credential_defaults": [{{"username": "x", "password": "y"}}],
  "post_login_redirect": "expected redirect after login",
  "auth_gate_pattern": "how auth-gated pages behave (redirect pattern, etc.)",
  "api_dispatch_mechanism": "how API calls are routed",
  "key_observations": ["list of important observations"],
  "crypto_details": "crypto chain — REQUIRED (e.g. sha1(nonce+sha1(pwd+key)))",
  "login_curl": "ready-to-use curl command — REQUIRED"
}}

Context data:
{context}"""


def assemble_stage2_context(architecture, test_targets, runtime_evidence) -> str:
    probe_summary = []
    for t in test_targets[:30]:
        probe_summary.append(f"  {t.method} {t.url} -> {t.reachability.value} blockers={t.blockers}")

    evidence_summary = []
    for e in runtime_evidence[:8]:
        evidence_summary.append(f"  [{e.source}] {e.command}: {e.observation[:150]}")

    parts = [
        "=== AUTH ARCHITECTURE (from Stage 1) ===",
        f"type={architecture.auth_type}",
        f"login={architecture.login_method} {architecture.login_url}",
        f"session={architecture.session_mechanism}",
        f"cookie={architecture.session_cookie_name}",
        "",
        "=== HTTP PROBE RESULTS ===",
        "\n".join(probe_summary),
    ]
    if evidence_summary:
        parts += [
            "",
            "=== RUNTIME EVIDENCE ===",
            "\n".join(evidence_summary),
        ]
    return "\n".join(parts)[:4000]


STAGE2_PROMPT = """You are analyzing why authentication fails in a rehosted IoT firmware environment.

Given the auth architecture analysis and actual HTTP probe results from the live rehosted firmware, determine:

1. What mismatches exist between expected and observed behavior?
2. For each mismatch, which layer is broken: source (missing config), representation (wrong format), transfer (broken propagation), or consumption (runtime check)?
3. Why does authentication specifically fail in this rehosted environment?

Classify each mismatch into one of these layers:
- source_mismatch: Config or credential state missing in rehosted env (e.g., empty NVRAM, missing UCI config, no session token files)
- representation_mismatch: Data format or encoding differs (e.g., password hashing mismatch, token format issues)
- transfer_mismatch: Auth state propagation broken between components (e.g., HTTP→HTTPS redirect blocking access, nginx proxy misconfiguration, service communication failure)
- consumption_mismatch: Runtime auth check blocks access (e.g., session validation, permission checks)

**IMPORTANT**: If you see HTTP probe results with blockers like 'redirect_to_https://...' or HTTP 301/302 redirects to HTTPS, this is a **transfer_mismatch** because the HTTP→HTTPS redirect layer is blocking access in the rehosted environment (HTTPS typically unavailable due to self-signed certificates).

Output ONLY valid JSON:
{{
  "mismatches": [
    {{
      "layer": "source_mismatch|representation_mismatch|transfer_mismatch|consumption_mismatch",
      "title": "short title",
      "description": "what is wrong and why",
      "evidence": ["observed evidence"],
      "confidence": 0.0-1.0,
      "recovery_relevance": "how this relates to fixing auth"
    }}
  ]
}}

Context:
{context}"""


def assemble_stage3_context(architecture, mismatches, surface=None, bundle=None) -> str:
    mismatch_summary = []
    for m in mismatches[:6]:
        mismatch_summary.append(f"  [{m.layer}] {m.title}: {m.description}")

    parts = [
        "=== AUTH ARCHITECTURE ===",
        f"login: {architecture.login_method} {architecture.login_url} ({architecture.login_content_type})",
        f"params: {architecture.login_params}",
        f"session: {architecture.session_mechanism} via {architecture.session_cookie_name}",
        f"defaults: {architecture.credential_defaults}",
        f"post_login: {architecture.post_login_redirect}",
        f"crypto: {architecture.crypto_details}",
        "",
        "=== IDENTIFIED MISMATCHES ===",
        *mismatch_summary,
    ]

    if surface:
        hints = _extract_auth_state_hints(surface)
        if hints:
            parts.append("")
            parts.append("=== BINARY AUTH STATE HINTS ===")
            parts.extend(hints)

    parts.append("")
    parts.append("=== RUNTIME ACCESS ===")
    parts.append("browser: available (Playwright)")
    parts.append("http: available (httpx)")

    return "\n".join(parts)[:4000]


def _extract_auth_state_hints(surface) -> list[str]:
    state_files = set()
    nvram_keys = set()
    key_imports = set()
    for b in surface.web_binaries + surface.cgi_binaries:
        if not b.analysis or b.analysis.arch == "unknown":
            continue
        for s in b.analysis.auth_strings:
            if s.startswith("/tmp/") or s.startswith("/var/"):
                state_files.add(s)
        for imp in b.analysis.key_imports:
            if "nvram" in imp.lower():
                key_imports.add(imp)
            if "strcmp" in imp.lower() or "memcmp" in imp.lower():
                key_imports.add(imp)
        for f in b.analysis.auth_functions:
            if "nvram" in f.lower():
                nvram_keys.add(f)

    hints = []
    if state_files:
        hints.append(f"state_files: {sorted(state_files)}")
    if nvram_keys:
        hints.append(f"nvram_related_functions: {sorted(nvram_keys)}")
    if key_imports:
        hints.append(f"key_imports: {sorted(key_imports)}")
    return hints


STAGE3_PROMPT = """You are generating a concrete bypass plan for authentication in a rehosted IoT firmware.

Your task is to **analyze and output a bypass plan** — you do NOT execute it. The plan will be presented to a security researcher who will execute the commands manually in the firmware's emulation shell.

Based on the auth architecture, identified mismatches, and binary analysis hints, produce a bypass plan that includes:
1. Specific shell commands to run in the emulation environment
2. HTTP requests to verify the bypass worked
3. Fallback strategies if the primary approach fails

**Strategy priority**:
1. **Empty/default credentials**: If NVRAM is empty or defaults exist, try login with empty password or known defaults
2. **Hash injection**: If credentials are stored as hash (sha1/md5), compute hash and write to UCI/NVRAM via shell
3. **Token extraction**: If token is in URL (token_location=url_path), login and extract token from JSON response
4. **State file creation**: If auth checks require state files (/tmp/login_flag etc.), create them via shell
5. **Debug mode**: If debug_mode flag exists, enable it via shell
6. **Cookie forging**: If session cookie is predictable, construct it directly
7. **Timing bypass**: If auth has race condition at boot, send request immediately after restart

Output ONLY valid JSON:
{{
  "strategy": "strategy name",
  "description": "human-readable description of the approach",
  "shell_commands": ["exact commands to run in emulation shell"],
  "credentials_to_try": [{{"username": "admin", "password": ""}}],
  "http_verification": ["curl commands to verify bypass works"],
  "expected_session": {{"cookie_name": "SESSION_ID", "token_pattern": ";stok=TOKEN"}},
  "fallback_strategies": ["description of fallback approaches if primary fails"],
  "confidence": 0.0-1.0
}}

Context:
{context}"""


# ---------------------------------------------------------------------------
# Agent-based Stage 1: LLM explores filesystem with tools
# ---------------------------------------------------------------------------


def assemble_basic_context(surface, rootfs_path: str = "") -> str:
    """Build minimal context for agent-based Stage 1 — no source code, just indices."""
    parts = []

    # Binary list
    bins = []
    for b in surface.web_binaries[:5] + surface.cgi_binaries[:8]:
        info = f"  {b.name} (role={b.role.value})"
        if b.analysis and b.analysis.arch != "unknown":
            info += f" arch={b.analysis.arch} bits={b.analysis.bits} endian={b.analysis.endian}"
        bins.append(info)
    if bins:
        parts.append("=== BINARIES ===")
        parts.extend(bins)

    # Endpoint list
    eps = []
    for ep in surface.endpoints[:40]:
        hints_str = ", ".join(f"{k}={v}" for k, v in ep.hints.items()) if ep.hints else ""
        eps.append(f"  {ep.method} {ep.url} [{', '.join(ep.tags)}] {hints_str}".strip())
    if eps:
        parts.append("\n=== ENDPOINTS ===")
        parts.extend(eps)

    # Config sources
    cfgs = []
    for c in surface.config_sources[:15]:
        cfgs.append(f"  {c.source_type}: {c.path} evidence={c.evidence[:3]}")
    if cfgs:
        parts.append("\n=== CONFIG SOURCES ===")
        parts.extend(cfgs)

    # Frontend assets (just file paths)
    assets = []
    for a in surface.frontend_assets[:20]:
        assets.append(f"  {a.path} ({a.kind})")
    if assets:
        parts.append("\n=== FRONTEND ASSETS ===")
        parts.extend(assets)

    # Pre-extract crypto/auth definitions from large JS/template files
    crypto_blocks = _pre_extract_crypto_definitions(surface, rootfs_path)
    if crypto_blocks:
        parts.append("\n=== PRE-EXTRACTED CRYPTO/AUTH DEFINITIONS ===")
        parts.extend(crypto_blocks)
        parts.append("(You do NOT need to read these files again — their crypto content is shown above)")

    return "\n".join(parts)[:6000]


def _pre_extract_crypto_definitions(surface, rootfs_path: str = "") -> list[str]:
    """Pre-extract Encrypt/crypto definitions from large frontend files.

    This prevents the agent from wasting rounds reading large files in tiny chunks.
    """
    crypto_patterns = [
        "var Encrypt", "Encrypt =", "Encrypt={", "Encrypt.prototype",
        "function Encrypt", "encrypt:", "oldPwd", "sha1", "SHA1",
        "CryptoJS", "crypto.subtle", "nonce", "hashPassword",
    ]
    blocks = []
    seen_files = set()

    candidate_paths = set()
    for asset in surface.frontend_assets:
        candidate_paths.add(Path(asset.path))

    # Also scan known directories that may not be in frontend_assets
    if rootfs_path:
        rootfs_p = Path(rootfs_path)
        scan_dirs = [
            rootfs_p / "usr/lib/lua/luci/view",
            rootfs_p / "www/self_diag/resource/js",
            rootfs_p / "www/js",
        ]
        for scan_dir in scan_dirs:
            if scan_dir.exists():
                for ext in ("*.htm", "*.html", "*.js"):
                    for f in scan_dir.rglob(ext):
                        if f.is_file() and 500 < f.stat().st_size < 200 * 1024:
                            candidate_paths.add(f)

    for p in sorted(candidate_paths):
        if str(p) in seen_files:
            continue
        if not p.exists() or p.suffix.lower() not in (".js", ".htm", ".html"):
            continue
        if p.stat().st_size < 500 or p.stat().st_size > 200 * 1024:
            continue

        try:
            content = p.read_text(errors="ignore")
        except Exception:
            continue

        # Check if this file contains crypto-related code
        has_crypto = any(pat in content for pat in crypto_patterns)
        if not has_crypto:
            continue

        # Extract relevant blocks around crypto patterns
        snippets = []
        for pat in ["var Encrypt", "Encrypt =", "Encrypt={", "Encrypt.prototype"]:
            idx = content.find(pat)
            if idx >= 0:
                # Extract 2000 chars around the match
                start = max(0, idx - 200)
                end = min(len(content), idx + 2000)
                snippet = content[start:end]
                if snippet not in snippets:
                    snippets.append(snippet)

        if snippets:
            # Only keep one snippet per file (first/best match)
            blocks.append(f"\n--- {p} (pre-extracted crypto) ---\n{snippets[0]}")
            seen_files.add(str(p))

    return blocks[:3]  # Limit to 3 blocks


STAGE1_AGENT_PROMPT = """You are a firmware security researcher analyzing an IoT router's authentication system.

You have access to tools to explore the firmware filesystem:
- search_files: Find files by glob pattern (e.g. '*.lua', '*auth*', 'dispatcher*')
- read_file: Read file content (Lua, JS, Python, PHP, configs, etc.)
- grep_files: Search file contents for patterns (e.g. 'checkUser', 'sha1', 'password')

Known information about this firmware:
{context}

**Your task**: Discover and understand the complete authentication chain. You must determine:
1. What auth framework is used (LuCI, custom CGI, GoAhead, Boa, HNAP, etc.)
2. How login works (URL, method, parameters, password hashing)
3. How sessions/tokens work (cookie, URL-embedded token, header)
4. Where credentials are stored (UCI, NVRAM, file, hardcoded)
5. Any crypto involved (hash functions, fixed keys, nonce)

**Known auth architecture patterns**:
- **GoAhead**: /goform/formLogin, Cookie: session_id=VALUE, common in MIPS routers (TP-Link, Tenda)
- **Boa**: HTTP Basic or /cgi-bin/ form handlers, common in older D-Link/Netgear
- **LuCI/uhttpd**: Lua session store, login via /cgi-bin/luci/..., routes in usr/lib/lua/luci/
- **HNAP**: SOAP at /HNAP1/ with HMAC-MD5 challenge, common in D-Link/Linksys
- **CSTE custom CGI**: /cgi-bin/cstecgi.cgi with topicurl dispatch
- **mini_httpd**: HTTP Basic auth or custom CGI

**Investigation strategy**:
- If you see LuCI/uhttpd/nginx → search for Lua files in usr/lib/lua/luci/
  - IMPORTANT: Also search for template files in usr/lib/lua/luci/view/ — the login form action URL is often in sysauth.htm or similar templates
  - grep for "build_url" or "form.*action" in .htm and .html files under luci/view/
  - Read g.js.htm or similar shared JS templates — they contain Encrypt functions with crypto keys
- If you see cstecgi.cgi → search for JS files with login logic
- If you see goform → search for formLogin, formLogout patterns
- If you see /HNAP1/ → search for HNAP authentication XML
- If you see custom CGI → grep for password/auth/session keywords
- Always check the web server config for auth-related settings
- Read the actual auth checker code (Lua, JS, or binary decompilation) to understand password verification
- If you find a fixed crypto key or nonce pattern, note it exactly
- Check frontend JS for how the login password is constructed (hashing, key, nonce)
- CRITICAL: The login_url must be the FULL API path, not just the CGI gateway. For LuCI, look for build_url("api","xqsystem","login") patterns — the login URL is like /cgi-bin/luci/api/xqsystem/login, NOT /cgi-bin/luci
- If the context contains a "PRE-EXTRACTED CRYPTO/AUTH DEFINITIONS" section, do NOT re-read those files — the content is already provided

**Also look for bypass conditions**:
- Hardcoded backdoor accounts (base64-encoded credentials, user:pass pairs in binary strings)
- Debug mode flags (debug_mode, bypass_auth, no_auth, telnet_enabled)
- Unauthenticated admin endpoints (paths that skip auth checks)
- Predictable session cookies (md5 of timestamp, fixed default tokens)
- Auth check logic flaws (if(authenticated || debug_mode) patterns in decompiled code)

**Critical**: You must read the actual source code. Do not guess — use the tools to find and read files.

**IMPORTANT about login_method**:
- login_method must be the HTTP method used to SUBMIT credentials (POST in most cases).
- Do NOT confuse GET requests that check/validate tokens with POST requests that submit login credentials.
- If the login API accepts GET with token validation AND POST with credentials, set login_method to "POST".
- The login_url should be the endpoint where credentials are submitted, not where tokens are checked.

**IMPORTANT about login_params**:
- Output actual parameter names and example values that can be used directly in a curl command.
- For crypto-based params (like oldPwd), describe the algorithm in crypto_details, but in login_params use the parameter name as key and a description as value.
- Example: {{"username": "admin", "password": "<oldPwd>", "logtype": "2", "nonce": "<generated>"}}

**IMPORTANT about crypto_details**:
- You MUST fill this field. If you find any password hashing/encryption, describe the exact algorithm chain.
- Include the fixed key and nonce format if found. Example: "SHA1(nonce + SHA1(password + 'a2ffa5c9be07488bbb04a3a47d3c5f6a')), nonce format: 0_epoch_random"
- If no crypto is used (plaintext), write "none" or "plaintext".

**IMPORTANT about login_curl**:
- You MUST fill this field with a ready-to-use curl command.
- Use http://TARGET as the base URL (it will be replaced with the actual target).
- Include the full URL, method, headers, and data.
- Example: curl -s 'http://TARGET/cgi-bin/luci/api/xqsystem/login?username=admin&password=HASH&logtype=2&nonce=0_1234567890_1234'

When done, output ONLY valid JSON:
{{
  "auth_type": "string describing auth architecture type",
  "login_url": "exact URL for login request (the endpoint where credentials are POSTed)",
  "login_method": "POST (the method used to submit credentials, not to check tokens)",
  "login_content_type": "form or json",
  "login_params": {{"param_name": "example_value_or_description"}},
  "session_mechanism": "description of how sessions work",
  "session_cookie_name": "expected cookie name if cookie-based",
  "credential_storage": "where credentials are stored (e.g. UCI account.common.admin, NVRAM http_passwd)",
  "credential_defaults": [{{"username": "x", "password": "y"}}],
  "post_login_redirect": "expected redirect after login",
  "auth_gate_pattern": "how auth-gated pages behave",
  "api_dispatch_mechanism": "how API calls are routed",
  "key_observations": ["list of important observations from your investigation"],
  "token_location": "cookie or url_path or header",
  "token_response_path": "JSON field containing the token (e.g. token) if login returns JSON",
  "url_token_pattern": "how token is embedded in URL (e.g. ;stok={{token}}) if url_path",
  "crypto_details": "crypto chain description — REQUIRED, do not leave empty",
  "recovery_shell_commands": ["shell commands to set up auth state, e.g. uci set account.common.admin=HASH"],
  "login_curl": "ready-to-use curl command — REQUIRED, do not leave empty"
}}"""


# ---------------------------------------------------------------------------
# Agent-based Stage 3: LLM generates bypass plan (does NOT execute)
# ---------------------------------------------------------------------------


def assemble_recovery_context(architecture, mismatches, bundle=None) -> str:
    """Build context for Stage 3 agent — bypass plan generation."""
    mismatch_summary = []
    for m in mismatches[:6]:
        mismatch_summary.append(f"  [{m.layer}] {m.title}: {m.description}")

    parts = [
        "=== AUTH ARCHITECTURE (from Stage 1 analysis) ===",
        f"auth_type: {architecture.auth_type}",
        f"login: {architecture.login_method} {architecture.login_url} ({architecture.login_content_type})",
        f"params: {architecture.login_params}",
        f"session: {architecture.session_mechanism} via {architecture.session_cookie_name}",
        f"credential_storage: {architecture.credential_storage}",
        f"defaults: {architecture.credential_defaults}",
        f"post_login: {architecture.post_login_redirect}",
        f"token_location: {architecture.token_location}",
        f"url_token_pattern: {architecture.url_token_pattern}",
        f"crypto_details: {architecture.crypto_details}",
        f"recovery_shell_commands: {architecture.recovery_shell_commands}",
        "",
        "=== IDENTIFIED MISMATCHES (from Stage 2) ===",
        *mismatch_summary,
    ]

    if bundle:
        parts.append("")
        parts.append("=== RUNTIME ACCESS ===")
        parts.append(f"web_url: {bundle.input.web_url}")
        parts.append("http: available (httpx)")
        parts.append("browser: available (Playwright)")

    return "\n".join(parts)[:4000]


STAGE3_AGENT_PROMPT = """You are a firmware security researcher analyzing authentication bypass strategies for a rehosted IoT device.

Your task is to **generate a concrete bypass plan** — you do NOT execute it. The plan includes specific shell commands that a security researcher will run in the firmware's emulation shell.

You have already analyzed the firmware's authentication architecture and identified the mismatches preventing access. Now use your tools (http_request for probing, search_files/read_file/grep_files for checking firmware files) to validate your analysis and produce a precise bypass plan.

**Available tools**:
- http_request: Send HTTP requests to probe the firmware and verify endpoints (e.g., check if login page responds, test default credentials)
- search_files / read_file / grep_files: Explore firmware files to confirm credential storage, crypto details, etc.

**IMPORTANT: Two-phase approach**:
Phase 1 (Information Gathering): Use tools to collect ALL critical information BEFORE deciding on a strategy:
  - Verify the login endpoint responds (http_request to login URL)
  - Check credential storage (read etc/config/account, etc/shadow)
  - Confirm crypto key and algorithm (read the JS/Lua files mentioned in Stage 1)
  - Test if any API endpoints respond without auth
  - Check if self_diag/diagnostic pages exist and are accessible

Phase 2 (Strategy Reasoning): ONLY AFTER gathering information, reason about the best strategy:
  - Which information confirms or rules out each strategy?
  - What is the single most likely to succeed strategy?
  - What are the exact commands needed?

**IMPORTANT efficiency rules**:
- If a file returns "[ENCRYPTED] Fate/Z encrypted", do NOT try to read it again — it cannot be decrypted.
- Focus on files that are readable (.htm, .html, .js, .conf, /etc/shadow, /etc/passwd).
- Do NOT re-read files you already read. Do NOT try variations of the same file path.
- Do NOT read minified JS files with offset pagination (base64 encoding tables, lookup arrays) — these are NOT auth-related.
- If a file starts with `(function(` or contains long arrays of numbers like `(-1),(-1),...`, skip it — it's a library, not auth code.

**Bypass strategy priority** (choose the most appropriate):

1. **Empty/default credentials** (confidence: high if NVRAM empty):
   → Shell: `curl` to test login with empty password or known defaults
   → No shell setup needed, just HTTP probe

2. **Hash injection** (if crypto_details mentions sha1/md5 + UCI/NVRAM storage):
   → Shell: compute hash and write to storage
   → Example: `uci set account.common.admin=$(echo -n 'adminKEY' | sha1sum | cut -d' ' -f1) && uci commit`

3. **Token extraction** (if token_location=url_path):
   → HTTP: login request, extract token from JSON response
   → Example: POST login → get `{{"token": "abc123"}}` → use in `/cgi-bin/luci/;stok=abc123/...`

4. **State file creation** (if binary shows /tmp/login_flag or similar):
   → Shell: `echo 1 > /tmp/login_flag`

5. **Debug mode enable** (if debug_mode flag found in code):
   → Shell: `nvram set debug_mode=1 && nvram commit`

**IMPORTANT: Xiaomi nonce format**:
- The nonce format is `0__<timestamp>_<random>` (note: DOUBLE underscore after 0, then single underscore before random)
- Example: `NONCE="0__$(date +%s)_$((RANDOM % 10000))"`
- The crypto chain is: `oldPwd = SHA1(password + key)` where key is the 32-char hex string found in JS files
- Then send: `GET /cgi-bin/luci/api/xqsystem/login?username=admin&password=SHA1(nonce+oldPwd)&logtype=2&nonce=NONCE`
- **CRITICAL**: For empty password, `oldPwd = SHA1("" + key) = SHA1(key)`, NOT just `key`

6. **Cookie forging** (if session cookie is predictable):
   → Construct cookie directly from known algorithm

7. **Timing bypass** (if auth has boot race condition):
   → Shell: restart service + immediate HTTP request

**Validation approach**:
- Use http_request to verify the login page is accessible
- Use grep_files to confirm credential storage format
- Use read_file to verify crypto key/nonce patterns
- Then output the final bypass plan

**CRITICAL RULES**:
1. Choose ONE primary strategy. Do NOT mix incompatible approaches (e.g., don't combine "remove password" with "compute hash").
2. You MUST clearly separate commands into TWO categories:
   - **vm_commands**: Commands to run INSIDE the QEMU VM shell (e.g., passwd -d root, uci set, echo > /tmp/login_flag, service restart)
   - **host_commands**: Commands to run on the ATTACKER HOST machine (e.g., curl to test login, browser verification steps)
3. vm_commands must be directly executable in the firmware's shell — no comments, no placeholders.
4. host_commands MUST be a JSON array of SEPARATE commands — one command per array element. Do NOT put multiple commands in one string with comments. Each element should be one shell command.
   - BAD: ["# Step 1: compute hash\nNONCE=...\nHASH=$(echo...)"]
   - GOOD: ["NONCE=\\\"0_$(date +%s)_1234\\\"", "HASH=$(echo -n adminKEY | sha1sum | cut -d' ' -f1)", "curl -s 'http://10.10.10.2/cgi-bin/luci/api/xqsystem/login?username=admin&password=HASH&logtype=2&nonce=$NONCE'"]
5. If no VM commands are needed (e.g., trying default credentials directly), set vm_commands to [].

Context:
{context}

When you have completed your analysis, output ONLY valid JSON:
{{
  "bypass_strategy": "one of: empty_password, hash_injection, token_extraction, state_file_creation, debug_mode, cookie_forging, timing_bypass",
  "description": "one-paragraph description of the approach",
  "vm_commands": ["command to run in QEMU VM", "..."],
  "host_commands": ["curl command to run on attacker host", "browser verification step", "..."],
  "credentials_to_try": [{{"username": "admin", "password": ""}}],
  "expected_session": {{"cookie_name": "SESSION_ID", "token_pattern": ";stok=TOKEN"}},
  "fallback_strategies": ["alternative approaches if primary fails"],
  "confidence": 0.0-1.0
}}"""
