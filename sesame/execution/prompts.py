"""Stage 4 prompt template."""


def assemble_execution_context(bypass_plan, architecture=None) -> str:
    """Build context for Stage 4 execution agent."""
    parts = [
        "=== BYPASS PLAN (from Stage 3 analysis) ===",
        f"Strategy: {bypass_plan.bypass_strategy}",
        f"Description: {bypass_plan.description}",
        "",
    ]

    if bypass_plan.vm_commands:
        parts.append("VM Commands (execute inside QEMU VM using shell_exec):")
        for i, cmd in enumerate(bypass_plan.vm_commands, 1):
            parts.append(f"  {i}. {cmd}")
    else:
        parts.append("VM Commands: (none — bypass via HTTP only)")

    parts.append("")
    if bypass_plan.host_commands:
        parts.append("Host Commands (execute via http_request/check_result):")
        for i, cmd in enumerate(bypass_plan.host_commands, 1):
            parts.append(f"  {i}. {cmd}")

    parts.append("")
    if bypass_plan.credentials_to_try:
        parts.append("Credentials to try:")
        for cred in bypass_plan.credentials_to_try:
            parts.append(f"  username={cred.get('username', '')} password={cred.get('password', '')}")

    if bypass_plan.expected_session:
        parts.append("")
        parts.append(f"Expected session: {bypass_plan.expected_session}")

    if bypass_plan.fallback_strategies:
        parts.append("")
        parts.append("Fallback strategies if primary fails:")
        for i, s in enumerate(bypass_plan.fallback_strategies, 1):
            parts.append(f"  {i}. {s}")

    if architecture:
        parts.append("")
        parts.append("=== AUTH ARCHITECTURE ===")
        parts.append(f"Login: {architecture.login_method} {architecture.login_url}")
        parts.append(f"Token location: {architecture.token_location}")
        parts.append(f"Token pattern: {architecture.url_token_pattern}")
        parts.append(f"Crypto: {architecture.crypto_details}")

    return "\n".join(parts)[:4000]


STAGE4_EXECUTION_PROMPT = """You are a firmware security researcher executing an authentication bypass plan on a rehosted IoT device.

You have access to these tools:
- **shell_exec**: Execute commands INSIDE the QEMU VM (modify config, restart services, create files). Returns stdout + exit code.
- **http_request**: Send HTTP requests to the firmware web interface (login attempts, page checks).
- **check_result**: Like http_request but adds automatic success/failure analysis of the response.
- **search_files / read_file / grep_files**: Read firmware files if you need to verify something.

**Your task**: Execute the bypass plan step by step, verify each step, and report whether authentication was successfully bypassed.

**Context:**
{context}

**Execution approach**:
1. Execute VM commands ONE AT A TIME using shell_exec. Check exit_code after each.
   - If a command fails, note the error and try an alternative approach.
   - Common alternatives: use full path (/usr/sbin/uci instead of uci), or try a different method.
2. After all VM setup commands succeed, verify the bypass by sending a login request using http_request or check_result.
3. Use check_result to verify: did login succeed? Were cookies/tokens set?
4. If primary strategy fails, try fallback strategies. You can modify VM state and retry.
5. When bypass succeeds, extract and report the session state.

**Success criteria** (any of these):
- Login request returns JSON with token/stok/url field
- Set-Cookie header contains session cookie (loginToken, sysauth, etc.)
- A post-auth page returns real content (not login form or redirect)
- HTTP 200 with authenticated content (not {{"code":401}} or redirect to /login)

**Failure indicators**:
- {{"code":401}} or "not auth" in response
- Redirect to login page (302 → /login or /cgi-bin/luci/)
- "Invalid token" or "authentication failed"
- Empty password hash doesn't match stored hash
- JS redirect to external domain (e.g., tplinkrepeater.net, router.asus.com) — domain unreachable in rehosted env

**IMPORTANT rules**:
- Execute commands ONE AT A TIME. Check each result before proceeding.
- If shell_exec fails with "command not found", try using full paths: /sbin/uci, /usr/bin/uci, /bin/sh -c "..."
- After successful login, use check_result on a post-auth page to confirm access.
- When you extract a token from login response, construct the authenticated URL: e.g. /cgi-bin/luci/;stok=TOKEN/web/home
- Report the EXACT session state: cookies and URL tokens needed for authenticated access.
- **DNS redirect bypass**: If the index page redirects to a domain (e.g., tplinkrepeater.net), fix by:
  1. On the HOST machine: add "10.10.10.2 tplinkrepeater.net" to /etc/hosts
  2. On the VM (if needed): echo "127.0.0.1 tplinkrepeater.net" >> /etc/hosts
  3. Then retry http_request with the domain URL: http://tplinkrepeater.net/

When done, call submit_result with JSON:
{{
  "success": true or false,
  "session_state": {{
    "cookies": {{"cookie_name": "value"}},
    "url_tokens": {{"stok": "token_value"}},
    "url_token_pattern": ";stok={{token}}"
  }},
  "strategy_used": "which strategy worked",
  "commands_executed": ["list of commands that were actually executed"],
  "login_response": "key part of the login response",
  "error": "error message if failed"
}}"""
