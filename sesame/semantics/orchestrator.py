import re as _re
from types import SimpleNamespace

from sesame.bootstrap import Settings
from sesame.domain.llm_result import AuthArchitecture, BypassPlan, LLMMismatchItem
from sesame.domain.report import EntryPoint, SemanticFinding
from sesame.semantics.config import build_semantic_runtime_config
from sesame.semantics.llm import DeepseekClient
from sesame.semantics.llm_stages import (
    assemble_stage1_context, assemble_stage2_context,
    assemble_basic_context, assemble_recovery_context,
    STAGE1_AGENT_PROMPT, STAGE3_AGENT_PROMPT,
)
from sesame.utils.logger import get_logger

logger = get_logger(__name__)


class SemanticContext(SimpleNamespace):
    pass


def build_semantic_context(bundle, surface, settings):
    semantic_config = build_semantic_runtime_config(settings)
    llm_client = DeepseekClient(semantic_config)

    # Heuristic baseline (always computed as fallback)
    entries = _heuristic_entry_points(surface)
    disasm = _heuristic_disasm_context(bundle, surface, settings)
    flow = _heuristic_flow(surface, entries)
    finding = SemanticFinding(
        entry_points=entries,
        auth_flow_summary="; ".join(flow),
        state_dependencies=[],
        unknowns=[],
        context_blocks=disasm,
    )

    architecture = AuthArchitecture()
    llm_mismatches: list[LLMMismatchItem] = []
    agent_session_state: dict = {}
    bypass_plan = BypassPlan()

    if llm_client.available:
        # Stage 1: Agent-based Architecture Analysis (filesystem tools)
        llm_client.snapshot_stage("stage1")
        logger.info("=" * 60)
        logger.info("=== LLM Stage 1: Agent Auth Architecture Analysis ===")
        logger.info("=" * 60)
        basic_ctx = assemble_basic_context(surface, rootfs_path=bundle.input.rootfs_path)
        s1_prompt = STAGE1_AGENT_PROMPT.format(context=basic_ctx.replace("{", "{{").replace("}", "}}"))
        logger.info(f"Stage 1 agent prompt ({len(s1_prompt)} chars)")
        agent_result = llm_client.analyze_architecture_with_tools(
            s1_prompt, rootfs_path=bundle.input.rootfs_path, max_rounds=20,
        )
        if agent_result:
            logger.info(f"Stage 1 agent result keys: {list(agent_result.keys())}")
            logger.info(f"AuthArchitecture fields: {list(AuthArchitecture.model_fields.keys())}")
            matched_keys = {k: v for k, v in agent_result.items() if k in AuthArchitecture.model_fields}
            logger.info(f"Matched keys: {list(matched_keys.keys())}")
            try:
                architecture = AuthArchitecture(**matched_keys)
            except Exception as e:
                logger.warning(f"Failed to parse agent architecture: {e}")
                s1_context = assemble_stage1_context(surface, settings)
                architecture = llm_client.analyze_architecture(s1_context)
            # Clean login_url: strip leading method prefix if LLM included it
            if architecture:
                for prefix in ("POST ", "GET ", "post ", "get "):
                    if architecture.login_url.startswith(prefix):
                        architecture.login_url = architecture.login_url[len(prefix):]
                # Fix login_method: if params contain credential fields AND
                # the login URL/content_type indicates a POST-based API, it's POST not GET.
                # Exception: JSONP-style APIs (e.g., Xiaomi xqsystem) legitimately use GET
                # — skip correction if URL contains known JSONP API patterns.
                if architecture.login_method.upper() == "GET" and architecture.login_params:
                    param_keys = set(k.lower() for k in architecture.login_params.keys())
                    credential_fields = {"username", "password", "passwd", "pwd", "oldpwd", "newpwd"}
                    login_url_lower = architecture.login_url.lower()
                    # Known GET-based login APIs (JSONP or query-string auth)
                    get_api_patterns = ["xqsystem", "jsonp", "callback="]
                    if not any(p in login_url_lower for p in get_api_patterns):
                        if param_keys & credential_fields:
                            logger.info(f"Correcting login_method from GET to POST (has credential params: {list(architecture.login_params.keys())})")
                            architecture.login_method = "POST"

                # Fix login_method: correct POST to GET for known GET-based APIs
                if architecture.login_method.upper() == "POST":
                    login_url_lower = architecture.login_url.lower()
                    get_api_patterns = ["xqsystem", "jsonp", "callback="]
                    if any(p in login_url_lower for p in get_api_patterns):
                        logger.info(f"Correcting login_method from POST to GET (known GET API: {architecture.login_url})")
                        architecture.login_method = "GET"
                        # Also fix login_curl if it uses POST
                        if architecture.login_curl and "-X POST" in architecture.login_curl:
                            architecture.login_curl = architecture.login_curl.replace("-X POST ", "")
                            # Convert -d params to query string for GET
                            _d_match = _re.search(r"-d '([^']+)'", architecture.login_curl)
                            if _d_match:
                                qs = _d_match.group(1).replace("&", "&")
                                architecture.login_curl = architecture.login_curl.replace(_d_match.group(0), "")
                                url_part = _re.search(r"'(http[^']+)'", architecture.login_curl)
                                if url_part:
                                    base_url = url_part.group(1)
                                    sep = "&" if "?" in base_url else "?"
                                    architecture.login_curl = architecture.login_curl.replace(base_url, f"{base_url}{sep}{qs}")

                # Fix token_location: check multiple sources for url_path indicators
                if architecture.token_location != "url_path":
                    stok_sources = [
                        architecture.url_token_pattern.lower(),
                        architecture.session_mechanism.lower(),
                    ]
                    if architecture.key_observations:
                        stok_sources.append(" ".join(architecture.key_observations).lower())
                    if any("stok" in s for s in stok_sources):
                        logger.info("Correcting token_location to url_path (stok found in architecture fields)")
                        architecture.token_location = "url_path"

                # Validate login_url against discovered endpoints
                if architecture.login_url and surface.endpoints:
                    ep_urls = {ep.url for ep in surface.endpoints}
                    if architecture.login_url not in ep_urls:
                        # Strategy 1: exact /login suffix (exclude clear_login_record, etc.)
                        strict_login_eps = [
                            ep for ep in surface.endpoints
                            if ep.url.lower().rstrip("/").endswith("/login")
                        ]
                        if len(strict_login_eps) == 1:
                            best = strict_login_eps[0]
                            logger.info(f"Correcting login_url from {architecture.login_url} to {best.url} (exact /login endpoint)")
                            architecture.login_url = best.url
                        elif strict_login_eps:
                            logger.info(f"Multiple /login endpoints found ({[ep.url for ep in strict_login_eps]}), keeping LLM choice: {architecture.login_url}")
                        else:
                            # Strategy 2: prefix match — LLM URL is a prefix of a discovered endpoint
                            login_prefix = architecture.login_url.rstrip("/")
                            prefix_matches = [
                                ep for ep in surface.endpoints
                                if ep.url.startswith(login_prefix) and ep.url != login_prefix
                            ]
                            # Filter to login-related endpoints
                            login_prefix_matches = [
                                ep for ep in prefix_matches
                                if "login" in ep.url.lower() and "clear" not in ep.url.lower()
                            ]
                            if len(login_prefix_matches) == 1:
                                best = login_prefix_matches[0]
                                logger.info(f"Correcting login_url from {architecture.login_url} to {best.url} (prefix match)")
                                architecture.login_url = best.url
                            elif login_prefix_matches:
                                # Pick the shortest (most general) login endpoint
                                best = min(login_prefix_matches, key=lambda ep: len(ep.url))
                                logger.info(f"Correcting login_url from {architecture.login_url} to {best.url} (shortest prefix match)")

                # Fix login_url: if login_curl contains a different URL, trust login_curl
                if architecture.login_curl and architecture.login_url:
                    curl_url_match = _re.search(r"https?://[^/]+(/[^\s'\"]*)", architecture.login_curl)
                    if curl_url_match:
                        curl_url = curl_url_match.group(1)
                        # Strip query string for comparison
                        curl_path = curl_url.split("?")[0]
                        if curl_path != architecture.login_url and len(curl_path) > len(architecture.login_url):
                            logger.info(f"Correcting login_url from {architecture.login_url} to {curl_path} (from login_curl)")
                            architecture.login_url = curl_path

                # Construct login_curl if empty
                if not architecture.login_curl and architecture.login_url:
                    import json as _json
                    if architecture.login_method.upper() == "GET":
                        if architecture.login_params:
                            qs = "&".join(f"{k}={v}" for k, v in architecture.login_params.items())
                            architecture.login_curl = f"curl -s 'http://TARGET{architecture.login_url}?{qs}'"
                        else:
                            architecture.login_curl = f"curl -s 'http://TARGET{architecture.login_url}'"
                    else:
                        if architecture.login_params:
                            data = _json.dumps(architecture.login_params)
                            architecture.login_curl = f"curl -s -X POST 'http://TARGET{architecture.login_url}' -H 'Content-Type: application/x-www-form-urlencoded' -d '{data}'"
                        else:
                            architecture.login_curl = f"curl -s -X POST 'http://TARGET{architecture.login_url}'"
                    logger.info(f"Constructed login_curl: {architecture.login_curl}")

                # Extract crypto_details from key_observations if empty
                if not architecture.crypto_details and architecture.key_observations:
                    crypto_kw = ["sha1", "sha256", "md5", "aes", "rc4", "hmac", "encrypt", "decrypt", "hash", "nonce", "key="]
                    for obs in architecture.key_observations:
                        if any(kw in obs.lower() for kw in crypto_kw):
                            architecture.crypto_details = obs
                            logger.info(f"Extracted crypto_details from key_observations: {obs}")
                            break
        else:
            logger.info("Agent mode returned nothing, falling back to standard Stage 1")
            s1_context = assemble_stage1_context(surface, settings)
            architecture = llm_client.analyze_architecture(s1_context)
        logger.info(f"Stage 1 result:")
        logger.info(f"  auth_type: {architecture.auth_type}")
        logger.info(f"  login: {architecture.login_method} {architecture.login_url} ({architecture.login_content_type})")
        logger.info(f"  session: {architecture.session_mechanism} via {architecture.session_cookie_name}")
        logger.info(f"  token_location: {architecture.token_location}")
        logger.info(f"  crypto_details: {architecture.crypto_details}")

        # Enrich finding with LLM architecture
        finding.auth_flow_summary = (
            f"LLM: {architecture.auth_type}; login={architecture.login_method} {architecture.login_url}; "
            f"session={architecture.session_mechanism}; dispatch={architecture.api_dispatch_mechanism}"
        )

        # Stage 2: Mismatch Reasoning (single-turn)
        llm_client.snapshot_stage("stage2")
        logger.info("=" * 60)
        logger.info("=== LLM Stage 2: Mismatch Reasoning ===")
        logger.info("=" * 60)
        s2_context = assemble_stage2_context(architecture, surface.test_targets, getattr(surface, "runtime_state_evidence", []))
        logger.info(f"Stage 2 context ({len(s2_context)} chars):\n{s2_context}")
        llm_mismatches = llm_client.analyze_mismatches(s2_context)
        logger.info(f"Stage 2 result: {len(llm_mismatches)} mismatches")
        for m in llm_mismatches:
            logger.info(f"  [{m.layer}] {m.title} (confidence={m.confidence})")

        # Stage 3: Bypass Plan Generation (agent analyzes, does NOT execute)
        llm_client.snapshot_stage("stage3")
        logger.info("=" * 60)
        logger.info("=== LLM Stage 3: Bypass Plan Generation ===")
        logger.info("=" * 60)
        recovery_ctx = assemble_recovery_context(architecture, llm_mismatches, bundle=bundle)
        s3_prompt = STAGE3_AGENT_PROMPT.format(context=recovery_ctx.replace("{", "{{").replace("}", "}}"))
        logger.info(f"Stage 3 agent prompt ({len(s3_prompt)} chars)")
        recovery_result = llm_client.recover_with_tools(
            s3_prompt, rootfs_path=bundle.input.rootfs_path, bundle=bundle, max_rounds=20,
        )
        if recovery_result:
            try:
                # Handle backward compatibility: map old field names to new ones
                normalized = dict(recovery_result)
                if "shell_commands" in normalized and "vm_commands" not in normalized:
                    normalized["vm_commands"] = normalized.pop("shell_commands")
                if "http_verification" in normalized and "host_commands" not in normalized:
                    normalized["host_commands"] = normalized.pop("http_verification")
                bypass_plan = BypassPlan(**{k: v for k, v in normalized.items() if k in BypassPlan.model_fields})
            except Exception as e:
                logger.warning(f"Failed to parse bypass plan: {e}")
                bypass_plan = BypassPlan(
                    bypass_strategy=recovery_result.get("bypass_strategy", "unknown"),
                    description=recovery_result.get("description", ""),
                    vm_commands=recovery_result.get("vm_commands", recovery_result.get("shell_commands", [])),
                    host_commands=recovery_result.get("host_commands", recovery_result.get("http_verification", [])),
                    credentials_to_try=recovery_result.get("credentials_to_try", []),
                    confidence=recovery_result.get("confidence", 0.0),
                )
            logger.info(f"Stage 3 result:")
            logger.info(f"  strategy: {bypass_plan.bypass_strategy}")
            logger.info(f"  confidence: {bypass_plan.confidence}")
            logger.info(f"  vm_commands: {len(bypass_plan.vm_commands)}")
            for cmd in bypass_plan.vm_commands[:5]:
                logger.info(f"    $ {cmd}")

            # Post-process: split multi-line and compound commands into individual commands
            for cmd_list_name in ("vm_commands", "host_commands"):
                cmd_list = getattr(bypass_plan, cmd_list_name, [])
                if not cmd_list:
                    continue
                cleaned = []
                for cmd in cmd_list:
                    for line in cmd.split('\n'):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        # Strip trivial || fallbacks: cmd || echo '' || true || exit 0
                        line = _re.sub(r'\s*\|\|\s*(?:echo\s+[\'"]?\s*[\'"]?|true|exit\s+0)\s*$', '', line)
                        # Split compound commands: echo '---' && real_cmd → keep real_cmd
                        if ' && ' in line:
                            parts = [p.strip() for p in line.split(' && ')]
                            for part in parts:
                                part = part.strip()
                                if not part or part.startswith("echo '---") or part.startswith('echo "---'):
                                    continue
                                # Filter informational echo without file redirect
                                if _is_info_echo(part):
                                    continue
                                cleaned.append(part)
                        else:
                            # Filter informational echo without file redirect
                            if _is_info_echo(line):
                                continue
                            cleaned.append(line)
                setattr(bypass_plan, cmd_list_name, cleaned)
                logger.info(f"  {cmd_list_name} (cleaned): {len(cleaned)}")
                for cmd in cleaned[:5]:
                    logger.info(f"    $ {cmd}")
            if bypass_plan.credentials_to_try:
                logger.info(f"  credentials: {bypass_plan.credentials_to_try}")

            # Post-process: extract actual login URL from host_commands to fix architecture
            if bypass_plan.host_commands and architecture.login_url:
                for cmd in bypass_plan.host_commands:
                    # Look for curl commands with login-related URLs
                    urls_in_cmd = _re.findall(r"https?://[^/\s]+(/[^\s'\"]*login[^\s'\"]*)", cmd)
                    for found_url in urls_in_cmd:
                        found_path = found_url.split("?")[0]
                        if len(found_path) > len(architecture.login_url) and found_path != architecture.login_url:
                            logger.info(f"Correcting login_url from {architecture.login_url} to {found_path} (from bypass plan host_commands)")
                            architecture.login_url = found_path
                            break
                    else:
                        continue
                    break

            # Post-process: fix token_location from bypass plan evidence
            if architecture.token_location != "url_path":
                stok_evidence = []
                if bypass_plan.expected_session:
                    stok_evidence.append(str(bypass_plan.expected_session).lower())
                if bypass_plan.description:
                    stok_evidence.append(bypass_plan.description.lower())
                if bypass_plan.host_commands:
                    stok_evidence.extend(cmd.lower() for cmd in bypass_plan.host_commands)
                if any("stok" in s for s in stok_evidence):
                    logger.info("Correcting token_location to url_path (stok found in bypass plan)")
                    architecture.token_location = "url_path"

            # Post-process: extract crypto details from bypass plan description
            # Stage 3 may find more accurate crypto info than Stage 1
            if bypass_plan.description:
                bp_lower = bypass_plan.description.lower()
                # Known crypto keys that should be in crypto_details
                key_patterns = [
                    (r"key=['\"]?([a-f0-9]{32,64})['\"]?", "key"),
                    (r"([a-f0-9]{32,64})", "hex_key"),
                ]
                for pattern, label in key_patterns:
                    match = _re.search(pattern, bypass_plan.description)
                    if match:
                        found_key = match.group(1)
                        # Only update if the found key is longer than what Stage 1 has
                        if found_key not in architecture.crypto_details and len(found_key) >= 32:
                            logger.info(f"Updating crypto_details with {label} from bypass plan: {found_key}")
                            # Extract the full crypto description from bypass plan
                            crypto_line = ""
                            for line in bypass_plan.description.split("."):
                                if found_key in line:
                                    crypto_line = line.strip()
                                    break
                            if crypto_line:
                                architecture.crypto_details = crypto_line
                            break

            # Post-process: rebuild login_curl from bypass plan host_commands
            # if the current login_curl uses a wrong key (e.g., "rackro" from fallback)
            if bypass_plan.host_commands and architecture.login_curl:
                # Extract the key from host_commands
                key_from_bp = None
                for cmd in bypass_plan.host_commands:
                    m = _re.search(r'KEY=["\']?([a-f0-9]{32,64})["\']?', cmd)
                    if m:
                        key_from_bp = m.group(1)
                        break
                    m = _re.search(r'echo -n ["\']?([a-f0-9]{32,64})', cmd)
                    if m:
                        key_from_bp = m.group(1)
                        break
                if key_from_bp and key_from_bp not in architecture.login_curl:
                    # Rebuild login_curl using the correct key from bypass plan
                    logger.info(f"Rebuilding login_curl with correct key from bypass plan: {key_from_bp}")
                    if architecture.login_method.upper() == "GET":
                        architecture.login_curl = (
                            f"KEY={key_from_bp} && "
                            f"OLDPWD=$(echo -n \"$KEY\" | sha1sum | cut -d' ' -f1) && "
                            f"NONCE=\"0__$(date +%s)_$((RANDOM % 10000))\" && "
                            f"PWD=$(echo -n \"${{NONCE}}${{OLDPWD}}\" | sha1sum | cut -d' ' -f1) && "
                            f"curl -s 'http://TARGET{architecture.login_url}?username=admin&password=${{PWD}}&logtype=2&nonce=${{NONCE}}'"
                        )
        else:
            logger.info("Stage 3 agent returned no result")
    else:
        logger.info("LLM not available, using heuristic analysis only")

    ctx = SemanticContext(
        finding=finding,
        entries=entries,
        flow=flow,
        context_blocks=disasm,
        architecture=architecture,
        llm_mismatches=llm_mismatches,
        agent_session_state=agent_session_state,
        bypass_plan=bypass_plan,
    )
    return ctx, llm_client


def _is_info_echo(cmd: str) -> bool:
    """Filter informational echo commands that don't write to a file."""
    cmd = cmd.strip()
    if not _re.match(r'^echo\s+', cmd):
        return False
    # Keep echo that redirects to a file (echo "x" > /path, echo "x" >> /path)
    if '>' in cmd:
        return False
    return True


def _heuristic_entry_points(surface) -> list[EntryPoint]:
    entries = []
    for ep in surface.endpoints[:64]:
        handler = ""
        lowered = ep.url.lower()
        if "login" in lowered:
            handler = "login"
        elif "auth" in lowered:
            handler = "auth"
        entries.append(EntryPoint(url=ep.url, method=ep.method, handler=handler, source=ep.source_file))
    return entries


def _heuristic_disasm_context(bundle, surface, settings) -> list[str]:
    blocks = []
    for binary in surface.web_binaries[:3] + surface.cgi_binaries[:5]:
        analysis = binary.analysis
        if analysis and analysis.arch != "unknown":
            parts = [f"[{binary.name}] arch={analysis.arch} bits={analysis.bits} endian={analysis.endian}"]
            if analysis.auth_strings:
                parts.append(f"  strings: {analysis.auth_strings[:6]}")
            if analysis.auth_functions:
                parts.append(f"  functions: {analysis.auth_functions[:6]}")
            if analysis.key_imports:
                parts.append(f"  imports: {analysis.key_imports[:8]}")
            blocks.append("\n".join(parts))
        else:
            blocks.append(f"[{binary.name}] path={binary.path}")
    for asset in surface.frontend_assets[:8]:
        blocks.append(f"[asset] {asset.path}"[:200])
    for config in surface.config_sources[:8]:
        blocks.append(f"[config] {config.source_type}:{config.path}"[:200])
    return blocks[:settings.max_context_chars // 100]


def _heuristic_flow(surface, entries) -> list[str]:
    flow = []
    for e in entries[:12]:
        flow.append(f"entry={e.method} {e.url} handler={e.handler or 'unknown'}")
    if surface.config_sources:
        flow.append("config_sources=" + ", ".join(c.source_type for c in surface.config_sources[:6]))
    return flow
