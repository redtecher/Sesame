import re

from sesame.domain.report import ReachabilityLevel, TestTarget
from sesame.utils.logger import get_logger

logger = get_logger(__name__)

# Authenticated content markers (indicate successful auth)
_AUTHENTICATED_MARKERS = [
    r'var\s+\w*[Uu]ser\w*\s*=\s*["\']',  # var currentUser = "admin"
    r'Welcome[,!]?\s*\w+',  # Welcome admin
    r'<input[^>]*name=["\']csrf',  # CSRF token field
    r'<input[^>]*name=["\']token',  # Token hidden field
    r'session[_-]?expir',  # Session expiry
    r'logout|sign.?out|disconnect',  # Logout link
]


def evaluate_targets(bundle, surface, session_state=None):
    """Evaluate target reachability using the session state recovered by the LLM Agent.

    Args:
        bundle: Runtime bundle with http connector.
        surface: Discovered attack surface with test_targets.
        session_state: Dict with 'cookies' and 'url_tokens' from Agent Stage 3,
                       or empty dict if agent recovery failed.

    Returns:
        (targets, session_state) tuple.
    """
    session_state = session_state or {}

    if session_state:
        logger.info(f"Evaluating targets with recovered session: cookies={list(session_state.get('cookies', {}).keys())}, url_tokens={list(session_state.get('url_tokens', {}).keys())}")
    else:
        logger.info("Evaluating targets without session state (agent recovery did not succeed)")

    evaluated: list[TestTarget] = []
    for target in surface.test_targets:
        if target.method == "POST":
            evaluated.append(_evaluate_post(bundle, target, session_state))
        else:
            evaluated.append(_evaluate_get(bundle, target, session_state))

    for t in evaluated:
        if t.reachability in {ReachabilityLevel.POST_AUTH_PAGE, ReachabilityLevel.API_READY} and not t.blockers:
            t.reachability = ReachabilityLevel.FUZZ_READY
        elif t.reachability == ReachabilityLevel.API_READY and t.blockers == ["empty_with_session"]:
            t.reachability = ReachabilityLevel.FUZZ_READY
    return evaluated, session_state


def _inject_url_token(url: str, token_value: str, token_pattern: str = "") -> str:
    """Inject URL token using the pattern from architecture analysis."""
    if token_value in url:
        return url

    if token_pattern:
        # Use the pattern from architecture (e.g., ";stok={token}")
        token_str = token_pattern.replace("{token}", token_value).replace("{TOKEN}", token_value)
        # Insert before the path component after the CGI gateway
        if "/cgi-bin/" in url:
            parts = url.split("/", 3)
            if len(parts) >= 4:
                return f"/{parts[1]}/{parts[2]}/{token_str}/{parts[3]}"
        return url + token_str

    # Fallback: LuCI-style injection
    return f"/cgi-bin/luci/;stok={token_value}" + url


def _evaluate_post(bundle, target, session_state) -> TestTarget:
    try:
        cookies = session_state.get("cookies", {}) if isinstance(session_state, dict) else {}
        post_data = {k: v for k, v in target.request_template.items() if k not in {"method", "url"}}
        response = bundle.http.post_with_cookies(target.url, data=post_data, cookies=cookies) if cookies else bundle.http.post(target.url, data=post_data)

        body = response.text.lower()
        location = response.headers.get("Location", "").lower()
        content_type = response.headers.get("Content-Type", "").lower()

        if response.status_code in {301, 302} and "login" in location:
            target.reachability = ReachabilityLevel.LOGIN_PAGE
            target.blockers = ["auth_redirect"]
            return target

        if response.status_code == 401:
            target.reachability = ReachabilityLevel.LOGIN_PAGE
            target.blockers = ["unauthorized"]
            return target

        if response.status_code == 403:
            target.reachability = ReachabilityLevel.LOGIN_PAGE
            target.blockers = ["forbidden"]
            return target

        if response.status_code == 200:
            stripped = body.strip()
            if any(x in content_type for x in ["json", "xml"]) or stripped.startswith("{") or stripped.startswith("["):
                target.reachability = ReachabilityLevel.API_READY
                target.blockers = [] if "frontend_declared_only" not in target.tags else ["frontend_declared_only"]
                return target
            if not stripped or len(stripped) < 10:
                target.reachability = ReachabilityLevel.API_READY if cookies else ReachabilityLevel.LOGIN_PAGE
                target.blockers = ["empty_with_session"] if cookies else ["empty_no_auth"]
                return target

            # Check for error response distinguishing "unauthorized" vs "bad request"
            if _is_auth_error(body):
                target.reachability = ReachabilityLevel.LOGIN_PAGE
                target.blockers = ["auth_error"]
                return target

        target.reachability = ReachabilityLevel.LOGIN_PAGE
        target.blockers = list(set(target.blockers + [f"post_{response.status_code}"]))
        return target
    except Exception as e:
        target.blockers = list(set(target.blockers + [f"post_err:{e}"]))
        return target


def _evaluate_get(bundle, target, session_state) -> TestTarget:
    try:
        cookies = session_state.get("cookies", {}) if isinstance(session_state, dict) else {}
        url_tokens = session_state.get("url_tokens", {}) if isinstance(session_state, dict) else {}
        token_pattern = session_state.get("url_token_pattern", "") if isinstance(session_state, dict) else ""

        # Inject URL token if available
        url = target.url
        if url_tokens:
            token_val = list(url_tokens.values())[0] if url_tokens else ""
            if token_val and ("luci" in url.lower() or "stok" in str(url_tokens).lower()):
                url = _inject_url_token(url, token_val, token_pattern)

        response = bundle.http.get_with_cookies(url, cookies) if cookies else bundle.http.get(url)
    except Exception:
        return target

    # Follow redirect chain like a browser (max 5 hops)
    response, chain = _follow_redirect_chain(bundle, response, cookies, max_hops=5)
    if chain:
        target.request_chain.extend(chain)

    body = response.text.lower()
    location = response.headers.get("Location", "").lower()
    headers = dict(response.headers)

    if response.status_code in {301, 302}:
        if "login" in location:
            target.reachability = ReachabilityLevel.LOGIN_PAGE
            target.blockers = ["auth_gate_redirect"]
            return target
        target.reachability = ReachabilityLevel.LOGIN_PAGE
        target.blockers = [f"redirect_loop_{location[:40]}"]
        return target

    if response.status_code == 401:
        target.reachability = ReachabilityLevel.LOGIN_PAGE
        target.blockers = ["unauthorized"]
        return target

    if response.status_code == 403:
        target.reachability = ReachabilityLevel.LOGIN_PAGE
        target.blockers = ["forbidden"]
        return target

    if response.status_code == 200:
        # Check for domain redirect (e.g., tplinkrepeater.net)
        domain_targets = detect_domain_redirect(response.text)
        if domain_targets:
            logger.info(f"Domain redirect detected on {target.url}: -> {domain_targets}")
            target.reachability = ReachabilityLevel.LOGIN_PAGE
            target.blockers = [f"dns_redirect:{domain_targets[0]}"]
            return target

        # Check for login page (multiple signals)
        is_login_form = _is_login_page(body, headers)

        if is_login_form:
            target.reachability = ReachabilityLevel.LOGIN_PAGE
            target.blockers = ["login_form_detected"]
            return target

        # Check for redirect/gateway pages (small pages with meta refresh or JS redirect)
        if _is_redirect_page(body):
            target.reachability = ReachabilityLevel.LOGIN_PAGE
            target.blockers = ["redirect_gateway"]
            return target

        content_type = response.headers.get("Content-Type", "").lower()
        if target.target_type == "api" and (any(x in content_type for x in ["json", "xml"]) or body.strip().startswith(("{", "["))):
            target.reachability = ReachabilityLevel.API_READY
            target.blockers = []
            return target

        # Check for authenticated content markers
        if _has_authenticated_markers(body):
            target.reachability = ReachabilityLevel.POST_AUTH_PAGE
            target.blockers = []
            return target

        if _looks_post_auth(target.url, body, target.tags):
            target.reachability = ReachabilityLevel.POST_AUTH_PAGE
            target.blockers = []
            return target

        target.reachability = ReachabilityLevel.LOGIN_PAGE
        target.blockers = ["reachable_but_not_post_auth"]
        return target

    target.reachability = ReachabilityLevel.UNREACHABLE
    target.blockers = [f"status_{response.status_code}"]
    return target


def _looks_post_auth(url: str, body: str, tags: list[str] | None = None) -> bool:
    tags = tags or []
    keywords = ["logout", "admin", "dashboard", "wireless", "wan", "lan", "topicurl", "connection_status", "basic_menu", "changepwd"]
    if url.rstrip("/") == "/cgi-bin":
        return False

    # Don't classify as post-auth if the page is a redirect/gateway page
    body_text = re.sub(r'<[^>]+>', '', body).strip()
    if len(body_text) < 500:
        if re.search(r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\']', body, re.IGNORECASE):
            return False
        if any(p in body for p in ['window.location', 'location.replace', 'location.href']):
            return False

    if any(h in url.lower() for h in ["home", "admin", "status", "basic", "advance"]):
        if "login" in url.lower():
            return False
        return True
    # For "index" URLs, require body content evidence too
    if "index" in url.lower():
        return any(k in body for k in keywords)
    if "topicurl_mapping" in tags or "menu_page" in tags:
        return True
    return any(k in body for k in keywords)


def _is_login_page(body: str, headers: dict = None) -> bool:
    """Check if the body is a login page, using multiple signals."""
    # Strong indicators
    if "loginfrm" in body:
        return True
    has_login_action = bool(re.search(r'<form[^>]*action\s*=\s*["\'][^"\']*login', body, re.IGNORECASE))
    if has_login_action:
        return True
    login_indicators = ['name="loginform"', "name='loginform'", 'id="loginform"', "id='loginform'",
                        'id="login-form"', 'class="login-form"', 'class="login_page"']
    if any(ind in body for ind in login_indicators):
        return True

    # WWW-Authenticate header
    if headers and "www-authenticate" in {k.lower(): v for k, v in headers.items()}:
        return True

    # Password field + login keyword (but exclude Wi-Fi/VPN password fields)
    has_password_field = 'type="password"' in body or "type='password'" in body
    if has_password_field and "login" in body and len(body) < 5000:
        pw_count = body.count('type="password"') + body.count("type='password'")
        if pw_count == 1:
            # Extra check: make sure it's not a password change form (post-auth)
            if not any(k in body for k in ["change password", "new password", "confirm password", "wifi password"]):
                return True

    return False


def _is_redirect_page(body: str) -> bool:
    """Check if the page is a redirect/gateway page with minimal real content."""
    text_content = re.sub(r'<[^>]+>', '', body).strip()

    # Meta refresh — redirect regardless of size
    if re.search(r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\']', body, re.IGNORECASE):
        if len(text_content) < 500:
            return True

    # JS redirect on a page with minimal visible text
    if len(text_content) < 500:
        if any(p in body for p in ['window.location', 'location.replace', 'location.href']):
            return True

    return False


def detect_domain_redirect(body: str) -> list[str]:
    """Detect JS redirects to external domains (e.g., tplinkrepeater.net).

    Many IoT devices use DNS hijacking to redirect users to a setup domain.
    In rehosted environments, these domains are unreachable.

    Returns:
        List of domain names found in redirect targets.
    """
    domains = []
    # Match patterns like: url="http://example.com/"; location.href="http://example.com"
    for match in re.finditer(
        r'(?:url|location\.\w+|window\.location)\s*[=\(]\s*["\']https?://([^/\'"]+)',
        body, re.IGNORECASE
    ):
        domain = match.group(1)
        # Filter out obviously local addresses
        if domain not in ("localhost", "127.0.0.1") and not re.match(r'^10\.', domain):
            domains.append(domain)
    return domains


def _has_authenticated_markers(body: str) -> bool:
    """Check for content markers that indicate successful authentication."""
    for pattern in _AUTHENTICATED_MARKERS:
        if re.search(pattern, body, re.IGNORECASE):
            return True
    return False


def _is_auth_error(body: str) -> bool:
    """Check if the response body indicates an auth error vs bad request."""
    auth_keywords = ["unauthorized", "not authorized", "authentication failed", "invalid password",
                     "login required", "session expired", "access denied", "permission denied"]
    return any(k in body for k in auth_keywords)


def _follow_redirect_chain(bundle, response, session_cookies, max_hops: int = 5):
    """Follow HTTP redirects like a browser, return (final_response, chain_list)."""
    chain = []
    seen = set()
    for _ in range(max_hops):
        if response.status_code not in {301, 302}:
            break
        location = response.headers.get("Location", "")
        if not location:
            break
        if location in seen:
            break
        seen.add(location)
        chain.append(f"{response.status_code} -> {location}")
        try:
            response = bundle.http.get_with_cookies(location, session_cookies) if session_cookies else bundle.http.get(location)
        except Exception:
            chain.append("follow_failed")
            break
    return response, chain
