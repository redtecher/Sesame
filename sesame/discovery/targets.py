import re
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from sesame.domain.report import ReachabilityLevel, TestTarget
from sesame.utils.logger import get_logger

logger = get_logger(__name__)

# Known web root directories relative to rootfs (in priority order)
_WEB_ROOTS = ["htdocs/web", "www", "web", "htdocs"]

# Known CGI/script path prefixes to also probe
_CGI_PREFIXES = ["/HNAP1/", "/cgi-bin/", "/goform/", "/api/"]


def _discover_urls_from_rootfs(rootfs_path: str) -> list[str]:
    """Scan the rootfs for web directories and convert filesystem paths to URL paths."""
    root = Path(rootfs_path)
    urls: list[str] = ["/"]

    for web_root_rel in _WEB_ROOTS:
        web_root = root / web_root_rel
        if not web_root.is_dir():
            continue

        for html_file in web_root.rglob("*.html"):
            rel = html_file.relative_to(web_root)
            url = "/" + str(rel).replace("\\", "/")
            urls.append(url)

        for htm_file in web_root.rglob("*.htm"):
            rel = htm_file.relative_to(web_root)
            url = "/" + str(rel).replace("\\", "/")
            urls.append(url)

        # Only use the first matching web root to avoid duplicates
        break

    return urls


def _discover_urls_from_httpd_config(rootfs_path: str) -> list[str]:
    """Parse httpd config files to extract URL Alias mappings and route prefixes."""
    root = Path(rootfs_path)
    urls: list[str] = []

    # Look for httpd config files that contain Alias directives
    config_dirs = ["etc/services/HTTP", "etc", "etc/config"]
    for config_dir_rel in config_dirs:
        config_dir = root / config_dir_rel
        if not config_dir.is_dir():
            continue
        for cfg_file in config_dir.rglob("*.php"):
            try:
                content = cfg_file.read_text(errors="ignore")
            except Exception:
                continue

            # Extract Alias directives: "Alias /somepath" or Alias /somepath/
            for match in re.finditer(r'Alias\s+(/[\w/\-\.]+)', content):
                alias = match.group(1).strip('"').strip("'")
                if alias and alias != "/" and len(alias) > 1:
                    # Add both with and without trailing slash
                    alias = alias.rstrip("/")
                    urls.append(f"{alias}/")
                    # If it maps to a CGI handler, also add it as an endpoint
                    urls.append(alias)

    return urls


def _build_probe_list(rootfs_path: str, surface) -> list[str]:
    """Build a dynamic probe URL list from rootfs filesystem scanning and httpd config parsing."""
    probe_list: list[str] = []

    # 1. Dynamic URLs from filesystem scanning
    fs_urls = _discover_urls_from_rootfs(rootfs_path)
    logger.info(f"Discovered {len(fs_urls)} URLs from filesystem scanning")
    probe_list.extend(fs_urls)

    # 2. Dynamic URLs from httpd config parsing
    config_urls = _discover_urls_from_httpd_config(rootfs_path)
    logger.info(f"Discovered {len(config_urls)} URLs from httpd config parsing")
    probe_list.extend(config_urls)

    # 3. Endpoint URLs discovered from JS/frontend analysis
    ep_urls = [ep.url for ep in surface.endpoints[:64] if ep.method == "GET"]
    probe_list.extend(ep_urls)

    # 4. Common CGI prefixes (very generic, not device-specific)
    probe_list.extend(_CGI_PREFIXES)

    # Deduplicate while preserving order
    return list(dict.fromkeys(probe_list))


def build_test_targets(bundle, surface) -> list[TestTarget]:
    targets: list[TestTarget] = []
    endpoint_map = {(ep.url, ep.method): ep for ep in surface.endpoints}

    seen_urls: set[str] = set()
    probe_list = _build_probe_list(bundle.input.rootfs_path, surface)

    # Phase A: probe all URLs and collect raw results
    raw_results: list[tuple[str, httpx.Response | None]] = bundle.http.probe_many(probe_list)

    # Phase B: detect auth-gate rewriting (e.g. D-Link authcgi returns login page for all .html)
    # If many different paths return the same body, they are being auth-gate-rewritten
    body_hashes: dict[str, list[int]] = {}  # hash -> list of indices in raw_results
    for i, (path, response) in enumerate(raw_results):
        if response and response.status_code == 200:
            body_hash = _stable_body_hash(response.text)
            body_hashes.setdefault(body_hash, []).append(i)

    # If any single body hash covers >3 different paths, it's likely an auth-gate rewrite
    rewritten_indices: set[int] = set()
    for body_hash, indices in body_hashes.items():
        if len(indices) > 3:
            # Check that these are different meaningful paths (not just / + /foo same page)
            paths = [raw_results[idx][0] for idx in indices]
            unique_stems = set(p.rstrip("/").split("?")[0] for p in paths if p != "/")
            if len(unique_stems) > 3:
                rewritten_indices.update(indices)
                logger.info(f"Detected auth-gate body rewriting: {len(indices)} paths share same 200 response")

    # Phase C: classify each result
    for i, (path, response) in enumerate(raw_results):
        if response is None:
            level = ReachabilityLevel.UNREACHABLE
            blockers = ["http_probe_failed"]
        elif i in rewritten_indices:
            # Auth-gate rewrite: server returned 200 but body is the login page, not the real page
            level = ReachabilityLevel.UNREACHABLE
            blockers = ["auth_gate_rewrite_200"]
        elif response.status_code == 200:
            body = response.text.lower()
            # Detect JS domain redirects (e.g., tplinkrepeater.net, router.asus.com)
            import re as _re
            domain_redirects = _re.findall(
                r'(?:url|location\.\w+|window\.location)\s*[=\(]\s*["\']https?://([^/\'"]+)',
                response.text, _re.IGNORECASE
            )
            external_domains = [d for d in domain_redirects if d not in ("localhost", "127.0.0.1") and not _re.match(r'^10\.', d)]
            if external_domains and len(body.strip()) < 500:
                level = ReachabilityLevel.LOGIN_PAGE
                blockers = [f"dns_redirect:{external_domains[0]}"]
                logger.info(f"Domain redirect detected: {path} -> {external_domains[0]}")
            else:
                is_login_page = (
                    ("login" in body and ("password" in body or "loginfrm" in body or "login_box" in body))
                    or ("window.location.href" in body and "login" in body)
                    or "dologin" in body
                    or "soaplogin" in body
                    or "loginpassword" in body
                    or ("challenge" in body and "publickey" in body)
                )
                is_post_auth = (
                    any(h in body for h in ["logout", "dashboard", "connection_status", "basic_menu"])
                    or ("admin" in body and "password" not in body and "login" not in body)
                )
                if is_login_page and not is_post_auth:
                    level = ReachabilityLevel.LOGIN_PAGE
                    blockers = ["login_form_detected"]
                elif is_post_auth:
                    level = ReachabilityLevel.POST_AUTH_PAGE
                    blockers = []
                else:
                    # Ambiguous page - could be login wrapper or static content
                    level = ReachabilityLevel.LOGIN_PAGE
                blockers = ["reachable_but_not_post_auth"]
        elif response.status_code in {301, 302}:
            location = response.headers.get("Location", "").lower()
            if any(k in location for k in ["login", "signin", "auth"]):
                level = ReachabilityLevel.LOGIN_PAGE
                blockers = ["auth_gate_redirect"]
            else:
                level = ReachabilityLevel.LOGIN_PAGE
                blockers = [f"redirect_to_{location[:60]}"]
        else:
            level = ReachabilityLevel.UNREACHABLE
            blockers = [f"status_{response.status_code}"]

        ep = endpoint_map.get((path, "GET"))
        targets.append(
            TestTarget(
                target_id=path.replace("/", "_") or "root",
                url=path,
                method="GET",
                target_type=_infer_target_type(path),
                reachability=level,
                blockers=blockers,
                source_file=ep.source_file if ep else "",
                tags=list(ep.tags) if ep else [],
                request_chain=["GET " + path],
                request_template={"method": "GET", "url": path},
            )
        )

    topicurl_endpoints = []
    for ep in surface.endpoints:
        if ep.method != "POST":
            continue
        if ep.hints.get("topicurl") and "topicurl_mapping" in ep.tags:
            topicurl_endpoints.append(ep)
        elif "login_cgi" in ep.tags or "auth_entry" in ep.tags:
            topicurl_endpoints.append(ep)

    for ep in topicurl_endpoints[:128]:
        request_chain = ["GET /login.html", f"POST {ep.url}"]
        request_template: dict[str, str] = {}
        topicurl = ep.hints.get("topicurl", "")
        if topicurl:
            request_chain.append(f"topicurl={topicurl}")
            request_template["topicurl"] = topicurl
        if "login_cgi" in ep.tags or ep.hints.get("topicurl") == "login":
            request_template.update({"action": "login", "username": "admin", "password": "<password>"})
        method_name = ep.hints.get("method_name", "")
        target_id_suffix = topicurl or method_name or "post"
        tags = list(ep.tags)
        if topicurl:
            tags.append(f"topicurl={topicurl.lower()}")
        targets.append(
            TestTarget(
                target_id=f"post_{target_id_suffix}_{ep.url.replace('/', '_') or 'root'}",
                url=ep.url,
                method="POST",
                target_type="api",
                reachability=ReachabilityLevel.LOGIN_PAGE,
                blockers=["requires_auth_context"],
                source_file=ep.source_file,
                tags=tags,
                request_chain=request_chain,
                request_template=request_template,
            )
        )

    unique = {}
    for target in targets:
        key = (target.url, target.method, tuple(sorted(target.tags)))
        if key not in unique:
            unique[key] = target
    return list(unique.values())[:256]


def _infer_target_type(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith((".html", ".htm", ".asp")) or lowered == "/":
        return "page"
    if "/api/" in lowered or lowered.endswith((".cgi", ".json", ".xml")):
        return "api"
    return "service"


def _stable_body_hash(text: str) -> str:
    """Hash the first N chars of a response body for duplicate detection."""
    import hashlib
    # Normalize: strip whitespace, lowercase first 2000 chars for stable comparison
    normalized = text.strip().lower()[:2000]
    return hashlib.md5(normalized.encode()).hexdigest()
