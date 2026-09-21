import re
from pathlib import Path

from sesame.domain.surface import Endpoint, FrontendAsset

URL_PATTERNS = [
    r'url\s*[:=]\s*["\']([^"\']+)["\']',
    r'\.(?:post|get|ajax)\s*\(\s*["\']([^"\']+)',
    r'fetch\s*\(\s*["\']([^"\']+)',
    r'action\s*=\s*["\']([^"\']+)',
    r'topicurl\s*[:=]\s*["\']([^"\']+)["\']',
    # XHR patterns
    r'\.open\s*\(\s*["\'](\w+)["\'],\s*["\']([^"\']+)',
    # $.ajax object form
    r'\$\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)',
    # axios
    r'axios\s*\.\s*(get|post)\s*\(\s*["\']([^"\']+)',
    # build_url (LuCI)
    r'build_url\s*\(\s*["\']([^"\')]+)["\']',
]


def find_endpoints(rootfs_path: str, frontend_assets: list[FrontendAsset]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    seen: set[tuple] = set()

    for asset in frontend_assets:
        try:
            content = Path(asset.path).read_text(errors="ignore")
        except Exception:
            continue

        if asset.path.endswith("login.html"):
            _add_endpoint(endpoints, seen, "/login.html", "GET", asset.path, tags=["login_page"], hints={"page": "login"})
            _add_endpoint(endpoints, seen, "/cgi-bin/cstecgi.cgi", "POST", asset.path, tags=["login_cgi", "auth_entry"], hints={"topicurl": "login", "action": "login"})

        if asset.path.endswith("config.js"):
            _parse_config_js(asset.path, content, endpoints, seen)

        if asset.path.endswith("topicurl.js"):
            _parse_topicurl_js(asset.path, content, endpoints, seen)

        if asset.path.endswith("common.js") or asset.path.endswith("layout.js"):
            _parse_menu_items(asset.path, content, endpoints, seen)

        for pattern in URL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                raw = match.group(1)
                if pattern.startswith("topicurl"):
                    _add_endpoint(
                        endpoints, seen, "/cgi-bin/cstecgi.cgi", "POST", asset.path,
                        tags=["topicurl", "discovered", "frontend_declared_only"],
                        hints={"topicurl": raw},
                    )
                    continue

                # XHR open pattern: first group is method, second is URL
                if pattern.startswith(r'\.open'):
                    xhr_method = match.group(1).upper()
                    xhr_url = match.group(2)
                    if xhr_url.startswith("/"):
                        _add_endpoint(endpoints, seen, xhr_url, xhr_method, asset.path, tags=["xhr", "discovered"], hints={})
                    continue

                # axios pattern: first group is method, second is URL
                if pattern.startswith(r'axios'):
                    ax_method = match.group(1).upper()
                    ax_url = match.group(2)
                    if ax_url.startswith("/"):
                        _add_endpoint(endpoints, seen, ax_url, ax_method, asset.path, tags=["axios", "discovered"], hints={})
                    continue

                # build_url pattern: construct LuCI path
                if pattern.startswith(r'build_url'):
                    build_parts = raw.replace('"', '').replace("'", "").split(",")
                    if build_parts:
                        luCI_path = "/cgi-bin/luci/" + "/".join(p.strip() for p in build_parts)
                        _add_endpoint(endpoints, seen, luCI_path, "GET", asset.path, tags=["luci_route", "discovered"], hints={"build_url_raw": raw})
                    continue

                url = raw
                if not url.startswith("/"):
                    continue
                method = _infer_method(content, match.start())
                tags = ["discovered"]
                hints: dict[str, str] = {}
                lowered = url.lower()
                if "login" in lowered:
                    tags.append("login_related")
                if lowered.endswith(".json"):
                    tags.append("json_candidate")
                _add_endpoint(endpoints, seen, url, method, asset.path, tags=tags, hints=hints)

    # Parse LuCI Lua routes from controller files
    _parse_luci_lua_routes(rootfs_path, endpoints, seen)

    # Parse .htm template build_url references
    _parse_htm_build_urls(rootfs_path, endpoints, seen)

    # Parse nginx REST API routes from conf.d
    _parse_nginx_rest_routes(rootfs_path, endpoints, seen)

    return endpoints[:512]


def _parse_luci_lua_routes(rootfs_path: str, endpoints: list[Endpoint], seen: set) -> None:
    """Parse LuCI Lua controller files for route definitions (entry({...}) patterns)."""
    root = Path(rootfs_path)
    controller_dirs = [
        root / "usr" / "lib" / "lua" / "luci" / "controller",
        root / "usr" / "lib" / "lua" / "luci" / "model" / "cbi",
    ]

    for ctrl_dir in controller_dirs:
        if not ctrl_dir.is_dir():
            continue
        for lua_file in ctrl_dir.rglob("*.lua"):
            # Skip Fate/Z encrypted files
            try:
                with open(lua_file, "rb") as f:
                    header = f.read(7)
                    if header == b"\x1bFate/Z":
                        continue
            except Exception:
                continue

            try:
                content = lua_file.read_text(errors="ignore")
            except Exception:
                continue

            rel_path = str(lua_file.relative_to(root))

            # Pattern 1: entry({"admin", "network", "wan"}, ...)
            entry_pattern = re.compile(
                r'entry\s*\(\s*\{([^}]+)\}',
                re.IGNORECASE,
            )
            for match in entry_pattern.finditer(content):
                route_parts = match.group(1)
                parts = re.findall(r'"([^"]+)"|\'([^\']+)\'', route_parts)
                clean_parts = [p[0] or p[1] for p in parts]
                if clean_parts:
                    url = "/cgi-bin/luci/" + "/".join(clean_parts)
                    _add_endpoint(endpoints, seen, url, "GET", rel_path,
                                  tags=["luci_route", "lua_controller"],
                                  hints={"source": "lua_entry"})

            # Pattern 2: page.entry(...)
            page_entry = re.compile(
                r'page\s*:\s*entry\s*\(\s*\{([^}]+)\}',
                re.IGNORECASE,
            )
            for match in page_entry.finditer(content):
                route_parts = match.group(1)
                parts = re.findall(r'"([^"]+)"|\'([^\']+)\'', route_parts)
                clean_parts = [p[0] or p[1] for p in parts]
                if clean_parts:
                    url = "/cgi-bin/luci/" + "/".join(clean_parts)
                    _add_endpoint(endpoints, seen, url, "GET", rel_path,
                                  tags=["luci_route", "lua_controller"],
                                  hints={"source": "lua_page_entry"})

            # Pattern 3: map("admin", "network", ...) or similar CBI maps
            map_pattern = re.compile(
                r'map\s*\(\s*["\'](\w+)["\']\s*,\s*["\'](\w+)["\']',
                re.IGNORECASE,
            )
            for match in map_pattern.finditer(content):
                section, subsection = match.groups()
                url = f"/cgi-bin/luci/admin/{section}/{subsection}"
                _add_endpoint(endpoints, seen, url, "GET", rel_path,
                              tags=["luci_cbi", "lua_controller"],
                              hints={"source": "lua_cbi_map"})


def _parse_htm_build_urls(rootfs_path: str, endpoints: list[Endpoint], seen: set) -> None:
    """Parse .htm template files for build_url() LuCI route references."""
    root = Path(rootfs_path)
    view_dirs = [
        root / "usr" / "lib" / "lua" / "luci" / "view",
        root / "www",
        root / "htdocs",
    ]

    for view_dir in view_dirs:
        if not view_dir.is_dir():
            continue
        for htm_file in list(view_dir.rglob("*.htm")) + list(view_dir.rglob("*.html")):
            # Skip large files
            if htm_file.stat().st_size > 200_000:
                continue
            try:
                content = htm_file.read_text(errors="ignore")
            except Exception:
                continue

            rel_path = str(htm_file.relative_to(root))

            # Find build_url("api", "xqsystem", "login") patterns
            build_url_pattern = re.compile(
                r'build_url\s*\(\s*["\']([^"\')]+)["\'](?:\s*,\s*["\']([^"\')]+)["\'])*(?:\s*,\s*["\']([^"\')]+)["\'])?',
                re.IGNORECASE,
            )
            for match in build_url_pattern.finditer(content):
                parts = [g for g in match.groups() if g]
                if parts:
                    url = "/cgi-bin/luci/" + "/".join(parts)
                    _add_endpoint(endpoints, seen, url, "POST", rel_path,
                                  tags=["luci_api", "htm_template"],
                                  hints={"source": "build_url", "parts": ",".join(parts)})


def _parse_config_js(source_file: str, content: str, endpoints: list[Endpoint], seen: set) -> None:
    cgi_match = re.search(r'cgiUrl\s*:\s*"([^"]+)"', content)
    if cgi_match:
        cgi_url = cgi_match.group(1)
        _add_endpoint(endpoints, seen, cgi_url, "POST", source_file, tags=["cgi_entry"], hints={"cgi_url": cgi_url})

    menu_matches = re.finditer(r'href\s*:\s*"([^"]+)"', content)
    for match in menu_matches:
        page = match.group(1)
        _add_endpoint(endpoints, seen, f"/basic/{page}.html", "GET", source_file, tags=["menu_page", "post_auth_candidate"], hints={"page": page})
        _add_endpoint(endpoints, seen, f"/advance/{page}.html", "GET", source_file, tags=["menu_page", "post_auth_candidate"], hints={"page": page})


def _parse_topicurl_js(source_file: str, content: str, endpoints: list[Endpoint], seen: set) -> None:
    pattern = re.compile(
        r'\.prototype\.(\w+)\s*=\s*function\([^)]*\)\s*\{[^}]*?this\.topicurl\s*=\s*"([^"]+)"[^}]*?this\.url\s*=\s*"([^"]*)"',
        re.IGNORECASE,
    )
    for match in pattern.finditer(content):
        method_name, topicurl, debug_url = match.groups()
        tags = ["topicurl_mapping", "api_candidate"]
        if topicurl.startswith("set") or topicurl.startswith("del"):
            tags.append("write_operation")
        elif topicurl.startswith("get"):
            tags.append("read_operation")
        hints: dict[str, str] = {"topicurl": topicurl, "method_name": method_name}
        if debug_url:
            hints["debug_data_url"] = debug_url
        _add_endpoint(endpoints, seen, "/cgi-bin/cstecgi.cgi", "POST", source_file, tags=tags, hints=hints)

    simple_pattern = re.compile(
        r'\.prototype\.(\w+)\s*=\s*function\([^)]*\)\s*\{\s*return\s+this\.topicurl\s*=\s*"([^"]+)"',
        re.IGNORECASE,
    )
    for match in simple_pattern.finditer(content):
        method_name, topicurl = match.groups()
        if any(e.hints.get("topicurl") == topicurl and e.hints.get("method_name") == method_name for e in endpoints):
            continue
        tags = ["topicurl_mapping", "api_candidate"]
        if topicurl.startswith("set") or topicurl.startswith("del"):
            tags.append("write_operation")
        elif topicurl.startswith("get"):
            tags.append("read_operation")
        hints = {"topicurl": topicurl, "method_name": method_name}
        _add_endpoint(endpoints, seen, "/cgi-bin/cstecgi.cgi", "POST", source_file, tags=tags, hints=hints)


def _parse_menu_items(source_file: str, content: str, endpoints: list[Endpoint], seen: set) -> None:
    menu_pattern = re.compile(r'href\s*:\s*"(\w+)"')
    for match in menu_pattern.finditer(content):
        page = match.group(1)
        if page in {"index", "wan", "wifi", "lan", "guest", "parental", "qos", "gamespeed"}:
            _add_endpoint(endpoints, seen, f"/basic/{page}.html", "GET", source_file, tags=["menu_page", "post_auth_candidate"], hints={"page": page})


def _infer_method(content: str, pos: int) -> str:
    ctx = content[max(0, pos - 500):pos + 500].lower()
    if any(x in ctx for x in [".post", "method:'post'", 'method:"post"', "type:'post'", 'type:"post"']):
        return "POST"
    return "GET"


def _add_endpoint(endpoints: list[Endpoint], seen: set, url: str, method: str, source_file: str, tags: list[str], hints: dict[str, str]) -> None:
    key = (url, method, tuple(sorted(hints.items())))
    if key in seen:
        return
    seen.add(key)
    endpoints.append(Endpoint(url=url, method=method, source_file=source_file, tags=tags, hints=hints))


def _parse_nginx_rest_routes(rootfs_path: str, endpoints: list[Endpoint], seen: set) -> None:
    """Parse REST API routes from nginx configuration files (Cisco RV340, etc.)."""
    nginx_conf_dirs = [
        Path(rootfs_path) / "etc/nginx/conf.d",
        Path(rootfs_path) / "etc/nginx",
    ]

    for conf_dir in nginx_conf_dirs:
        if not conf_dir.is_dir():
            continue

        for conf_file in conf_dir.glob("*.conf"):
            try:
                content = conf_file.read_text(errors="ignore")
            except Exception:
                continue

            # Parse nginx location blocks: location /api/operations/ciscosb-file:form-file-upload {
            location_pattern = re.compile(
                r'location\s+([~/=\^]*)\s*([^\s{]+)\s*\{',
                re.MULTILINE
            )

            for match in location_pattern.finditer(content):
                modifier = match.group(1).strip()
                location_path = match.group(2).strip()

                # Skip internal locations and variables
                if location_path.startswith("@") or "$" in location_path:
                    continue

                # Extract the block content to determine method and auth requirements
                block_start = match.end()
                block_end = _find_matching_brace(content, block_start)
                if block_end == -1:
                    continue

                block_content = content[block_start:block_end]

                # Determine HTTP methods allowed
                methods = ["GET", "POST"]  # Default
                if "proxy_pass" in block_content or "uwsgi_pass" in block_content:
                    methods = ["GET", "POST", "PUT", "DELETE"]
                if "upload_pass" in block_content:
                    methods = ["POST"]

                # Check auth requirements
                tags = ["nginx_location", "rest_api"]
                hints = {"nginx_conf": str(conf_file.relative_to(rootfs_path))}

                if "auth_request" in block_content:
                    tags.append("auth_required")
                if "$http_authorization" in block_content:
                    tags.append("authorization_header_check")
                if "return 403" in block_content or "return 401" in block_content:
                    tags.append("conditional_auth")

                # Special handling for Cisco REST API patterns
                if location_path.startswith("/api/"):
                    tags.append("cisco_rest_api")
                    if "ciscosb-file:form-file-upload" in location_path:
                        tags.append("file_upload")
                        tags.append("cve_2023_20073_endpoint")
                    if "ciscosb-aaa:login" in location_path:
                        tags.append("login_endpoint")

                # Add endpoint for each method
                for method in methods:
                    _add_endpoint(
                        endpoints, seen, location_path, method,
                        str(conf_file.relative_to(rootfs_path)),
                        tags=tags.copy(),
                        hints=hints.copy()
                    )


def _find_matching_brace(content: str, start: int) -> int:
    """Find the matching closing brace for a block starting at position start."""
    depth = 1
    i = start
    while i < len(content) and depth > 0:
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
        i += 1
    return i if depth == 0 else -1
