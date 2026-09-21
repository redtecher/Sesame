"""Known IoT firmware authentication patterns and bypass conditions."""

import re
from pathlib import Path

from sesame.utils.logger import get_logger

logger = get_logger(__name__)

# Known vendor authentication patterns
VENDOR_AUTH_PATTERNS = {
    "totolink": {
        "auth_type": "custom_cgi",
        "login_url": "/cgi-bin/cstecgi.cgi",
        "login_params": {"action": "login", "username": "admin", "password": ""},
        "session_cookie": "SESSION_ID",
        "default_creds": [{"username": "admin", "password": ""}],
        "indicators": ["cstecgi.cgi", "topicurl", "TOTOLINK"],
    },
    "xiaomi": {
        "auth_type": "luci_api",
        "login_url": "/cgi-bin/luci/api/xqsystem/login",
        "session_token": "stok",
        "crypto": "sha1(sha1(pwd+key)+nonce)",
        "default_creds": [{"username": "admin", "password": ""}],
        "indicators": ["xqsystem", "miwifi", "xiaomi", "stok"],
    },
    "dlink": {
        "auth_type": "hnap",
        "login_url": "/HNAP1/",
        "session_cookie": "uid",
        "crypto": "hmac_md5",
        "default_creds": [{"username": "admin", "password": ""}],
        "indicators": ["HNAP1", "dlink", "D-Link", "soaplogin"],
    },
    "tplink": {
        "auth_type": "goahead",
        "login_url": "/goform/formLogin",
        "session_cookie": "session_id",
        "default_creds": [{"username": "admin", "password": "admin"}],
        "indicators": ["goform", "TP-LINK", "tplink", "formLogin"],
    },
    "tenda": {
        "auth_type": "goahead",
        "login_url": "/goform/LoginCheck",
        "session_cookie": "session_id",
        "default_creds": [{"username": "admin", "password": "admin"}],
        "indicators": ["Tenda", "goform", "LoginCheck"],
    },
    "netgear": {
        "auth_type": "basic_or_cgi",
        "login_url": "/cgi-bin/noauth.cgi",
        "session_cookie": "session_id",
        "default_creds": [{"username": "admin", "password": "password"}],
        "indicators": ["NETGEAR", "netgear", "noauth.cgi"],
    },
    "asus": {
        "auth_type": "httpd",
        "login_url": "/login.cgi",
        "session_cookie": "asus_token",
        "default_creds": [{"username": "admin", "password": "admin"}],
        "indicators": ["ASUS", "asus", "login.cgi", "httpd"],
    },
    "openwrt": {
        "auth_type": "luci",
        "login_url": "/cgi-bin/luci",
        "session_cookie": "sysauth",
        "session_store": "/tmp/luci-sessions/",
        "default_creds": [{"username": "root", "password": ""}],
        "indicators": ["luci", "openwrt", "uhttpd", "sysauth"],
    },
}

# Known authentication bypass patterns
KNOWN_BYPASS_PATTERNS = [
    {
        "name": "empty_password",
        "description": "NVRAM/UCI 中无密码设置，空密码即可登录",
        "check_indicators": ["nvram empty", "no password set", "default_empty"],
        "shell_command": "curl -d 'action=login&username=admin&password=' {web_url}/cgi-bin/cstecgi.cgi",
    },
    {
        "name": "hardcoded_credentials",
        "description": "二进制中发现硬编码后门凭据",
        "check_indicators": ["base64 credential", "Authorization: Basic", "user:pass pair in binary"],
        "shell_command": "# Use credentials found in binary analysis",
    },
    {
        "name": "debug_mode",
        "description": "调试模式标志可启用，跳过认证检查",
        "check_indicators": ["debug_mode", "bypass_auth", "no_auth", "telnet_enabled"],
        "shell_command": "nvram set debug_mode=1 && nvram commit",
    },
    {
        "name": "hash_injection",
        "description": "计算密码 hash 后写入 NVRAM/UCI 存储",
        "check_indicators": ["sha1", "md5", "uci set", "nvram set http_passwd"],
        "shell_command": "uci set account.common.admin=$(echo -n 'adminKEY' | sha1sum | cut -d' ' -f1) && uci commit",
    },
    {
        "name": "state_file_creation",
        "description": "创建认证状态文件绕过检查",
        "check_indicators": ["/tmp/login_flag", "/tmp/auth_state", "/var/login_ok"],
        "shell_command": "echo 1 > /tmp/login_flag",
    },
    {
        "name": "timing_bypass",
        "description": "利用启动时认证初始化的竞态条件",
        "check_indicators": ["boot race", "auth init delay"],
        "shell_command": "/etc/init.d/httpd restart && sleep 0.1 && curl {web_url}/admin/",
    },
    {
        "name": "default_session_token",
        "description": "固件内置固定的默认 session token",
        "check_indicators": ["fixed token", "default session", "hardcoded session_id"],
        "shell_command": "# Use the default token found in binary analysis",
    },
    {
        "name": "cookie_forging",
        "description": "Session cookie 可预测，可直接构造",
        "check_indicators": ["md5(timestamp)", "predictable cookie", "admin_<timestamp>"],
        "shell_command": "# Construct cookie from known algorithm",
    },
    {
        "name": "path_confusion",
        "description": "大小写路径差异绕过认证检查",
        "check_indicators": ["case sensitive auth", "admin vs Admin"],
        "shell_command": "curl {web_url}/Admin/  # vs /admin/",
    },
    {
        "name": "unauthenticated_endpoints",
        "description": "部分管理端点无需认证即可访问",
        "check_indicators": ["no auth check", "skip_auth", "public endpoint"],
        "shell_command": "# Access the unauthenticated endpoint directly",
    },
]


def match_known_vendor(rootfs_path: str) -> list[dict]:
    """Match known vendor authentication patterns from rootfs indicators."""
    matches = []
    root = Path(rootfs_path)

    # Collect indicator text from key files
    indicator_text = _collect_indicator_text(root)

    for vendor, pattern in VENDOR_AUTH_PATTERNS.items():
        score = 0
        matched_indicators = []
        for indicator in pattern.get("indicators", []):
            if indicator.lower() in indicator_text.lower():
                score += 1
                matched_indicators.append(indicator)
        if score >= 1:
            matches.append({
                "vendor": vendor,
                "score": score,
                "matched_indicators": matched_indicators,
                "auth_pattern": pattern,
            })

    matches.sort(key=lambda x: x["score"], reverse=True)
    return matches


def match_bypass_patterns(rootfs_path: str, auth_strings: list[str] = None) -> list[dict]:
    """Match known bypass patterns from rootfs analysis."""
    matches = []
    root = Path(rootfs_path)
    auth_strings = auth_strings or []

    # Collect all relevant text
    indicator_text = _collect_indicator_text(root)
    all_text = indicator_text + " " + " ".join(auth_strings)

    for pattern in KNOWN_BYPASS_PATTERNS:
        score = 0
        for indicator in pattern["check_indicators"]:
            if indicator.lower() in all_text.lower():
                score += 1
        if score > 0:
            matches.append({
                "name": pattern["name"],
                "description": pattern["description"],
                "score": score,
                "shell_command": pattern["shell_command"],
            })

    matches.sort(key=lambda x: x["score"], reverse=True)
    return matches


def _collect_indicator_text(root: Path) -> str:
    """Collect text from key firmware files for indicator matching."""
    texts = []

    # Check binary names in common locations
    for bin_dir in ["usr/sbin", "usr/bin", "sbin", "bin"]:
        bin_path = root / bin_dir
        if bin_path.is_dir():
            try:
                texts.extend(f.name for f in bin_path.iterdir() if f.is_file())
            except Exception:
                pass

    # Check web server configs
    config_files = [
        "etc/httpd.conf", "etc/lighttpd/lighttpd.conf", "etc/nginx/nginx.conf",
        "etc/config/uhttpd", "etc/passwd",
    ]
    for cfg in config_files:
        cfg_path = root / cfg
        if cfg_path.exists():
            try:
                texts.append(cfg_path.read_text(errors="replace")[:2000])
            except Exception:
                pass

    # Check JS/HTML for vendor indicators
    for web_dir in ["www", "htdocs", "web"]:
        web_path = root / web_dir
        if web_path.is_dir():
            try:
                for f in list(web_path.rglob("*.js"))[:10] + list(web_path.rglob("*.html"))[:5]:
                    try:
                        texts.append(f.read_text(errors="replace")[:1000])
                    except Exception:
                        pass
            except Exception:
                pass

    return " ".join(texts)
