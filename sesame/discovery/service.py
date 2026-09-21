from pathlib import Path

from sesame.discovery.binaries import analyze_binaries, find_binaries
from sesame.discovery.configs import find_config_sources
from sesame.discovery.endpoints import find_endpoints
from sesame.discovery.frontend import find_frontend_assets
from sesame.discovery.targets import build_test_targets
from sesame.domain.report import RuntimeStateEvidence
from sesame.utils.logger import get_logger

logger = get_logger(__name__)


def discover_surface(bundle, settings):
    surface = find_binaries(bundle.input.rootfs_path)
    analyze_binaries(surface, settings)
    surface.frontend_assets = find_frontend_assets(bundle.input.rootfs_path)
    surface.config_sources = find_config_sources(bundle.input.rootfs_path)
    surface.runtime_state_evidence = _enrich_config_sources_from_rootfs(
        surface=surface, rootfs_path=bundle.input.rootfs_path
    )
    surface.endpoints = find_endpoints(bundle.input.rootfs_path, surface.frontend_assets)
    surface.candidate_files = sorted(
        {*(b.path for b in surface.web_binaries), *(b.path for b in surface.cgi_binaries), *(a.path for a in surface.frontend_assets)}
    )[: settings.max_targets]
    surface.test_targets = build_test_targets(bundle=bundle, surface=surface)
    return surface


def _enrich_config_sources_from_rootfs(surface, rootfs_path: str) -> list[RuntimeStateEvidence]:
    """Read auth-related files directly from the rootfs filesystem (no shell needed)."""
    evidences: list[RuntimeStateEvidence] = []
    root = Path(rootfs_path)

    # 1. /etc/passwd
    passwd_path = root / "etc" / "passwd"
    if passwd_path.exists():
        try:
            content = passwd_path.read_text(errors="replace").strip()
            if content:
                for source in surface.config_sources:
                    if source.source_type == "unix_auth":
                        source.evidence.append("static:/etc/passwd:present")
                        break
                evidences.append(RuntimeStateEvidence(
                    source="unix_auth", command="static:/etc/passwd",
                    observation=content[:2000], confidence=0.75
                ))
        except Exception:
            pass

    # 2. /etc/shadow
    shadow_path = root / "etc" / "shadow"
    if shadow_path.exists():
        try:
            content = shadow_path.read_text(errors="replace").strip()
            if content:
                for source in surface.config_sources:
                    if source.source_type == "unix_auth":
                        source.evidence.append("static:/etc/shadow:present")
                        break
                evidences.append(RuntimeStateEvidence(
                    source="unix_auth", command="static:/etc/shadow",
                    observation=content[:2000], confidence=0.8
                ))
        except Exception:
            pass

    # 3. Grep for login config references in www/ and etc/
    login_patterns = ["getLoginCfg", "getPasswordCfg", "setPasswordCfg"]
    for search_dir in ["www", "etc"]:
        dir_path = root / search_dir
        if dir_path.is_dir():
            try:
                matches = []
                for f in dir_path.rglob("*"):
                    if f.is_file() and f.stat().st_size < 512_000:
                        try:
                            text = f.read_text(errors="replace")
                            for pat in login_patterns:
                                if pat in text:
                                    matches.append(f"{f.relative_to(root)}: {pat}")
                                    break
                        except Exception:
                            continue
                    if len(matches) >= 20:
                        break
                if matches:
                    evidences.append(RuntimeStateEvidence(
                        source="login_cfg_refs", command=f"static:grep login cfg in {search_dir}/",
                        observation="\n".join(matches[:20]), confidence=0.72
                    ))
            except Exception:
                pass

    # 4. NVRAM
    nvram_path = root / "dev" / "nvram"
    if nvram_path.exists():
        try:
            stat = nvram_path.stat()
            evidences.append(RuntimeStateEvidence(
                source="nvram", command="static:/dev/nvram",
                observation=f"exists, size={stat.st_size}", confidence=0.7
            ))
        except Exception:
            pass

    # 5. Web server binaries detection
    web_binaries = ["lighttpd", "httpd", "goahead", "nginx", "uhttpd", "cstecgi", "mini_httpd"]
    found_web = []
    for search_dir in ["usr/sbin", "usr/bin", "sbin", "bin"]:
        bin_dir = root / search_dir
        if bin_dir.is_dir():
            for name in web_binaries:
                if (bin_dir / name).exists():
                    found_web.append(f"{search_dir}/{name}")
    if found_web:
        evidences.append(RuntimeStateEvidence(
            source="process_list", command="static:web server binaries",
            observation="\n".join(found_web), confidence=0.85
        ))

    # 6. Session files in /tmp
    tmp_path = root / "tmp"
    if tmp_path.is_dir():
        session_files = []
        for pattern in ["*.cookie", "sess*", "httpd*", "luci-sessions*"]:
            for f in tmp_path.glob(pattern):
                session_files.append(str(f.relative_to(root)))
        if session_files:
            evidences.append(RuntimeStateEvidence(
                source="session_files", command="static:/tmp session files",
                observation="\n".join(session_files[:20]), confidence=0.78
            ))

    # 7. Password config files
    config_files = [
        "etc/config/password", "etc/config/auth", "var/password.conf",
        "etc/config/uhttpd", "etc/httpd.conf",
    ]
    found_configs = []
    for cfg in config_files:
        cfg_path = root / cfg
        if cfg_path.exists():
            try:
                content = cfg_path.read_text(errors="replace").strip()
                if content:
                    found_configs.append(f"{cfg}: {content[:200]}")
            except Exception:
                pass
    if found_configs:
        evidences.append(RuntimeStateEvidence(
            source="password_config", command="static:password config files",
            observation="\n".join(found_configs)[:500], confidence=0.82
        ))

    logger.info(f"Collected {len(evidences)} static evidence items from rootfs")
    return evidences
