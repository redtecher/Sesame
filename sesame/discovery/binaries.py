from pathlib import Path

from sesame.domain.surface import BinaryInfo, FileRole, SurfaceSnapshot
from sesame.utils.logger import get_logger

logger = get_logger(__name__)

WEB_NAMES = {"lighttpd", "goahead", "httpd", "nginx", "uhttpd", "boa"}

_ELF_MAGIC = b"\x7fELF"


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == _ELF_MAGIC
    except Exception:
        return False


def find_binaries(rootfs_path: str) -> SurfaceSnapshot:
    root = Path(rootfs_path)
    snapshot = SurfaceSnapshot()
    for rel in ["bin", "sbin", "usr/bin", "usr/sbin", "www/cgi-bin"]:
        path = root / rel
        if not path.exists():
            continue
        for item in path.iterdir():
            if not item.is_file():
                continue
            name = item.name.lower()
            if name in WEB_NAMES:
                snapshot.web_binaries.append(BinaryInfo(path=str(item), name=item.name, role=FileRole.WEB_SERVER))
            elif (rel.endswith("cgi-bin") or name.endswith(".cgi")) and _is_elf(item):
                snapshot.cgi_binaries.append(BinaryInfo(path=str(item), name=item.name, role=FileRole.CGI_HANDLER))
    return snapshot


def analyze_binaries(snapshot: SurfaceSnapshot, settings=None) -> None:
    from sesame.discovery.binary_analysis import BinaryAnalyzer

    analyzer = BinaryAnalyzer()
    if not analyzer.is_available():
        logger.info("r2pipe unavailable, skipping binary analysis")
        return

    binaries = snapshot.web_binaries[:3] + snapshot.cgi_binaries[:5]
    for b in binaries:
        try:
            result = analyzer.analyze(b.path)
            b.analysis = result
            if result.arch != "unknown":
                b.arch = result.arch
            logger.info(f"Analyzed {b.name}: arch={result.arch} auth_strings={len(result.auth_strings)} "
                        f"auth_funcs={len(result.auth_functions)} imports={len(result.key_imports)}")
        except Exception as e:
            logger.warning(f"Binary analysis failed for {b.name}: {e}")
