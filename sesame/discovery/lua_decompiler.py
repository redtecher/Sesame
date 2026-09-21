"""Detect and decompile Fate/Z encrypted Lua files (Xiaomi/MIWiFi firmware).

Xiaomi routers encrypt their Lua files with a proprietary Fate/Z format.
The unluac_miwifi tool can decompile these files, making them readable
for the LLM agent's filesystem exploration tools.
"""

import os
import subprocess
import tempfile
from pathlib import Path

from sesame.utils.logger import get_logger

logger = get_logger(__name__)

# Path to unluac_miwifi jar (relative to this package)
_UNLUAC_JAR = Path(__file__).parent.parent / "utils" / "unluac_miwifi" / "build" / "unluac.jar"

# Fate/Z magic header (ESC + "Fate/Z")
_FATE_Z_MAGIC = b"\x1bFate/Z"


def is_fate_z_encrypted(file_path: str | Path) -> bool:
    """Check if a file starts with the Fate/Z magic header."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(7)
            return header == _FATE_Z_MAGIC
    except Exception:
        return False


def decompile_lua(file_path: str | Path, jar_path: str | Path | None = None) -> str | None:
    """Decompile a single Fate/Z encrypted Lua file.

    Returns the decompiled source code, or None on failure.
    """
    jar = Path(jar_path) if jar_path else _UNLUAC_JAR
    if not jar.exists():
        logger.warning(f"unluac_miwifi jar not found: {jar}")
        return None

    try:
        result = subprocess.run(
            ["java", "-jar", str(jar), str(file_path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        return None
    except Exception as e:
        logger.debug(f"Decompile failed for {file_path}: {e}")
        return None


def batch_decompile_lua(rootfs_path: str, cache_dir: str | None = None) -> str:
    """Scan rootfs for Fate/Z encrypted Lua files, decompile them to a cache dir.

    Returns the cache directory path (where decompiled files are stored).
    If no encrypted Lua files found, returns empty string.
    """
    rootfs = Path(rootfs_path)
    jar = _UNLUAC_JAR

    if not jar.exists():
        logger.debug("unluac_miwifi jar not found, skipping Lua decompilation")
        return ""

    # Find encrypted Lua files
    encrypted_files = []
    for lua_file in rootfs.rglob("*.lua"):
        if is_fate_z_encrypted(lua_file):
            encrypted_files.append(lua_file)

    if not encrypted_files:
        logger.info("No Fate/Z encrypted Lua files found")
        return ""

    logger.info(f"Found {len(encrypted_files)} Fate/Z encrypted Lua files, decompiling...")

    # Create cache directory
    if cache_dir is None:
        cache_dir = os.path.join(tempfile.gettempdir(), f"sesame_decompiled_{os.getpid()}")
    os.makedirs(cache_dir, exist_ok=True)

    success = 0
    for lua_file in encrypted_files:
        rel_path = lua_file.relative_to(rootfs)
        # Decompile
        source = decompile_lua(lua_file, jar)
        if source:
            dest = Path(cache_dir) / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(source)
            success += 1

    logger.info(f"Decompiled {success}/{len(encrypted_files)} Lua files to {cache_dir}")
    return cache_dir
