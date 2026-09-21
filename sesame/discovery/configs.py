from pathlib import Path

from sesame.domain.surface import ConfigSource


def find_config_sources(rootfs_path: str) -> list[ConfigSource]:
    root = Path(rootfs_path)
    configs: list[ConfigSource] = []

    if (root / "dev/nvram").exists():
        configs.append(ConfigSource(path=str(root / "dev/nvram"), source_type="nvram", keys=[]))

    config_dir = root / "etc/config"
    if config_dir.exists():
        for item in config_dir.iterdir():
            if item.is_file():
                configs.append(ConfigSource(path=str(item), source_type="uci", keys=[], evidence=[item.name]))

    for rel in ["etc/passwd", "etc/shadow"]:
        path = root / rel
        if path.exists():
            configs.append(ConfigSource(path=str(path), source_type="unix_auth", keys=[], evidence=[rel]))

    for item in root.rglob("*.conf"):
        if item.is_file() and item.stat().st_size < 128 * 1024:
            evidence = []
            try:
                content = item.read_text(errors="ignore")[:4000]
                for keyword in ["login", "password", "auth", "account", "username", "passwd", "topicurl"]:
                    if keyword in content.lower():
                        evidence.append(keyword)
            except Exception:
                pass
            configs.append(ConfigSource(path=str(item), source_type="config_file", keys=[], evidence=evidence))
    return configs[:200]
