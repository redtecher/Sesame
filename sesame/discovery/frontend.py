from pathlib import Path

from sesame.domain.surface import FrontendAsset


def find_frontend_assets(rootfs_path: str) -> list[FrontendAsset]:
    root = Path(rootfs_path)
    assets: list[FrontendAsset] = []
    for rel in ["www", "htdocs", "web"]:
        path = root / rel
        if not path.exists():
            continue
        for ext in ("*.js", "*.html", "*.htm", "*.asp"):
            for item in path.rglob(ext):
                kind = item.suffix.lstrip(".") or "asset"
                assets.append(FrontendAsset(path=str(item), kind=kind))
    return assets[:200]

