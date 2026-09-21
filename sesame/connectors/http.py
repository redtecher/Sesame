from urllib.parse import urljoin

import httpx


class HttpProbe:
    def __init__(self, base_url: str, timeout: float = 8.0):
        self.base_url = base_url.rstrip("/") + "/"
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)

    def get(self, path: str = "") -> httpx.Response:
        return self.client.get(urljoin(self.base_url, path.lstrip("/")))

    def post(self, path: str, data: dict[str, str] | None = None) -> httpx.Response:
        return self.client.post(urljoin(self.base_url, path.lstrip("/")), data=data or {})

    def get_with_cookies(self, path: str, cookies: dict[str, str]) -> httpx.Response:
        return self.client.get(urljoin(self.base_url, path.lstrip("/")), cookies=cookies)

    def post_with_cookies(self, path: str, data: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> httpx.Response:
        return self.client.post(urljoin(self.base_url, path.lstrip("/")), data=data or {}, cookies=cookies or {})

    def probe_many(self, paths: list[str]) -> list[tuple[str, httpx.Response | None]]:
        results = []
        for path in paths:
            try:
                results.append((path, self.get(path)))
            except Exception:
                results.append((path, None))
        return results
