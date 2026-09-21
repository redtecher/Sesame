"""Playwright browser driver for firmware web interface analysis."""

from dataclasses import dataclass, field

from sesame.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class BrowserResult:
    status: str = "ok"  # "ok", "redirect_to_login", "error"
    final_url: str = ""
    content_snippet: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    error: str = ""


class BrowserDriver:
    """Playwright sync_api wrapper for browser automation."""

    def __init__(self, headless: bool = True):
        self.headless = headless
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None

    def launch(self) -> None:
        """Start browser and create a new context."""
        from playwright.sync_api import sync_playwright
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=self.headless)
        self._context = self._browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        self._page = self._context.new_page()
        self._page.set_default_timeout(15000)
        logger.info("Browser launched")

    def navigate(self, url: str) -> BrowserResult:
        """Navigate to URL, return status, final URL, content snippet."""
        if not self._page:
            return BrowserResult(status="error", error="Browser not launched")

        try:
            response = self._page.goto(url, wait_until="networkidle", timeout=15000)
            final_url = self._page.url
            content = self._page.content()
            cookies = self.get_cookies()

            # Detect login redirect
            if final_url != url and any(k in final_url.lower() for k in ["login", "signin", "auth"]):
                return BrowserResult(
                    status="redirect_to_login",
                    final_url=final_url,
                    content_snippet=content[:500],
                    cookies=cookies,
                )

            # Extract visible text
            try:
                visible_text = self._page.inner_text("body")[:2000]
            except Exception:
                visible_text = content[:2000]

            return BrowserResult(
                status="ok",
                final_url=final_url,
                content_snippet=visible_text[:500],
                cookies=cookies,
            )
        except Exception as e:
            return BrowserResult(status="error", error=str(e))

    def fill_form(self, fields: dict[str, str], submit_selector: str = "") -> BrowserResult:
        """Fill form fields and optionally click submit."""
        if not self._page:
            return BrowserResult(status="error", error="Browser not launched")

        try:
            for selector, value in fields.items():
                try:
                    self._page.fill(selector, value, timeout=3000)
                except Exception:
                    # Try alternative selectors
                    for alt_selector in [
                        f'input[name="{selector}"]',
                        f'input[id="{selector}"]',
                        f'#{selector}',
                    ]:
                        try:
                            self._page.fill(alt_selector, value, timeout=2000)
                            break
                        except Exception:
                            continue

            if submit_selector:
                try:
                    self._page.click(submit_selector, timeout=3000)
                    self._page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass

            return BrowserResult(
                status="ok",
                final_url=self._page.url,
                content_snippet=self._page.content()[:500],
                cookies=self.get_cookies(),
            )
        except Exception as e:
            return BrowserResult(status="error", error=str(e))

    def get_cookies(self) -> dict[str, str]:
        """Return all cookies from current context as name->value dict."""
        if not self._context:
            return {}
        try:
            cookies = self._context.cookies()
            return {c["name"]: c["value"] for c in cookies}
        except Exception:
            return {}

    def get_page_text(self) -> str:
        """Return visible text content of current page."""
        if not self._page:
            return ""
        try:
            return self._page.inner_text("body")
        except Exception:
            return ""

    def get_page_html(self) -> str:
        """Return HTML content of current page."""
        if not self._page:
            return ""
        try:
            return self._page.content()
        except Exception:
            return ""

    def get_current_url(self) -> str:
        """Return current page URL (after redirects)."""
        if not self._page:
            return ""
        return self._page.url

    def close(self) -> None:
        """Close browser and stop Playwright."""
        try:
            if self._context:
                self._context.close()
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
