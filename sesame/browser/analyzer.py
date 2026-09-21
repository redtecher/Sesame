"""Web page analyzer for login form structure and token mechanism detection."""

import json
import re
from dataclasses import dataclass, field

from sesame.browser.driver import BrowserDriver
from sesame.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class LoginFormInfo:
    url: str = ""
    action: str = ""
    method: str = "POST"
    fields: dict[str, str] = field(default_factory=dict)  # name -> type
    hidden_fields: dict[str, str] = field(default_factory=dict)  # name -> value
    submit_selector: str = ""
    has_captcha: bool = False
    has_csrf: bool = False
    js_auth_logic: str = ""  # extracted JS auth patterns


@dataclass
class TokenInfo:
    mechanism: str = ""  # "cookie", "url_path", "header"
    cookie_names: list[str] = field(default_factory=list)
    url_token_pattern: str = ""
    redirect_pattern: str = ""
    js_token_refs: list[str] = field(default_factory=list)


class WebAnalyzer:
    """Analyze firmware web interface for login structure and token mechanisms."""

    def __init__(self, driver: BrowserDriver, base_url: str):
        self.driver = driver
        self.base_url = base_url.rstrip("/")

    def analyze_login_page(self, login_url: str = "/") -> LoginFormInfo:
        """Navigate to login page and extract form structure."""
        full_url = self.base_url + login_url if not login_url.startswith("http") else login_url
        result = self.driver.navigate(full_url)

        if result.status == "error":
            logger.warning(f"Failed to navigate to login page: {result.error}")
            return LoginFormInfo(url=full_url)

        html = self.driver.get_page_html()
        return self._parse_login_form(html, result.final_url)

    def detect_token_mechanism(self, login_url: str = "/") -> TokenInfo:
        """Detect how authentication tokens work."""
        full_url = self.base_url + login_url if not login_url.startswith("http") else login_url
        result = self.driver.navigate(full_url)

        if result.status == "error":
            return TokenInfo()

        html = self.driver.get_page_html()
        return self._analyze_token_mechanism(html, result)

    def extract_js_auth_patterns(self, html: str) -> dict:
        """Extract authentication-related patterns from page JavaScript."""
        patterns = {}

        # Find login-related JavaScript
        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)

        for js in js_blocks:
            # Find form submission patterns
            form_subs = re.findall(r'(?:\.submit|\.ajax|fetch|XMLHttpRequest).*?["\']([^"\']+)["\']', js)
            if form_subs:
                patterns.setdefault("form_actions", []).extend(form_subs)

            # Find crypto patterns
            crypto = re.findall(r'(?:Encrypt|SHA1|MD5|sha1|md5|AES|encrypt)\s*[\.(]', js)
            if crypto:
                patterns.setdefault("crypto_refs", []).extend(crypto[:5])

            # Find URL patterns
            urls = re.findall(r'["\']/(?:cgi-bin|goform|api|HNAP1)/[^"\']+["\']', js)
            if urls:
                patterns.setdefault("api_urls", []).extend(urls)

            # Find variable assignments with auth keywords
            auth_vars = re.findall(r'var\s+(\w*(?:user|pass|token|session|auth|login)\w*)\s*=', js, re.IGNORECASE)
            if auth_vars:
                patterns.setdefault("auth_variables", []).extend(auth_vars)

        return patterns

    def _parse_login_form(self, html: str, url: str) -> LoginFormInfo:
        """Parse HTML to extract login form structure."""
        info = LoginFormInfo(url=url)

        # Find form with login-related attributes
        form_patterns = [
            r'<form[^>]*(?:action|id|class|name)=["\']?[^"\']*login[^"\']*["\']?[^>]*>(.*?)</form>',
            r'<form[^>]*>(.*?)</form>',
        ]

        form_html = ""
        for pattern in form_patterns:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                form_html = match.group(0)
                break

        if not form_html:
            return info

        # Extract form action
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        if action_match:
            info.action = action_match.group(1)

        # Extract form method
        method_match = re.search(r'method=["\'](\w+)["\']', form_html, re.IGNORECASE)
        if method_match:
            info.method = method_match.group(1).upper()

        # Extract input fields
        input_pattern = r'<input[^>]*>'
        for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
            input_tag = input_match.group(0)
            name = self._extract_attr(input_tag, "name")
            input_type = self._extract_attr(input_tag, "type") or "text"
            value = self._extract_attr(input_tag, "value")

            if not name:
                continue

            if input_type == "hidden":
                info.hidden_fields[name] = value or ""
            elif input_type in ("password", "text", "email"):
                info.fields[name] = input_type

            if input_type == "password":
                info.fields[name] = "password"

        # Check for CSRF token
        if any(k in str(info.hidden_fields).lower() for k in ["csrf", "token", "_token", "nonce"]):
            info.has_csrf = True

        # Check for captcha
        if any(k in html.lower() for k in ["captcha", "recaptcha", "g-recaptcha"]):
            info.has_captcha = True

        # Find submit button
        submit_patterns = [
            r'<(?:input|button)[^>]*type=["\']submit["\'][^>]*>',
            r'<button[^>]*(?:id|class|name)=["\']?[^"\']*submit[^"\']*["\']?[^>]*>',
            r'<input[^>]*(?:id|class|name)=["\']?[^"\']*login[^"\']*["\']?[^>]*type=["\']submit',
        ]
        for sp in submit_patterns:
            match = re.search(sp, html, re.IGNORECASE)
            if match:
                submit_tag = match.group(0)
                submit_id = self._extract_attr(submit_tag, "id")
                submit_class = self._extract_attr(submit_tag, "class")
                if submit_id:
                    info.submit_selector = f"#{submit_id}"
                elif submit_class:
                    info.submit_selector = f".{submit_class.split()[0]}"
                break

        # Extract JS auth logic
        info.js_auth_logic = str(self.extract_js_auth_patterns(html))[:500]

        return info

    def _analyze_token_mechanism(self, html: str, result) -> TokenInfo:
        """Analyze how tokens are used in the authentication flow."""
        info = TokenInfo()

        # Check cookies for session tokens
        cookies = result.cookies
        if cookies:
            info.cookie_names = list(cookies.keys())
            info.mechanism = "cookie"

        # Check for URL token patterns (like LuCI stok)
        url_token_patterns = re.findall(r';(\w+)=([A-Za-z0-9]+)', result.final_url)
        if url_token_patterns:
            info.mechanism = "url_path"
            info.url_token_pattern = f";{url_token_patterns[0][0]}={{token}}"

        # Check JS for token references
        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        for js in js_blocks:
            token_refs = re.findall(r'(?:token|stok|session_id|auth_code)\s*[:=]', js, re.IGNORECASE)
            if token_refs:
                info.js_token_refs.extend(token_refs[:5])

            # Check for redirect-based token passing
            redirect_patterns = re.findall(r'location\s*[.=]\s*["\']([^"\']*(?:token|stok)[^"\']*)["\']', js, re.IGNORECASE)
            if redirect_patterns:
                info.redirect_pattern = redirect_patterns[0]

        # Check for URL-embedded token patterns
        if re.search(r';stok=', html):
            info.mechanism = "url_path"
            info.url_token_pattern = ";stok={token}"

        return info

    @staticmethod
    def _extract_attr(tag: str, attr: str) -> str:
        """Extract attribute value from HTML tag."""
        match = re.search(rf'{attr}=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        return match.group(1) if match else ""
