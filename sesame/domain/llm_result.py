from pydantic import BaseModel, Field


class AuthArchitecture(BaseModel):
    auth_type: str = ""
    login_url: str = ""
    login_method: str = "POST"
    login_content_type: str = "form"
    login_params: dict[str, str] = Field(default_factory=dict)
    session_mechanism: str = ""
    session_cookie_name: str = ""
    credential_storage: str = ""
    credential_defaults: list[dict[str, str]] = Field(default_factory=list)
    post_login_redirect: str = ""
    auth_gate_pattern: str = ""
    api_dispatch_mechanism: str = ""
    key_observations: list[str] = Field(default_factory=list)
    # --- Agent-discovered fields ---
    token_location: str = "cookie"  # "cookie" | "url_path" | "header"
    token_response_path: str = ""  # JSON path in login response, e.g. "$.token"
    url_token_pattern: str = ""  # e.g. ";stok={token}"
    crypto_details: str = ""  # e.g. "sha1(sha1(pwd+key)+nonce)"
    recovery_shell_commands: list[str] = Field(default_factory=list)
    login_curl: str = ""  # Ready-to-use curl command for login


class LLMMismatchItem(BaseModel):
    layer: str = ""
    title: str = ""
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    recovery_relevance: str = ""


class RecoveryStep(BaseModel):
    step: int = 0
    step_type: str = "http"
    url: str = ""
    method: str = "POST"
    content_type: str = "form"
    body: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    command: str = ""
    follow_redirect: bool = False
    extract_token: str = ""  # JSON path to extract token from response, e.g. "$.token"
    success_indicators: list[str] = Field(default_factory=list)
    failure_indicators: list[str] = Field(default_factory=list)
    description: str = ""


class BypassPlan(BaseModel):
    """Concrete bypass plan with shell commands for manual execution."""
    bypass_strategy: str = ""
    description: str = ""
    vm_commands: list[str] = Field(default_factory=list, description="Commands to run inside QEMU VM shell")
    host_commands: list[str] = Field(default_factory=list, description="Commands to run on attacker host (curl, browser, etc.)")
    credentials_to_try: list[dict[str, str]] = Field(default_factory=list)
    expected_session: dict[str, str] = Field(default_factory=dict)
    fallback_strategies: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class RecoveryPlan(BaseModel):
    strategy: str = ""
    steps: list[RecoveryStep] = Field(default_factory=list)
    expected_cookies: list[str] = Field(default_factory=list)
    fallback_credentials: list[dict[str, str]] = Field(default_factory=list)
    recovery_technique: str = ""  # "HTTP" | "Browser"
