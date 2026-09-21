from enum import Enum

from pydantic import BaseModel, Field


class FileRole(str, Enum):
    WEB_SERVER = "web_server"
    CGI_HANDLER = "cgi_handler"
    FRONTEND = "frontend"
    SCRIPT = "script"
    CONFIG = "config"


class BinaryAnalysisResult(BaseModel):
    path: str
    name: str
    arch: str = "unknown"
    bits: int = 0
    endian: str = "unknown"
    stripped: bool = True
    auth_strings: list[str] = Field(default_factory=list)
    auth_functions: list[str] = Field(default_factory=list)
    key_imports: list[str] = Field(default_factory=list)
    auth_decompilation: str = ""


class BinaryInfo(BaseModel):
    path: str
    name: str
    role: FileRole
    arch: str = "unknown"
    analysis: BinaryAnalysisResult | None = None


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    source_file: str = ""
    tags: list[str] = Field(default_factory=list)
    hints: dict[str, str] = Field(default_factory=dict)


class ConfigSource(BaseModel):
    path: str
    source_type: str
    keys: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class FrontendAsset(BaseModel):
    path: str
    kind: str


class SurfaceSnapshot(BaseModel):
    web_binaries: list[BinaryInfo] = Field(default_factory=list)
    cgi_binaries: list[BinaryInfo] = Field(default_factory=list)
    frontend_assets: list[FrontendAsset] = Field(default_factory=list)
    config_sources: list[ConfigSource] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    candidate_files: list[str] = Field(default_factory=list)
    test_targets: list = Field(default_factory=list)
    runtime_state_evidence: list = Field(default_factory=list)
