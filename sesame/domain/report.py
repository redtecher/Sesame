from enum import Enum

from pydantic import BaseModel, Field

from sesame.domain.primitives import PrimitivePlan


class EntryPoint(BaseModel):
    url: str
    method: str
    handler: str = ""
    source: str = ""


class StateDependency(BaseModel):
    name: str
    storage_type: str
    location: str
    format: str = "unknown"
    producer: str = ""
    consumer: str = ""
    evidence: list[str] = Field(default_factory=list)


class SemanticFinding(BaseModel):
    entry_points: list[EntryPoint] = Field(default_factory=list)
    auth_flow_summary: str = ""
    state_dependencies: list[StateDependency] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    context_blocks: list[str] = Field(default_factory=list)


class DiagnosisHypothesis(BaseModel):
    title: str
    mismatch_layer: str
    primitives: list[PrimitivePlan] = Field(default_factory=list)
    rationale: str
    evidence: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class VerificationTrace(BaseModel):
    method: str
    target: str
    observation: str
    confirms: list[str] = Field(default_factory=list)


class RuntimeStateEvidence(BaseModel):
    source: str
    command: str
    observation: str
    confidence: float = 0.0


class TestEnablementReport(BaseModel):
    summary: str
    semantics: SemanticFinding
    hypotheses: list[DiagnosisHypothesis] = Field(default_factory=list)
    traces: list[VerificationTrace] = Field(default_factory=list)
    runtime_state_evidence: list[RuntimeStateEvidence] = Field(default_factory=list)


class ReachabilityLevel(str, Enum):
    UNREACHABLE = "unreachable"
    LOGIN_PAGE = "login_page"
    POST_AUTH_PAGE = "post_auth_page"
    API_READY = "api_ready"
    FUZZ_READY = "fuzz_ready"


class TestTarget(BaseModel):
    target_id: str
    url: str
    method: str = "GET"
    target_type: str = "page"
    reachability: ReachabilityLevel = ReachabilityLevel.UNREACHABLE
    blockers: list[str] = Field(default_factory=list)
    source_file: str = ""
    tags: list[str] = Field(default_factory=list)
    request_chain: list[str] = Field(default_factory=list)
    request_template: dict[str, str] = Field(default_factory=dict)


class FuzzArtifact(BaseModel):
    target_url: str
    request_template: dict[str, str] = Field(default_factory=dict)
    state_prerequisites: list[str] = Field(default_factory=list)
    seed_cookies: dict[str, str] = Field(default_factory=dict)
    seed_headers: dict[str, str] = Field(default_factory=dict)
    seed_body: dict[str, str] = Field(default_factory=dict)
    request_chain: list[str] = Field(default_factory=list)
    seed_url_tokens: dict[str, str] = Field(default_factory=dict)
    url_token_pattern: str = ""


class StageMetrics(BaseModel):
    wall_time_s: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: dict[str, int] = Field(default_factory=dict)


class PipelineMetrics(BaseModel):
    total_wall_time_s: float = 0.0
    discovery: StageMetrics = Field(default_factory=StageMetrics)
    stage1_architecture: StageMetrics = Field(default_factory=StageMetrics)
    stage2_mismatch: StageMetrics = Field(default_factory=StageMetrics)
    stage3_recovery: StageMetrics = Field(default_factory=StageMetrics)
    verification: StageMetrics = Field(default_factory=StageMetrics)
    recovery_technique: str = ""  # "HTTP" | "Shell" | "GDB" | ""
    mismatch_distribution: dict[str, int] = Field(default_factory=dict)


class RehostingMetrics(BaseModel):
    reachable_services_before: int = 0
    reachable_services_after: int = 0
    reachable_pages_before: int = 0
    reachable_pages_after: int = 0
    post_auth_targets_before: int = 0
    post_auth_targets_after: int = 0
    fuzzable_targets_before: int = 0
    fuzzable_targets_after: int = 0


class BypassPlanOutput(BaseModel):
    """Bypass plan output for manual execution."""
    bypass_strategy: str = ""
    description: str = ""
    vm_commands: list[str] = Field(default_factory=list, description="Commands to run inside QEMU VM shell")
    host_commands: list[str] = Field(default_factory=list, description="Commands to run on attacker host (curl, browser)")
    credentials_to_try: list[dict[str, str]] = Field(default_factory=list)
    expected_session: dict[str, str] = Field(default_factory=dict)
    fallback_strategies: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class EnablementResult(BaseModel):
    report: TestEnablementReport
    targets: list[TestTarget] = Field(default_factory=list)
    artifacts: list[FuzzArtifact] = Field(default_factory=list)
    metrics: RehostingMetrics
    pipeline_metrics: PipelineMetrics = Field(default_factory=PipelineMetrics)
    bypass_plan: BypassPlanOutput = Field(default_factory=BypassPlanOutput)
