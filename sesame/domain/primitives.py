from enum import Enum

from pydantic import BaseModel, Field


class SolutionPrimitive(str, Enum):
    RECOVER_SOURCE = "recover_source"
    NORMALIZE_REPRESENTATION = "normalize_representation"
    TRACE_TRANSFER = "trace_transfer"
    EXPLAIN_CONSUMPTION = "explain_consumption"
    COLLECT_RUNTIME_EVIDENCE = "collect_runtime_evidence"


class PrimitivePlan(BaseModel):
    primitive: SolutionPrimitive
    goal: str
    required_inputs: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)


class SolutionPlan(BaseModel):
    mismatch_layers: list[str] = Field(default_factory=list)
    primitives: list[PrimitivePlan] = Field(default_factory=list)
    expected_outcomes: list[str] = Field(default_factory=list)

