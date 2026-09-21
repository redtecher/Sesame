from enum import Enum

from pydantic import BaseModel, Field


class MismatchLayer(str, Enum):
    SOURCE = "source_mismatch"
    REPRESENTATION = "representation_mismatch"
    TRANSFER = "transfer_mismatch"
    CONSUMPTION = "consumption_mismatch"


class MismatchFinding(BaseModel):
    layer: MismatchLayer
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0

