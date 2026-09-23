from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypedDict

AwsAccountResolutionState = Literal["resolved", "unknown", "ambiguous", "invalid"]


class AwsAccountArnInput(TypedDict):
    field: str
    value: str | None
    state: Literal["known", "unknown", "invalid"]


@dataclass(frozen=True, slots=True)
class AwsAccountResolution:
    account_id: str | None
    state: AwsAccountResolutionState
    evidence: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()
    partition: str | None = None
