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


@dataclass(frozen=True, slots=True)
class AwsAccountRelationship:
    source: AwsAccountResolution
    target: AwsAccountResolution

    @property
    def partitions_match(self) -> bool:
        return bool(self.source.partition and self.target.partition and self.source.partition == self.target.partition)

    @property
    def same_account(self) -> bool | None:
        if (
            self.source.state != "resolved"
            or self.target.state != "resolved"
            or self.source.account_id is None
            or self.target.account_id is None
            or self.source.partition is None
            or self.target.partition is None
        ):
            return None
        return self.source.account_id == self.target.account_id and self.partitions_match
