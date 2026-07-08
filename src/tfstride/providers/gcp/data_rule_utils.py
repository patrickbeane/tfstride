from __future__ import annotations

import re

_GCP_DURATION_SECONDS = re.compile(r"^\s*(\d+(?:\.\d+)?)s\s*$")


def gcp_duration_seconds(value: str | None) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    match = _GCP_DURATION_SECONDS.match(value)
    if not match:
        return None
    seconds = float(match.group(1))
    return int(seconds) if seconds.is_integer() else int(seconds) + 1
