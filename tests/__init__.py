from __future__ import annotations

import sys

from tests.helpers.paths import SRC_ROOT

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
