"""Snapshot the exact GCP Pub/Sub path output on a scaled mixed-authority plan.

The three Cloud Run Pub/Sub stages join workloads to topics and subscriptions
through IAM grants of very different shapes. This test records, per workload, the
exact paths (in order, with a digest of each full path) and the exact uncertainty
messages the stages produce, so a change to how those joins are computed must
reproduce today's output exactly. Regenerate the snapshot only for a deliberate
behavior change:

    python -m tests.providers.gcp.test_gcp_pubsub_path_snapshot --write
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any

from tests.helpers.gcp_pubsub_plan import build_pubsub_plan, describe_plan
from tfstride.models import ResourceInventory
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

SNAPSHOT_PATH = Path(__file__).resolve().parents[2] / "golden" / "gcp_pubsub_paths_snapshot.json"
SNAPSHOT_SCALE = 12
_STAGES = ("access", "message_removal", "topology_destruction")
_PATH_KEY_FIELDS = (
    "operation",
    "messaging_resource_address",
    "iam_resource_address",
    "role",
    "scope_type",
    "scope",
)


def _digest(path: dict[str, Any]) -> str:
    canonical = json.dumps(path, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _stage_output(inventory: ResourceInventory, workload_address: str, stage: str) -> dict[str, Any]:
    workload = inventory.get_by_address(workload_address)
    assert workload is not None
    facts = gcp_facts(workload)
    paths = list(getattr(facts, f"cloud_run_pubsub_{stage}_paths"))
    uncertainties = list(getattr(facts, f"cloud_run_pubsub_{stage}_path_uncertainties"))
    return {
        "paths": [
            {
                "key": [path.get(field) for field in _PATH_KEY_FIELDS],
                "sha256": _digest(dict(path)),
            }
            for path in paths
        ],
        "uncertainties": uncertainties,
    }


def build_snapshot(scale: int = SNAPSHOT_SCALE) -> dict[str, Any]:
    inventory = GcpNormalizer().normalize(build_pubsub_plan(scale))
    return {
        "scale": scale,
        "workloads": {
            f"google_cloud_run_v2_service.w{index}": {
                stage: _stage_output(inventory, f"google_cloud_run_v2_service.w{index}", stage) for stage in _STAGES
            }
            for index in range(scale)
        },
    }


def _render(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=1, sort_keys=True) + "\n"


class GcpPubsubPathSnapshotTests(unittest.TestCase):
    def test_plan_generator_is_deterministic(self) -> None:
        self.assertEqual(
            describe_plan(build_pubsub_plan(SNAPSHOT_SCALE)), describe_plan(build_pubsub_plan(SNAPSHOT_SCALE))
        )

    def test_snapshot_plan_exercises_every_authority_shape(self) -> None:
        snapshot = build_snapshot()
        totals = {
            stage: (
                sum(len(entry[stage]["paths"]) for entry in snapshot["workloads"].values()),
                [message for entry in snapshot["workloads"].values() for message in entry[stage]["uncertainties"]],
            )
            for stage in _STAGES
        }
        for stage in _STAGES:
            self.assertGreater(totals[stage][0], 0, stage)
        joined = "\n".join(message for _stage, (_count, messages) in totals.items() for message in messages)
        self.assertIn("is ambiguous because authoritative", joined)
        self.assertIn("condition", joined)
        self.assertIn("unresolved", joined)
        self.assertIn("policy_data is unknown", joined)
        self.assertIn("role or members are unresolved", joined)
        roles = {
            key[3]
            for entry in snapshot["workloads"].values()
            for stage in _STAGES
            for key in (path["key"] for path in entry[stage]["paths"])
        }
        self.assertIn("roles/pubsub.admin", roles)
        self.assertIn("roles/pubsub.editor", roles)
        self.assertIn("projects/tfstride-demo/roles/pubsubOperator", roles)
        scope_types = {
            key[4]
            for entry in snapshot["workloads"].values()
            for stage in _STAGES
            for key in (path["key"] for path in entry[stage]["paths"])
        }
        self.assertIn("project", scope_types)

    def test_stage_output_matches_the_recorded_snapshot(self) -> None:
        recorded = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(build_snapshot(recorded["scale"]), recorded)


if __name__ == "__main__":
    if "--write" in sys.argv:
        SNAPSHOT_PATH.write_text(_render(build_snapshot()), encoding="utf-8")
        print(f"wrote {SNAPSHOT_PATH}")
    else:
        unittest.main()
