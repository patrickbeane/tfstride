from __future__ import annotations

import unittest

from tests.helpers.paths import FIXTURES_DIR
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import TerraformResource

FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_plan.json"


def _fixture_resources_by_address():
    return {resource.address: resource for resource in load_terraform_plan(FIXTURE_PATH).resources}


def _terraform_resource(
    address: str,
    resource_type: str,
    values: dict[str, object],
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


class GcpNormalizerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.resources = _fixture_resources_by_address()
