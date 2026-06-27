from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers.paths import FIXTURES_DIR
from tfstride.app import TfStride

BASELINE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_baseline_plan.json"
FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_nightmare_plan.json"
ALB_EC2_RDS_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_alb_ec2_rds_plan.json"
ECS_FARGATE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_ecs_fargate_plan.json"
LAMBDA_DEPLOY_ROLE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_lambda_deploy_role_plan.json"
GCP_FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_plan.json"
GCP_SAFE_FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_safe_plan.json"
GCP_BASELINE_FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_baseline_plan.json"
GCP_LB_COMPUTE_SQL_FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_lb_compute_sql_plan.json"
GCP_SERVERLESS_FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_serverless_plan.json"
GCP_CROSS_PROJECT_IAM_FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_cross_project_iam_plan.json"
GCP_NIGHTMARE_FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_nightmare_plan.json"
AZURE_SAFE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_safe_plan.json"
AZURE_STORAGE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_storage_plan.json"
AZURE_STORAGE_UNKNOWN_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_storage_unknown_plan.json"
AZURE_KEY_VAULT_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_key_vault_plan.json"
AZURE_IDENTITY_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_identity_plan.json"
AZURE_COMPUTE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_compute_plan.json"
AZURE_NSG_PRECEDENCE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_nsg_precedence_plan.json"
AZURE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_plan.json"
AZURE_NIGHTMARE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_nightmare_plan.json"
CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH = (
    FIXTURES_DIR / "aws" / "sample_aws_cross_account_trust_unconstrained_plan.json"
)
CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH = (
    FIXTURES_DIR / "aws" / "sample_aws_cross_account_trust_constrained_plan.json"
)


class TFSIntegrationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = TfStride()
        self.result = self.engine.analyze_plan(FIXTURE_PATH)

    def _analyze_payload(self, payload: dict) -> object:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            return self.engine.analyze_plan(plan_path)
