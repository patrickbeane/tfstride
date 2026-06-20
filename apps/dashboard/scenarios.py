from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from fastapi import FastAPI

from tfstride.app import TfStride
from tfstride.input.terraform_plan import TerraformPlanLoadError

APP_ROOT = Path(__file__).resolve().parent
REPO_ROOT = APP_ROOT.parents[1]
FIXTURES_DIR = REPO_ROOT / "fixtures"


@dataclass(frozen=True, slots=True)
class DemoScenarioDefinition:
    scenario_id: str
    title: str
    report_title: str
    fixture_name: str
    description: str
    emphasis: str
    theme: str


@dataclass(frozen=True, slots=True)
class DemoScenario:
    scenario_id: str
    title: str
    report_title: str
    provider: str
    fixture_name: str
    fixture_path: str
    description: str
    emphasis: str
    theme: str
    normalized_resources: int
    trust_boundaries: int
    active_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int


DEMO_SCENARIO_DEFINITIONS = (
    DemoScenarioDefinition(
        scenario_id="safe",
        title="Safe Plan",
        report_title="Safe Plan Demo",
        fixture_name="aws/sample_aws_safe_plan.json",
        description="Private-by-default AWS infrastructure with guarded storage, private database access, and no active findings.",
        emphasis="Quiet reference architecture",
        theme="safe",
    ),
    DemoScenarioDefinition(
        scenario_id="baseline",
        title="Baseline Plan",
        report_title="Baseline Plan Demo",
        fixture_name="aws/sample_aws_baseline_plan.json",
        description="Mostly segmented AWS infrastructure with a small IAM hygiene issue and a non-obvious private-data path.",
        emphasis="Calibrated baseline",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="mixed",
        title="Mixed AWS Plan",
        report_title="Mixed AWS Plan Demo",
        fixture_name="aws/sample_aws_plan.json",
        description="Public exposure, permissive database access, risky IAM, and broad trust in one reviewable plan.",
        emphasis="Representative mixed case",
        theme="mixed",
    ),
    DemoScenarioDefinition(
        scenario_id="nightmare",
        title="Nightmare Plan",
        report_title="Nightmare Plan Demo",
        fixture_name="aws/sample_aws_nightmare_plan.json",
        description="Stacked public access, wildcard IAM, exposed storage, and high blast radius across the stack.",
        emphasis="Stress-case fixture",
        theme="nightmare",
    ),
    DemoScenarioDefinition(
        scenario_id="alb-ec2-rds",
        title="ALB, EC2, and RDS",
        report_title="ALB / EC2 / RDS Demo",
        fixture_name="aws/sample_aws_alb_ec2_rds_plan.json",
        description="A common web architecture where an internet-facing load balancer still composes into a private RDS access path.",
        emphasis="Common architecture",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="ecs-fargate",
        title="ECS / Fargate",
        report_title="ECS / Fargate Demo",
        fixture_name="aws/sample_aws_ecs_fargate_plan.json",
        description="Internet-facing ALB, private ECS tasks, RDS security-group trust, and Secrets Manager access through the task role.",
        emphasis="Container workload",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="lambda-deploy-role",
        title="Lambda Deploy Role",
        report_title="Lambda Deploy Role Demo",
        fixture_name="aws/sample_aws_lambda_deploy_role_plan.json",
        description="Private Lambda deployment path with scoped S3 access and deliberate trust-chain review points.",
        emphasis="Control-plane focus",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="gcp-safe",
        title="Safe GCP Plan",
        report_title="Safe GCP Plan Demo",
        fixture_name="gcp/sample_gcp_safe_plan.json",
        description="Private-by-default GCP reference with hardened storage, private Cloud SQL, scoped identity, Secret Manager, and Cloud KMS.",
        emphasis="Quiet reference architecture",
        theme="safe",
    ),
    DemoScenarioDefinition(
        scenario_id="gcp-baseline",
        title="Baseline GCP Plan",
        report_title="Baseline GCP Plan Demo",
        fixture_name="gcp/sample_gcp_baseline_plan.json",
        description="Mostly segmented GCP infrastructure with custom-role IAM risk and a focused Cloud SQL recovery finding.",
        emphasis="Calibrated baseline",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="gcp-lb-compute-sql",
        title="GCP Load Balancer and SQL",
        report_title="GCP Load Balancer / Compute / SQL Demo",
        fixture_name="gcp/sample_gcp_lb_compute_sql_plan.json",
        description="External load-balancing edge, private compute, NAT egress posture, and private Cloud SQL in a common GCP web shape.",
        emphasis="Common architecture",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="gcp-serverless",
        title="GCP Serverless",
        report_title="GCP Serverless Demo",
        fixture_name="gcp/sample_gcp_serverless_plan.json",
        description="Cloud Run and Cloud Functions public invoker paths with service-account access into Secret Manager.",
        emphasis="Serverless workload",
        theme="mixed",
    ),
    DemoScenarioDefinition(
        scenario_id="gcp-cross-project-iam",
        title="GCP Cross-Project IAM",
        report_title="GCP Cross-Project IAM Demo",
        fixture_name="gcp/sample_gcp_cross_project_iam_plan.json",
        description="Focused IAM blast-radius fixture for project-level grants, Secret Manager access, and Cloud KMS decryption trust.",
        emphasis="Trust expansion",
        theme="trust",
    ),
    DemoScenarioDefinition(
        scenario_id="gcp-scaffold",
        title="Mixed GCP Inventory",
        report_title="GCP Inventory Demo",
        fixture_name="gcp/sample_gcp_plan.json",
        description="Mixed Google provider inventory covering compute, network, IAM, Pub/Sub, BigQuery, Cloud SQL, Secret Manager, Cloud KMS, and GCS.",
        emphasis="Provider expansion",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="gcp-nightmare",
        title="GCP Nightmare Plan",
        report_title="GCP Nightmare Plan Demo",
        fixture_name="gcp/sample_gcp_nightmare_plan.json",
        description="Stacked GCP risk across compute, GKE, serverless, data services, org/folder/project IAM, and unsupported-resource coverage.",
        emphasis="Stress-case fixture",
        theme="nightmare",
    ),
    DemoScenarioDefinition(
        scenario_id="trust-unconstrained",
        title="Cross-Account Trust",
        report_title="Cross-Account Trust Demo",
        fixture_name="aws/sample_aws_cross_account_trust_unconstrained_plan.json",
        description="Minimal assume-role trust without narrowing conditions to exercise the IAM trust path directly.",
        emphasis="Trust expansion",
        theme="trust",
    ),
    DemoScenarioDefinition(
        scenario_id="trust-constrained",
        title="Constrained Trust",
        report_title="Constrained Trust Demo",
        fixture_name="aws/sample_aws_cross_account_trust_constrained_plan.json",
        description="The same trust edge narrowed by ExternalId, SourceArn, and SourceAccount conditions.",
        emphasis="Narrowed trust",
        theme="safe",
    ),
)
KNOWN_DEMO_SCENARIO_IDS = ", ".join(definition.scenario_id for definition in DEMO_SCENARIO_DEFINITIONS)


def build_demo_scenarios(engine: TfStride, *, fixtures_dir: Path = FIXTURES_DIR) -> tuple[DemoScenario, ...]:
    scenarios: list[DemoScenario] = []
    for definition in DEMO_SCENARIO_DEFINITIONS:
        fixture_path = fixtures_dir / definition.fixture_name
        if not fixture_path.is_file():
            continue
        try:
            result = engine.analyze_plan(fixture_path, title=definition.report_title)
        except TerraformPlanLoadError:
            continue
        severity_counts = Counter(finding.severity.value for finding in result.findings)
        scenarios.append(
            DemoScenario(
                scenario_id=definition.scenario_id,
                title=definition.title,
                report_title=definition.report_title,
                provider=definition.fixture_name.split("/", 1)[0],
                fixture_name=definition.fixture_name,
                fixture_path=str(fixture_path),
                description=definition.description,
                emphasis=definition.emphasis,
                theme=definition.theme,
                normalized_resources=len(result.inventory.resources),
                trust_boundaries=len(result.trust_boundaries),
                active_findings=len(result.findings),
                high_findings=severity_counts["high"],
                medium_findings=severity_counts["medium"],
                low_findings=severity_counts["low"],
            )
        )
    return tuple(scenarios)


def get_demo_scenarios(app: FastAPI, engine: TfStride) -> tuple[DemoScenario, ...]:
    cached = getattr(app.state, "demo_scenarios", None)
    if cached is None:
        cached = build_demo_scenarios(engine)
        app.state.demo_scenarios = cached
    return cast(tuple[DemoScenario, ...], cached)


def get_demo_scenarios_by_id(app: FastAPI, engine: TfStride) -> dict[str, DemoScenario]:
    cached = getattr(app.state, "demo_scenarios_by_id", None)
    if cached is None:
        cached = {scenario.scenario_id: scenario for scenario in get_demo_scenarios(app, engine)}
        app.state.demo_scenarios_by_id = cached
    return cast(dict[str, DemoScenario], cached)
