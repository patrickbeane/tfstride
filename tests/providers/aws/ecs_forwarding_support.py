from __future__ import annotations

from typing import Any

from tfstride.models import TerraformResource

TARGET_GROUP_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/orders/def"


def forwarding_action(reference: str | None, field: str = "default_action") -> dict[str, Any]:
    return {
        "type": "forward",
        "order": None,
        "uncertainties": [],
        "targets": [
            {"reference": reference, "weight": 1, "configuration_path": [field, 0, "target_group_arn"]},
        ],
    }


def load_balancer_path(*, internal: bool = False) -> list[TerraformResource]:
    """An explicit ALB listener/target-group fixture for workload authorization tests."""
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/public/abc"
    values_by_type = {
        "aws_lb": {
            "name": "public",
            "arn": load_balancer_arn,
            "internal": internal,
            "load_balancer_type": "application",
            "security_groups": ["aws_security_group.public_alb"],
        },
        "aws_lb_target_group": {
            "name": "public",
            "arn": TARGET_GROUP_ARN,
            "port": 8080,
            "protocol": "HTTP",
            "target_type": "ip",
        },
        "aws_lb_listener": {
            "load_balancer_arn": load_balancer_arn,
            "port": 443,
            "protocol": "HTTPS",
            "default_action": [{"type": "forward", "target_group_arn": TARGET_GROUP_ARN}],
        },
    }
    resources = [
        TerraformResource(
            address=f"{kind}.public",
            resource_type=kind,
            name="public",
            mode="managed",
            provider_name="registry.terraform.io/hashicorp/aws",
            provider_config_key="aws",
            values=values,
        )
        for kind, values in values_by_type.items()
    ]
    for name, values in {
        "public_alb": {
            "ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}],
            "egress": [
                {
                    "protocol": "tcp",
                    "from_port": 8080,
                    "to_port": 8080,
                    "security_groups": ["aws_security_group.public_tasks"],
                }
            ],
        },
        "public_tasks": {
            "ingress": [
                {
                    "protocol": "tcp",
                    "from_port": 8080,
                    "to_port": 8080,
                    "security_groups": ["aws_security_group.public_alb"],
                }
            ],
            "egress": [],
        },
    }.items():
        resources.append(
            TerraformResource(
                address=f"aws_security_group.{name}",
                resource_type="aws_security_group",
                name=name,
                mode="managed",
                provider_name="registry.terraform.io/hashicorp/aws",
                provider_config_key="aws",
                values={"id": f"sg-{name}", **values},
            )
        )
    return resources
