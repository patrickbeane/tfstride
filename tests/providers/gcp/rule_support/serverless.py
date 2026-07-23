from __future__ import annotations

from tfstride.models import TerraformResource


def _cloud_run_service(
    *,
    public_ingress: bool = True,
    service_account_email: str = "tfstride-run@tfstride-demo.iam.gserviceaccount.com",
    secret_reference: str | None = None,
    invoker_iam_disabled: bool | None = None,
) -> TerraformResource:
    template: dict[str, object] = {"service_account": service_account_email}
    if secret_reference is not None:
        template["containers"] = [
            {
                "name": "api",
                "env": [
                    {
                        "name": "DB_PASSWORD",
                        "value_source": [
                            {
                                "secret_key_ref": [
                                    {
                                        "secret": secret_reference,
                                        "version": "5",
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ]
    return TerraformResource(
        address="google_cloud_run_v2_service.api",
        mode="managed",
        resource_type="google_cloud_run_v2_service",
        name="api",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-api",
            "project": "tfstride-demo",
            "location": "us-central1",
            "ingress": "INGRESS_TRAFFIC_ALL" if public_ingress else "INGRESS_TRAFFIC_INTERNAL_ONLY",
            "template": [template],
            **({"invoker_iam_disabled": invoker_iam_disabled} if invoker_iam_disabled is not None else {}),
        },
    )


def _cloud_run_service_iam_member(
    member: str = "allUsers",
    role: str = "roles/run.invoker",
    condition: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_cloud_run_v2_service_iam_member.public_invoker",
        mode="managed",
        resource_type="google_cloud_run_v2_service_iam_member",
        name="public_invoker",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-api",
            "location": "us-central1",
            "role": role,
            "member": member,
            **({"condition": [condition]} if condition else {}),
        },
    )


def _cloudfunctions_function(
    *,
    public: bool = True,
    service_account_email: str = "tfstride-fn@tfstride-demo.iam.gserviceaccount.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_cloudfunctions_function.fn",
        mode="managed",
        resource_type="google_cloudfunctions_function",
        name="fn",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-fn",
            "project": "tfstride-demo",
            "region": "us-central1",
            "runtime": "python312",
            "trigger_http": public,
            "service_account_email": service_account_email,
        },
    )


def _cloudfunctions_function_iam_member(
    member: str = "allUsers",
    role: str = "roles/cloudfunctions.invoker",
) -> TerraformResource:
    return TerraformResource(
        address="google_cloudfunctions_function_iam_member.public_invoker",
        mode="managed",
        resource_type="google_cloudfunctions_function_iam_member",
        name="public_invoker",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "cloud_function": "tfstride-fn",
            "region": "us-central1",
            "role": role,
            "member": member,
        },
    )


def _cloudfunctions2_function(public: bool = True) -> TerraformResource:
    service_config: dict[str, object] = {
        "service_account_email": "tfstride-fn2@tfstride-demo.iam.gserviceaccount.com",
    }
    if public:
        service_config["uri"] = "https://tfstride-fn2-uc.a.run.app"
    return TerraformResource(
        address="google_cloudfunctions2_function.fn2",
        mode="managed",
        resource_type="google_cloudfunctions2_function",
        name="fn2",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-fn2",
            "project": "tfstride-demo",
            "location": "us-central1",
            "service_config": [service_config],
        },
    )


def _cloudfunctions2_function_iam_binding(
    members: list[str] | None = None,
    role: str = "roles/cloudfunctions.invoker",
) -> TerraformResource:
    return TerraformResource(
        address="google_cloudfunctions2_function_iam_binding.public_invokers",
        mode="managed",
        resource_type="google_cloudfunctions2_function_iam_binding",
        name="public_invokers",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "cloud_function": "tfstride-fn2",
            "location": "us-central1",
            "role": role,
            "members": members or ["allAuthenticatedUsers"],
        },
    )
