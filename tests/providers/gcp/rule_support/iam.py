from __future__ import annotations

from tfstride.models import TerraformResource


def _service_account() -> TerraformResource:
    email = "tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
    return TerraformResource(
        address="google_service_account.deploy",
        mode="managed",
        resource_type="google_service_account",
        name="deploy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "account_id": "tfstride-deploy",
            "email": email,
            "name": f"projects/tfstride-demo/serviceAccounts/{email}",
            "project": "tfstride-demo",
        },
    )


def _service_account_key(
    *,
    valid_after: str = "2026-01-01T00:00:00Z",
    valid_before: str = "2027-01-01T00:00:00Z",
    keepers: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_service_account_key.deploy",
        mode="managed",
        resource_type="google_service_account_key",
        name="deploy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "projects/tfstride-demo/serviceAccounts/tfstride-deploy@tfstride-demo.iam.gserviceaccount.com/keys/key-id",
            "service_account_id": "google_service_account.deploy.name",
            "key_algorithm": "KEY_ALG_RSA_2048",
            "public_key_type": "TYPE_X509_PEM_FILE",
            "valid_after": valid_after,
            "valid_before": valid_before,
            "keepers": keepers or {},
            "private_key": "redacted-test-secret-material",
        },
    )


def _service_account_iam_member(
    role: str = "roles/iam.serviceAccountTokenCreator",
    member: str = "group:deploy@example.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_service_account_iam_member.deploy_token_creator",
        mode="managed",
        resource_type="google_service_account_iam_member",
        name="deploy_token_creator",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "service_account_id": "google_service_account.deploy.name",
            "role": role,
            "member": member,
        },
    )


def _service_account_iam_binding(
    role: str = "roles/iam.serviceAccountUser",
    members: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_service_account_iam_binding.deploy_users",
        mode="managed",
        resource_type="google_service_account_iam_binding",
        name="deploy_users",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "service_account_id": "google_service_account.deploy.name",
            "role": role,
            "members": members or ["allUsers"],
        },
    )


def _service_account_iam_policy(bindings: list[dict[str, object]]) -> TerraformResource:
    return TerraformResource(
        address="google_service_account_iam_policy.deploy_policy",
        mode="managed",
        resource_type="google_service_account_iam_policy",
        name="deploy_policy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "service_account_id": "google_service_account.deploy.name",
            "policy_data": {"bindings": bindings},
        },
    )


def _project_iam_member(
    role: str, member: str = "serviceAccount:deploy@example.iam.gserviceaccount.com"
) -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_member.binding",
        mode="managed",
        resource_type="google_project_iam_member",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role": role,
            "member": member,
        },
    )


def _project_iam_binding(
    role: str,
    members: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_binding.binding",
        mode="managed",
        resource_type="google_project_iam_binding",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role": role,
            "members": members or ["serviceAccount:deploy@example.iam.gserviceaccount.com"],
        },
    )


def _project_iam_policy(bindings: list[dict[str, object]]) -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_policy.policy",
        mode="managed",
        resource_type="google_project_iam_policy",
        name="policy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "policy_data": {"bindings": bindings},
        },
    )


def _organization_iam_member(
    role: str,
    member: str = "group:platform-admins@example.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_organization_iam_member.binding",
        mode="managed",
        resource_type="google_organization_iam_member",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"org_id": "1234567890", "role": role, "member": member},
    )


def _organization_iam_binding(
    role: str,
    members: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_organization_iam_binding.binding",
        mode="managed",
        resource_type="google_organization_iam_binding",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "org_id": "1234567890",
            "role": role,
            "members": members or ["group:platform-admins@example.com"],
        },
    )


def _organization_iam_policy(bindings: list[dict[str, object]]) -> TerraformResource:
    return TerraformResource(
        address="google_organization_iam_policy.policy",
        mode="managed",
        resource_type="google_organization_iam_policy",
        name="policy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"org_id": "1234567890", "policy_data": {"bindings": bindings}},
    )


def _folder_iam_member(
    role: str,
    member: str = "group:folder-admins@example.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_folder_iam_member.binding",
        mode="managed",
        resource_type="google_folder_iam_member",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"folder": "folders/12345", "role": role, "member": member},
    )


def _organization_iam_custom_role(
    role_id: str = "orgAdmin",
    permissions: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_organization_iam_custom_role.custom",
        mode="managed",
        resource_type="google_organization_iam_custom_role",
        name="custom",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "org_id": "1234567890",
            "role_id": role_id,
            "title": "Org Custom Role",
            "permissions": permissions or ["resourcemanager.projects.setIamPolicy"],
            "stage": "GA",
        },
    )


def _project_iam_custom_role(
    role_id: str = "deployAdmin",
    permissions: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_custom_role.custom",
        mode="managed",
        resource_type="google_project_iam_custom_role",
        name="custom",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role_id": role_id,
            "title": "Custom Role",
            "permissions": permissions or ["iam.serviceAccounts.actAs"],
            "stage": "GA",
        },
    )
