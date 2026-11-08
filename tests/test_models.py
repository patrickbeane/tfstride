from __future__ import annotations

import unittest
from dataclasses import fields, replace
from functools import partial
from inspect import Parameter, signature
from types import MappingProxyType

from tfstride.models import (
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    Severity,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
)
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.resource_metadata import InventoryMetadata, ResourceMetadata


def _resource(
    *,
    address: str,
    resource_type: str,
    category: ResourceCategory = ResourceCategory.COMPUTE,
    identifier: str | None = None,
    arn: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
    )


class _RaisesOnDeepcopy:
    def __deepcopy__(self, _memo: object) -> object:
        raise AssertionError("runtime metadata reads should not deep copy")


_METADATA_MODEL_CONSTRUCTORS = (
    partial(
        NormalizedResource,
        address="aws_instance.web",
        provider="aws",
        resource_type="aws_instance",
        name="web",
        category=ResourceCategory.COMPUTE,
    ),
    partial(ResourceInventory, provider="aws", resources=()),
)


class SeverityTests(unittest.TestCase):
    def test_rank_orders_severities_for_threshold_comparison(self) -> None:
        self.assertLess(Severity.LOW.rank, Severity.MEDIUM.rank)
        self.assertLess(Severity.MEDIUM.rank, Severity.HIGH.rank)
        self.assertFalse(hasattr(Severity, "RANK_ORDER"))

    def test_sort_key_orders_highest_severity_first(self) -> None:
        severities = [Severity.LOW, Severity.HIGH, Severity.MEDIUM]

        self.assertEqual(
            sorted(severities, key=Severity.sort_key),
            [Severity.HIGH, Severity.MEDIUM, Severity.LOW],
        )


class ModelMetadataConstructionTests(unittest.TestCase):
    def test_constructor_parameters_match_stored_init_fields(self) -> None:
        for model in (NormalizedResource, ResourceInventory):
            with self.subTest(model=model.__name__):
                stored_init_fields = {field.name for field in fields(model) if field.init}
                constructor_fields = set(signature(model).parameters)
                # metadata is a constructor input, but InitVar excludes it from fields().
                constructor_fields.remove("metadata")

                self.assertEqual(constructor_fields, stored_init_fields)

    def test_metadata_constructor_parameter_defaults_to_none(self) -> None:
        for constructor in _METADATA_MODEL_CONSTRUCTORS:
            with self.subTest(model=constructor.func.__name__):
                parameter = signature(constructor.func).parameters["metadata"]

                self.assertIsNone(parameter.default)
                self.assertEqual(parameter.kind, Parameter.POSITIONAL_OR_KEYWORD)

    def test_omitted_none_and_empty_metadata_produce_independent_empty_mappings(self) -> None:
        for constructor in _METADATA_MODEL_CONSTRUCTORS:
            for arguments in ({}, {"metadata": None}, {"metadata": {}}):
                with self.subTest(model=constructor.func.__name__, arguments=arguments):
                    first = constructor(**arguments)
                    second = constructor(**arguments)

                    self.assertEqual(first.metadata, {})
                    self.assertEqual(first.metadata_snapshot(), {})
                    if isinstance(first, NormalizedResource):
                        first.public_access_reasons = ["public IP"]
                        self.assertEqual(first.metadata, {"public_access_reasons": ["public IP"]})
                    else:
                        first.primary_account_id = "111122223333"
                        self.assertEqual(first.metadata, {"primary_account_id": "111122223333"})
                    self.assertEqual(second.metadata, {})

    def test_metadata_property_cannot_be_reassigned_or_deleted(self) -> None:
        for constructor in _METADATA_MODEL_CONSTRUCTORS:
            with self.subTest(model=constructor.func.__name__):
                model = constructor(metadata={"review": {"reviewers": ["security"]}})

                with self.assertRaises(AttributeError):
                    model.metadata = {}
                with self.assertRaises(AttributeError):
                    del model.metadata
                self.assertEqual(model.metadata, {"review": {"reviewers": ["security"]}})

    def test_replace_inherits_current_metadata_with_independent_nested_values(self) -> None:
        for constructor in _METADATA_MODEL_CONSTRUCTORS:
            with self.subTest(model=constructor.func.__name__):
                original = constructor(metadata={"review": {"reviewers": ["security"]}})
                if isinstance(original, NormalizedResource):
                    original.public_access_reasons = ["public IP"]
                else:
                    original.primary_account_id = "111122223333"

                replacement = replace(original)

                self.assertIsNot(replacement, original)
                self.assertEqual(replacement.metadata, original.metadata)
                # Public reads copy metadata, so inspect storage to detect aliases hidden by those reads.
                original._metadata["review"]["reviewers"].append("original")
                replacement._metadata["review"]["reviewers"].append("replacement")
                self.assertEqual(original.metadata["review"], {"reviewers": ["security", "original"]})
                self.assertEqual(replacement.metadata["review"], {"reviewers": ["security", "replacement"]})

                view = replacement.metadata
                with self.assertRaises(TypeError):
                    view["review"] = {}
                view["review"]["reviewers"].append("view")
                snapshot = replacement.metadata_snapshot()
                snapshot["review"]["reviewers"].append("snapshot")
                self.assertEqual(replacement.metadata["review"], {"reviewers": ["security", "replacement"]})

    def test_replace_explicit_metadata_replaces_instead_of_merging_and_copies_input(self) -> None:
        for constructor in _METADATA_MODEL_CONSTRUCTORS:
            with self.subTest(model=constructor.func.__name__):
                original = constructor(metadata={"original_only": {"items": ["original"]}})
                supplied = {"review": {"reviewers": ["security"]}}

                replacement = replace(original, metadata=MappingProxyType(supplied))
                supplied["review"]["reviewers"].append("caller")

                self.assertEqual(original.metadata, {"original_only": {"items": ["original"]}})
                self.assertEqual(replacement.metadata, {"review": {"reviewers": ["security"]}})

    def test_replace_none_and_empty_metadata_clear_inherited_values(self) -> None:
        for constructor in _METADATA_MODEL_CONSTRUCTORS:
            for metadata in (None, {}):
                with self.subTest(model=constructor.func.__name__, metadata=metadata):
                    original = constructor(metadata={"review": {"reviewers": ["security"]}})

                    replacement = replace(original, metadata=metadata)

                    self.assertEqual(replacement.metadata, {})
                    self.assertEqual(original.metadata, {"review": {"reviewers": ["security"]}})


class ResourceInventoryTests(unittest.TestCase):
    def test_constructor_accepts_all_public_arguments_positionally_and_by_keyword(self) -> None:
        resource = _resource(address="aws_instance.web", resource_type="aws_instance")
        arguments = {
            "provider": "aws",
            "resources": (resource,),
            "unsupported_resources": ["aws_unknown.example"],
            "plan_time_unknown_resources": 3,
            "metadata": {"primary_account_id": "111122223333"},
        }

        for style, inventory in (
            ("positional", ResourceInventory(*arguments.values())),
            ("keyword", ResourceInventory(**arguments)),
        ):
            with self.subTest(style=style):
                for name, expected in arguments.items():
                    self.assertEqual(getattr(inventory, name), expected, name)
                self.assertIs(inventory.get_by_address(resource.address), resource)

    def test_metadata_field_keys_are_normalized_with_field_setters(self) -> None:
        inventory = ResourceInventory(
            provider="aws",
            resources=(),
            metadata=MappingProxyType(
                {
                    InventoryMetadata.PRIMARY_ACCOUNT_ID: " 111122223333 ",
                    "review": {"reviewers": ["security"]},
                }
            ),
        )

        self.assertEqual(inventory.primary_account_id, "111122223333")
        self.assertEqual(
            inventory.metadata,
            {"primary_account_id": "111122223333", "review": {"reviewers": ["security"]}},
        )

    def test_replace_rebuilds_indexes_for_changed_resources_and_retains_metadata(self) -> None:
        old_resource = _resource(address="aws_instance.old", resource_type="aws_instance")
        new_resource = _resource(address="aws_lambda_function.new", resource_type="aws_lambda_function")
        original = ResourceInventory(
            provider="aws",
            resources=(old_resource,),
            unsupported_resources=["aws_unknown.example"],
            plan_time_unknown_resources=3,
            metadata={"primary_account_id": "111122223333"},
        )

        replacement = replace(original, resources=(new_resource,))

        self.assertIs(original.get_by_address(old_resource.address), old_resource)
        self.assertIsNone(original.get_by_address(new_resource.address))
        self.assertIs(replacement.get_by_address(new_resource.address), new_resource)
        self.assertIsNone(replacement.get_by_address(old_resource.address))
        self.assertEqual(replacement.by_type("aws_instance"), [])
        self.assertEqual(replacement.by_type("aws_lambda_function"), [new_resource])
        self.assertEqual(replacement.unsupported_resources, ["aws_unknown.example"])
        self.assertEqual(replacement.plan_time_unknown_resources, 3)
        self.assertEqual(replacement.metadata, {"primary_account_id": "111122223333"})

    def test_by_type_preserves_original_resource_order_for_multiple_types(self) -> None:
        resources = [
            _resource(address="aws_instance.web", resource_type="aws_instance"),
            _resource(address="aws_db_instance.app", resource_type="aws_db_instance", category=ResourceCategory.DATA),
            _resource(address="aws_lambda_function.worker", resource_type="aws_lambda_function"),
            _resource(address="aws_instance.jobs", resource_type="aws_instance"),
        ]
        inventory = ResourceInventory(provider="aws", resources=resources)

        selected = inventory.by_type("aws_lambda_function", "aws_instance")

        self.assertEqual(
            [resource.address for resource in selected],
            [
                "aws_instance.web",
                "aws_lambda_function.worker",
                "aws_instance.jobs",
            ],
        )

    def test_get_by_identifier_preserves_first_match_across_identifier_arn_and_address_aliases(self) -> None:
        first = _resource(
            address="alias",
            resource_type="aws_instance",
            identifier="instance-1",
            arn="arn:aws:ec2:us-east-1:111122223333:instance/i-1234567890",
        )
        second = _resource(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="alias",
            arn="arn:aws:s3:::logs",
        )
        third = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="role-app",
            arn="alias",
        )
        inventory = ResourceInventory(provider="aws", resources=[first, second, third])

        self.assertIs(inventory.get_by_identifier("alias"), first)

    def test_get_by_address_uses_address_index(self) -> None:
        target = _resource(address="aws_instance.web", resource_type="aws_instance")
        inventory = ResourceInventory(
            provider="aws",
            resources=[
                target,
                _resource(address="aws_lambda_function.worker", resource_type="aws_lambda_function"),
            ],
        )

        self.assertIs(inventory.get_by_address("aws_instance.web"), target)
        self.assertIsNone(inventory.get_by_address("aws_instance.missing"))

    def test_resources_are_tuple_backed_after_index_construction(self) -> None:
        first = _resource(address="aws_instance.web", resource_type="aws_instance")
        second = _resource(address="aws_lambda_function.worker", resource_type="aws_lambda_function")
        resources = [first]

        inventory = ResourceInventory(provider="aws", resources=resources)
        resources.append(second)

        self.assertEqual(inventory.resources, (first,))
        self.assertEqual(inventory.by_type("aws_lambda_function"), [])
        with self.assertRaises(AttributeError):
            inventory.resources.append(second)

    def test_indexed_identity_is_sealed_after_inventory_construction(self) -> None:
        resource = _resource(address="aws_instance.original", resource_type="aws_instance")
        resource.address = "aws_instance.web"
        resource.resource_type = "aws_lambda_function"
        resource.identifier = "function-web"
        resource.arn = "arn:aws:lambda:us-east-1:111122223333:function:web"
        inventory = ResourceInventory(provider="aws", resources=[resource])

        for field_name, replacement in (
            ("address", "aws_instance.changed"),
            ("provider", "gcp"),
            ("resource_type", "aws_instance"),
            ("identifier", "function-changed"),
            ("arn", "arn:aws:lambda:us-east-1:111122223333:function:changed"),
        ):
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(AttributeError, field_name):
                    setattr(resource, field_name, replacement)

        with self.assertRaisesRegex(AttributeError, "resources"):
            inventory.resources = ()
        with self.assertRaisesRegex(AttributeError, "provider"):
            inventory.provider = "gcp"
        with self.assertRaisesRegex(AttributeError, "_indexed_identity_sealed"):
            resource._indexed_identity_sealed = False
        with self.assertRaisesRegex(AttributeError, "_indexed_identity_sealed"):
            inventory._indexed_identity_sealed = False

        self.assertIs(inventory.get_by_address("aws_instance.web"), resource)
        self.assertIs(inventory.get_by_identifier("function-web"), resource)
        self.assertIs(inventory.get_by_identifier(resource.arn or ""), resource)
        self.assertEqual(inventory.by_type("aws_lambda_function"), [resource])
        self.assertEqual(inventory.resources, (resource,))

    def test_primary_account_id_property_defaults_and_setter_use_metadata(self) -> None:
        inventory = ResourceInventory(provider="aws", resources=[])

        self.assertIsNone(inventory.primary_account_id)

        inventory.primary_account_id = "111122223333"
        self.assertEqual(inventory.primary_account_id, "111122223333")
        self.assertEqual(inventory.metadata["primary_account_id"], "111122223333")

        inventory.primary_account_id = None
        self.assertIsNone(inventory.primary_account_id)
        self.assertNotIn("primary_account_id", inventory.metadata)

    def test_metadata_snapshot_returns_detached_copy(self) -> None:
        inventory = ResourceInventory(
            provider="aws",
            resources=[],
            metadata={"unsupported_resource_types": {"aws_cloudwatch_log_group": 1}},
        )

        snapshot = inventory.metadata_snapshot()
        snapshot["unsupported_resource_types"]["aws_cloudwatch_log_group"] = 2
        snapshot["new_key"] = "new-value"

        self.assertEqual(
            inventory.metadata,
            {"unsupported_resource_types": {"aws_cloudwatch_log_group": 1}},
        )

    def test_typed_metadata_access_does_not_deepcopy_unrelated_values(self) -> None:
        inventory = ResourceInventory(provider="aws", resources=[])
        value = _RaisesOnDeepcopy()
        inventory._metadata["opaque"] = value

        inventory.primary_account_id = "111122223333"
        self.assertEqual(inventory.primary_account_id, "111122223333")
        self.assertIs(inventory._metadata["opaque"], value)

    def test_metadata_view_is_read_only_and_detached(self) -> None:
        source_metadata = {
            "unsupported_resource_types": {"aws_cloudwatch_log_group": 1},
            "review": {"reviewers": ["security"]},
        }
        inventory = ResourceInventory(provider="aws", resources=[], metadata=MappingProxyType(source_metadata))

        source_metadata["unsupported_resource_types"]["aws_cloudwatch_log_group"] = 2
        view = inventory.metadata
        with self.assertRaises(TypeError):
            view["unsupported_resource_types"] = {"aws_cloudwatch_log_group": 3}
        view["unsupported_resource_types"]["aws_cloudwatch_log_group"] = 3
        view["review"]["reviewers"].append("operations")
        inventory.primary_account_id = "111122223333"

        self.assertEqual(
            inventory.metadata,
            {
                "unsupported_resource_types": {"aws_cloudwatch_log_group": 1},
                "review": {"reviewers": ["security"]},
                "primary_account_id": "111122223333",
            },
        )
        self.assertNotIn("primary_account_id", view)


class NormalizedResourcePropertyTests(unittest.TestCase):
    def test_constructor_accepts_all_public_arguments_positionally_and_by_keyword(self) -> None:
        network_rule = SecurityGroupRule(direction="ingress", protocol="tcp", from_port=443, to_port=443)
        policy_statement = IAMPolicyStatement(effect="Allow", actions=["s3:GetObject"])
        reference_resolution = TerraformReferenceResolution(
            path=("vpc_id",),
            state=TerraformReferenceResolutionState.RESOLVED,
            provenance=TerraformReferenceProvenance.PLANNED_VALUE,
            planned_value="vpc-1",
        )
        arguments = {
            "address": "aws_instance.web",
            "provider": "aws",
            "resource_type": "aws_instance",
            "name": "web",
            "category": ResourceCategory.COMPUTE,
            "identifier": "i-web",
            "arn": "arn:aws:ec2:us-east-1:111122223333:instance/i-web",
            "vpc_id": "vpc-1",
            "subnet_ids": ("subnet-1",),
            "security_group_ids": ("sg-1",),
            "attached_role_arns": ("arn:aws:iam::111122223333:role/web",),
            "network_rules": (network_rule,),
            "policy_statements": (policy_statement,),
            "public_access_configured": True,
            "public_exposure": False,
            "data_sensitivity": "sensitive",
            "provider_config_key": "aws.east",
            "reference_resolutions": (reference_resolution,),
            "metadata": {"review": {"reviewers": ["security"]}},
        }

        for style, resource in (
            ("positional", NormalizedResource(*arguments.values())),
            ("keyword", NormalizedResource(**arguments)),
        ):
            with self.subTest(style=style):
                for name, expected in arguments.items():
                    self.assertEqual(getattr(resource, name), expected, name)

    def test_replace_updates_identity_and_retains_metadata_from_indexed_resource(self) -> None:
        original = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
            identifier="i-web",
            subnet_ids=("subnet-1",),
            metadata={"public_access_reasons": ["public IP"]},
        )
        inventory = ResourceInventory(provider="aws", resources=(original,))

        replacement = replace(original, address="aws_instance.copy", name="copy", identifier="i-copy")

        self.assertEqual(replacement.address, "aws_instance.copy")
        self.assertEqual(replacement.name, "copy")
        self.assertEqual(replacement.identifier, "i-copy")
        self.assertEqual(replacement.subnet_ids, ("subnet-1",))
        self.assertEqual(replacement.metadata, {"public_access_reasons": ["public IP"]})
        self.assertIs(inventory.get_by_address("aws_instance.web"), original)
        self.assertIs(inventory.get_by_identifier("i-web"), original)
        self.assertIsNone(inventory.get_by_address("aws_instance.copy"))

    def test_resource_placement_ids_are_tuple_backed(self) -> None:
        subnet_ids = ["subnet-1"]
        security_group_ids = ["sg-1"]
        resource = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
            subnet_ids=subnet_ids,
            security_group_ids=security_group_ids,
        )

        subnet_ids.append("subnet-2")
        security_group_ids.append("sg-2")

        self.assertEqual(resource.subnet_ids, ("subnet-1",))
        self.assertEqual(resource.security_group_ids, ("sg-1",))
        with self.assertRaises(AttributeError):
            resource.subnet_ids.append("subnet-3")
        with self.assertRaises(AttributeError):
            resource.security_group_ids.append("sg-3")

    def test_resource_mutation_helpers_update_explicit_mutable_fields(self) -> None:
        resource = _resource(address="aws_instance.web", resource_type="aws_instance")
        network_rule = SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_blocks=["0.0.0.0/0"],
        )
        policy_statement = IAMPolicyStatement(effect="Allow", actions=["s3:GetObject"])

        resource.add_attached_role_arn("arn:aws:iam::111122223333:role/web")
        resource.add_attached_role_arn("arn:aws:iam::111122223333:role/web")
        resource.add_attached_role_arn(None)
        resource.extend_network_rules([network_rule])
        resource.extend_policy_statements([policy_statement])

        self.assertEqual(resource.attached_role_arns, ("arn:aws:iam::111122223333:role/web",))
        self.assertEqual(resource.network_rules, (network_rule,))
        self.assertEqual(resource.policy_statements, (policy_statement,))

    def test_freeze_decoration_state_wraps_mutable_decoration_fields(self) -> None:
        resource = _resource(address="aws_instance.web", resource_type="aws_instance")
        network_rule = SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_blocks=["0.0.0.0/0"],
        )
        policy_statement = IAMPolicyStatement(effect="Allow", actions=["s3:GetObject"])

        resource.add_attached_role_arn("arn:aws:iam::111122223333:role/web")
        resource.extend_network_rules([network_rule])
        resource.extend_policy_statements([policy_statement])

        resource.freeze_decoration_state()

        self.assertEqual(resource.attached_role_arns, ("arn:aws:iam::111122223333:role/web",))
        self.assertEqual(resource.network_rules, (network_rule,))
        self.assertEqual(resource.policy_statements, (policy_statement,))
        with self.assertRaises(RuntimeError):
            resource.add_attached_role_arn("arn:aws:iam::111122223333:role/late")
        with self.assertRaises(RuntimeError):
            resource.extend_network_rules([network_rule])
        with self.assertRaises(RuntimeError):
            resource.extend_policy_statements([policy_statement])

    def test_posture_property_defaults_do_not_require_metadata_keys(self) -> None:
        resource = _resource(address="aws_instance.web", resource_type="aws_instance")

        self.assertFalse(resource.direct_internet_reachable)
        self.assertFalse(resource.in_public_subnet)
        self.assertFalse(resource.has_nat_gateway_egress)
        self.assertFalse(resource.internet_ingress_capable)
        self.assertFalse(resource.publicly_accessible)
        self.assertFalse(resource.storage_encrypted)
        self.assertTrue(resource.vpc_enabled)
        self.assertEqual(resource.public_access_reasons, [])
        self.assertEqual(resource.public_exposure_reasons, [])
        self.assertEqual(resource.internet_ingress_reasons, [])
        self.assertEqual(resource.metadata, {})

    def test_metadata_snapshot_returns_detached_copy(self) -> None:
        resource = NormalizedResource(
            address="aws_s3_bucket.logs",
            provider="aws",
            resource_type="aws_s3_bucket",
            name="logs",
            category=ResourceCategory.DATA,
            metadata={
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "tags": {"env": "prod"},
            },
        )

        snapshot = resource.metadata_snapshot()
        snapshot["policy_document"]["Statement"][0]["Effect"] = "Deny"
        snapshot["tags"]["env"] = "dev"
        snapshot["new_key"] = "new-value"

        self.assertEqual(
            resource.metadata,
            {
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "tags": {"env": "prod"},
            },
        )

    def test_metadata_field_keys_are_normalized_with_field_setters(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
            metadata={
                ResourceMetadata.PUBLIC_ACCESS_CONFIGURED: "enabled",
                ResourceMetadata.STORAGE_ENCRYPTED: None,
                "raw": {"items": ["value"]},
            },
        )

        self.assertTrue(resource.get_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertFalse(resource.has_metadata_field(ResourceMetadata.STORAGE_ENCRYPTED))
        self.assertEqual(
            resource.metadata_snapshot(),
            {"public_access_configured": True, "raw": {"items": ["value"]}},
        )

    def test_metadata_value_presence_distinguishes_none_from_false(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
            metadata={
                ResourceMetadata.STORAGE_ENCRYPTED.key: None,
                ResourceMetadata.PUBLIC_ACCESS_CONFIGURED.key: False,
            },
        )

        self.assertTrue(resource.has_metadata_field(ResourceMetadata.STORAGE_ENCRYPTED))
        self.assertFalse(resource.has_metadata_value(ResourceMetadata.STORAGE_ENCRYPTED))
        self.assertTrue(resource.has_metadata_value(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertFalse(resource.has_metadata_value(ResourceMetadata.VPC_ENABLED))

    def test_typed_metadata_access_does_not_deepcopy_unrelated_values(self) -> None:
        resource = _resource(address="aws_instance.web", resource_type="aws_instance")
        value = _RaisesOnDeepcopy()
        resource._metadata["opaque"] = value

        resource.set_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED, True)
        self.assertTrue(resource.get_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertIs(resource._metadata["opaque"], value)

    def test_metadata_view_is_read_only_and_detached(self) -> None:
        source_metadata = {"tags": {"env": "prod", "owners": ["security"]}}
        resource = NormalizedResource(
            address="aws_s3_bucket.logs",
            provider="aws",
            resource_type="aws_s3_bucket",
            name="logs",
            category=ResourceCategory.DATA,
            metadata=MappingProxyType(source_metadata),
        )

        source_metadata["tags"]["env"] = "dev"
        view = resource.metadata
        with self.assertRaises(TypeError):
            view["tags"] = {"env": "test"}
        view["tags"]["env"] = "test"
        view["tags"]["owners"].append("operations")
        resource.set_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED, True)

        self.assertEqual(resource.metadata["tags"], {"env": "prod", "owners": ["security"]})
        self.assertNotIn("public_access_configured", view)

    def test_metadata_schema_helpers_update_private_metadata(self) -> None:
        resource = _resource(address="aws_iam_role.app", resource_type="aws_iam_role")

        self.assertFalse(resource.has_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertFalse(resource.get_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        resource.set_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED, True)
        resource.append_metadata_field(
            AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES,
            "missing-role",
        )
        resource.append_metadata_field(
            AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES,
            "missing-role",
        )
        resource.append_metadata_field(
            AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES,
            None,
        )
        resource.extend_metadata_field(
            AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES,
            ["missing-role", "another-missing-role", "another-missing-role", None],
        )

        self.assertTrue(resource.has_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertTrue(resource.get_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertTrue(resource.metadata["public_access_configured"])
        self.assertEqual(
            resource.get_metadata_field(AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES),
            ["missing-role", "another-missing-role"],
        )
        self.assertEqual(
            resource.metadata["unresolved_role_references"],
            ["missing-role", "another-missing-role"],
        )

    def test_metadata_field_getter_uses_field_copy_semantics(self) -> None:
        resource = _resource(address="aws_s3_bucket.logs", resource_type="aws_s3_bucket")
        resource.set_metadata_field(
            AwsResourceMetadata.POLICY_DOCUMENT,
            {"Statement": [{"Effect": "Allow"}]},
        )

        policy_document = resource.get_metadata_field(AwsResourceMetadata.POLICY_DOCUMENT)
        policy_document["Statement"][0]["Effect"] = "Deny"

        self.assertEqual(
            resource.get_metadata_field(AwsResourceMetadata.POLICY_DOCUMENT),
            {"Statement": [{"Effect": "Allow"}]},
        )

    def test_posture_property_setters_update_metadata(self) -> None:
        resource = _resource(address="aws_db_instance.app", resource_type="aws_db_instance")

        resource.direct_internet_reachable = True
        resource.internet_ingress_capable = True
        resource.in_public_subnet = True
        resource.has_nat_gateway_egress = True
        resource.is_public_subnet = True
        resource.has_public_route = True
        resource.publicly_accessible = True
        resource.storage_encrypted = True
        resource.vpc_enabled = False
        resource.public_access_reasons = ["instance requests a public IP", ""]
        resource.public_exposure_reasons = ["attached security groups allow internet ingress"]
        resource.internet_ingress_reasons = ["aws_security_group.web ingress tcp 443 from 0.0.0.0/0"]

        self.assertTrue(resource.metadata["direct_internet_reachable"])
        self.assertTrue(resource.metadata["internet_ingress_capable"])
        self.assertTrue(resource.metadata["in_public_subnet"])
        self.assertTrue(resource.metadata["has_nat_gateway_egress"])
        self.assertTrue(resource.metadata["is_public_subnet"])
        self.assertTrue(resource.metadata["has_public_route"])
        self.assertTrue(resource.metadata["publicly_accessible"])
        self.assertTrue(resource.metadata["storage_encrypted"])
        self.assertFalse(resource.metadata["vpc_enabled"])
        self.assertEqual(resource.metadata["public_access_reasons"], ["instance requests a public IP"])
        self.assertEqual(
            resource.metadata["public_exposure_reasons"],
            ["attached security groups allow internet ingress"],
        )
        self.assertEqual(
            resource.metadata["internet_ingress_reasons"],
            ["aws_security_group.web ingress tcp 443 from 0.0.0.0/0"],
        )

    def test_unresolved_reference_keys_returns_coerced_references_without_exposing_metadata(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.app",
            provider="aws",
            resource_type="aws_instance",
            name="app",
            category=ResourceCategory.COMPUTE,
            metadata={
                "unresolved_instance_profiles": ["missing-profile"],
                "unresolved_role_references": ["missing-role", "another-missing"],
                "other_metadata": "should-not-appear",
            },
        )

        references = resource.unresolved_reference_keys()

        self.assertEqual(
            references,
            {
                "unresolved_instance_profiles": ["missing-profile"],
                "unresolved_role_references": ["missing-role", "another-missing"],
            },
        )
        self.assertNotIn("other_metadata", references)

    def test_unresolved_reference_keys_returns_empty_when_no_references(self) -> None:
        resource = _resource(address="aws_instance.web", resource_type="aws_instance")

        self.assertEqual(resource.unresolved_reference_keys(), {})

    def test_unresolved_reference_keys_filters_none_and_empty_values(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.app",
            provider="aws",
            resource_type="aws_instance",
            name="app",
            category=ResourceCategory.COMPUTE,
            metadata={
                "unresolved_refs": ["valid", None, "", "also-valid"],
            },
        )

        references = resource.unresolved_reference_keys()

        self.assertEqual(references, {"unresolved_refs": ["valid", "also-valid"]})

    def test_unresolved_reference_keys_coerces_non_string_values(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.app",
            provider="aws",
            resource_type="aws_instance",
            name="app",
            category=ResourceCategory.COMPUTE,
            metadata={
                "unresolved_ids": [123, True, "str-val"],
            },
        )

        references = resource.unresolved_reference_keys()

        self.assertEqual(references, {"unresolved_ids": ["123", "True", "str-val"]})

    def test_unresolved_reference_keys_handles_single_non_list_value(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.app",
            provider="aws",
            resource_type="aws_instance",
            name="app",
            category=ResourceCategory.COMPUTE,
            metadata={
                "unresolved_single": "just-a-string",
            },
        )

        references = resource.unresolved_reference_keys()

        self.assertEqual(references, {"unresolved_single": ["just-a-string"]})

    def test_unresolved_reference_keys_returns_sorted_keys(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.app",
            provider="aws",
            resource_type="aws_instance",
            name="app",
            category=ResourceCategory.COMPUTE,
            metadata={
                "unresolved_z": ["z-ref"],
                "unresolved_a": ["a-ref"],
                "unresolved_m": ["m-ref"],
            },
        )

        references = resource.unresolved_reference_keys()

        self.assertEqual(list(references.keys()), ["unresolved_a", "unresolved_m", "unresolved_z"])

    def test_unresolved_reference_keys_json_encodes_structured_values(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.app",
            provider="aws",
            resource_type="aws_instance",
            name="app",
            category=ResourceCategory.COMPUTE,
            metadata={
                "unresolved_complex": [{"b": 2, "a": 1}],
            },
        )

        self.assertEqual(
            resource.unresolved_reference_keys(),
            {"unresolved_complex": ['{"a":1,"b":2}']},
        )


class ResourceInventoryValidationTests(unittest.TestCase):
    def test_primary_account_id_setter_routes_through_ownership_validator(self) -> None:
        from unittest.mock import patch

        inventory = ResourceInventory(provider="aws", resources=[])

        with patch(
            "tfstride.providers.metadata_ownership.validate_normalized_resource_metadata_write"
        ) as mock_validate:
            inventory.primary_account_id = "111122223333"

            mock_validate.assert_called_once()
            call_kwargs = mock_validate.call_args.kwargs
            self.assertEqual(call_kwargs["resource_provider"], "aws")

        self.assertEqual(inventory.primary_account_id, "111122223333")

    def test_primary_account_id_setter_none_removes_key_through_validator(self) -> None:
        from unittest.mock import patch

        inventory = ResourceInventory(
            provider="aws",
            resources=[],
            metadata={"primary_account_id": "111122223333"},
        )

        with patch(
            "tfstride.providers.metadata_ownership.validate_normalized_resource_metadata_write"
        ) as mock_validate:
            inventory.primary_account_id = None

            mock_validate.assert_called_once()

        self.assertIsNone(inventory.primary_account_id)

    def test_primary_account_id_setter_accepts_owned_inventory_metadata(self) -> None:
        inventory = ResourceInventory(provider="aws", resources=[])

        inventory.primary_account_id = "111122223333"

        self.assertEqual(inventory.primary_account_id, "111122223333")


if __name__ == "__main__":
    unittest.main()
