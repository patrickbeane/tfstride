from __future__ import annotations

import unittest

from tfstride.providers.container_images import parse_container_image_reference


class ContainerImageReferenceTests(unittest.TestCase):
    def test_parses_implicit_registry_tag_reference_without_inventing_host(self) -> None:
        reference = parse_container_image_reference("team/api:stable")

        self.assertTrue(reference.is_resolved)
        self.assertEqual(reference.raw, "team/api:stable")
        self.assertIsNone(reference.registry_host)
        self.assertEqual(reference.repository, "team/api")
        self.assertEqual(reference.tag, "stable")
        self.assertIsNone(reference.digest)
        self.assertFalse(reference.digest_pinned)

    def test_parses_explicit_registry_and_port(self) -> None:
        reference = parse_container_image_reference("registry.example.com:5000/team/api:stable")

        self.assertEqual(reference.registry_host, "registry.example.com:5000")
        self.assertEqual(reference.repository, "team/api")
        self.assertEqual(reference.tag, "stable")
        self.assertEqual(reference.digest_pinned, False)

    def test_parses_digest_pinned_reference(self) -> None:
        digest = "sha256:" + "a" * 64
        reference = parse_container_image_reference(f"ghcr.io/acme/api@{digest}")

        self.assertTrue(reference.is_resolved)
        self.assertEqual(reference.registry_host, "ghcr.io")
        self.assertEqual(reference.repository, "acme/api")
        self.assertIsNone(reference.tag)
        self.assertEqual(reference.digest, digest)
        self.assertTrue(reference.digest_pinned)

    def test_preserves_tag_and_digest_when_both_are_present(self) -> None:
        digest = "sha256:" + "b" * 64
        reference = parse_container_image_reference(f"docker.io/library/nginx:1.27@{digest}")

        self.assertEqual(reference.registry_host, "docker.io")
        self.assertEqual(reference.repository, "library/nginx")
        self.assertEqual(reference.tag, "1.27")
        self.assertEqual(reference.digest, digest)
        self.assertTrue(reference.digest_pinned)

    def test_parses_localhost_registry(self) -> None:
        reference = parse_container_image_reference("localhost/team/api:dev")

        self.assertEqual(reference.registry_host, "localhost")
        self.assertEqual(reference.repository, "team/api")
        self.assertEqual(reference.tag, "dev")

    def test_preserves_unresolved_expression_and_unknown_pin_state(self) -> None:
        value = "${var.container_image}"
        reference = parse_container_image_reference(value)

        self.assertFalse(reference.is_resolved)
        self.assertEqual(reference.raw, value)
        self.assertEqual(reference.unresolved_value, value)
        self.assertEqual(reference.unresolved_reason, "image reference is unresolved")
        self.assertIsNone(reference.digest_pinned)

    def test_preserves_known_after_apply_marker(self) -> None:
        value = "<known after apply>"
        reference = parse_container_image_reference(value)

        self.assertFalse(reference.is_resolved)
        self.assertEqual(reference.raw, value)
        self.assertEqual(reference.unresolved_value, value)
        self.assertIsNone(reference.digest_pinned)

    def test_missing_and_non_string_values_remain_unresolved(self) -> None:
        missing = parse_container_image_reference(None)
        non_string = parse_container_image_reference(["image"])

        self.assertFalse(missing.is_resolved)
        self.assertIsNone(missing.raw)
        self.assertIsNone(missing.unresolved_value)
        self.assertEqual(missing.unresolved_reason, "image reference is not represented")
        self.assertFalse(non_string.is_resolved)
        self.assertIsNone(non_string.raw)
        self.assertEqual(non_string.unresolved_value, ["image"])
        self.assertEqual(non_string.unresolved_reason, "image reference is not a string")
        self.assertIsNone(non_string.digest_pinned)

    def test_malformed_digest_remains_unresolved(self) -> None:
        value = "registry.example.com/team/api@sha256"
        reference = parse_container_image_reference(value)

        self.assertFalse(reference.is_resolved)
        self.assertEqual(reference.raw, value)
        self.assertEqual(reference.unresolved_value, value)
        self.assertEqual(reference.unresolved_reason, "image digest has invalid syntax")
        self.assertIsNone(reference.digest_pinned)

    def test_empty_or_whitespace_references_remain_unresolved(self) -> None:
        empty = parse_container_image_reference("")
        whitespace = parse_container_image_reference("team/api latest")

        self.assertEqual(empty.unresolved_reason, "image reference is empty")
        self.assertEqual(whitespace.unresolved_reason, "image reference contains whitespace")
        self.assertIsNone(empty.digest_pinned)
        self.assertIsNone(whitespace.digest_pinned)


if __name__ == "__main__":
    unittest.main()
