from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.resource_reference_index import build_resource_reference_index


def _resource(
    address: str,
    *,
    identifier: str,
    resource_type: str = "test_key",
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="test",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=ResourceCategory.DATA,
        identifier=identifier,
    )


def _references(resource: NormalizedResource) -> tuple[str | None, ...]:
    return (
        resource.address,
        resource.identifier,
        resource.identifier.upper() if resource.identifier else None,
    )


class ResourceReferenceIndexTests(unittest.TestCase):
    def test_index_preserves_ambiguous_candidates_after_canonicalization(self) -> None:
        first = _resource("test_key.first", identifier="/keys/shared")
        second = _resource("test_key.second", identifier="/KEYS/SHARED")

        index = build_resource_reference_index(
            (second, first),
            references_for_resource=_references,
            reference_key=str.casefold,
        )

        self.assertEqual(
            [candidate.address for candidate in index.candidates("/Keys/Shared")],
            [first.address, second.address],
        )
        self.assertIsNone(index.unique_candidate("/keys/shared"))

    def test_index_deduplicates_aliases_for_one_resource(self) -> None:
        key = _resource("test_key.exact", identifier="/keys/exact")

        index = build_resource_reference_index(
            (key,),
            references_for_resource=_references,
            reference_key=str.casefold,
        )

        self.assertEqual(index.candidates("/KEYS/EXACT"), (key,))
        self.assertIs(index.unique_candidate("/keys/exact"), key)
        self.assertEqual(index.candidates(None), ())
        self.assertEqual(index.candidates("/keys/missing"), ())

    def test_resolution_classifies_candidate_cardinality(self) -> None:
        first = _resource("test_key.first", identifier="/keys/shared")
        second = _resource("test_key.second", identifier="/KEYS/SHARED")
        index = build_resource_reference_index(
            (second, first),
            references_for_resource=_references,
            reference_key=str.casefold,
        )

        resolved = index.resolve(first.address)
        ambiguous = index.resolve("/Keys/Shared")
        unresolved = index.resolve(None)

        self.assertEqual(resolved.state, "resolved")
        self.assertEqual(resolved.candidates, (first,))
        self.assertIs(resolved.selected_candidate, first)
        self.assertEqual(ambiguous.state, "ambiguous")
        self.assertEqual(ambiguous.candidates, (first, second))
        self.assertIsNone(ambiguous.selected_candidate)
        self.assertEqual(unresolved.state, "unresolved")
        self.assertEqual(unresolved.candidates, ())
        self.assertIsNone(unresolved.selected_candidate)

    def test_resolution_filters_candidates_before_classifying(self) -> None:
        key = _resource("test_key.first", identifier="/keys/shared")
        alias = _resource(
            "test_key.second",
            identifier="/KEYS/SHARED",
            resource_type="test_alias",
        )
        index = build_resource_reference_index(
            (alias, key),
            references_for_resource=_references,
            reference_key=str.casefold,
        )

        resolved = index.resolve(
            "/Keys/Shared",
            candidate_filter=lambda candidate: candidate.resource_type == "test_key",
        )
        unresolved = index.resolve(
            "/Keys/Shared",
            candidate_filter=lambda candidate: candidate.resource_type == "missing",
        )

        self.assertEqual(resolved.state, "resolved")
        self.assertEqual(resolved.candidates, (key,))
        self.assertIs(resolved.selected_candidate, key)
        self.assertEqual(unresolved.state, "unresolved")
        self.assertEqual(unresolved.candidates, ())
        self.assertIsNone(unresolved.selected_candidate)


if __name__ == "__main__":
    unittest.main()
