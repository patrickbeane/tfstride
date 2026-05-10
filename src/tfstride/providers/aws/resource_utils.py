from __future__ import annotations

from typing import Any


def bucket_public_exposure_reasons(
    bucket_acl: str,
    *,
    public_policy: bool,
    public_access_block: dict[str, bool] | None = None,
) -> list[str]:
    reasons: list[str] = []
    access_block = public_access_block or {}
    acl_is_public = bucket_acl in {"public-read", "public-read-write", "website"}
    if acl_is_public and not (access_block.get("block_public_acls") or access_block.get("ignore_public_acls")):
        reasons.append(f"bucket ACL `{bucket_acl}` grants public access")
    if public_policy and not (access_block.get("block_public_policy") or access_block.get("restrict_public_buckets")):
        reasons.append("bucket policy allows anonymous access")
    return reasons


def ecs_task_definition_identifier(family: Any, revision: Any) -> str | None:
    family_text = str(family).strip() if family not in (None, "") else ""
    if not family_text:
        return None
    revision_text = str(revision).strip() if revision not in (None, "") else ""
    if revision_text:
        return f"{family_text}:{revision_text}"
    return family_text


def route_table_has_internet_route(routes: list[dict[str, Any]]) -> bool:
	    for route in routes:
	        destination = route.get("cidr_block") or route.get("destination_cidr_block")
	        gateway_id = route.get("gateway_id")
	        if destination == "0.0.0.0/0" and isinstance(gateway_id, str) and gateway_id.startswith("igw-"):
	            return True
	    return False
	
	
def route_table_has_nat_gateway_route(routes: list[dict[str, Any]], nat_gateway_ids: set[str]) -> bool:
    for route in routes:
        destination = route.get("cidr_block") or route.get("destination_cidr_block")
        nat_gateway_id = route.get("nat_gateway_id")
        gateway_id = route.get("gateway_id")
        if destination != "0.0.0.0/0":
            continue
        if isinstance(nat_gateway_id, str) and nat_gateway_id in nat_gateway_ids:
            return True
        if isinstance(gateway_id, str) and gateway_id in nat_gateway_ids:
            return True
    return False 