# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_plan.json`
- Provider: `gcp`
- Normalized resources: `7`
- Unsupported resources: `0`

## Summary

This run identified **2 trust boundaries** and **2 findings** across **7 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `2`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `7`
- Provider resources considered: `7`
- Normalized resources: `7`
- Unsupported resources: `0`
- Registered rules: `17`
- Enabled rules: `17`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-gcs-public-access`: `1`
  - `gcp-public-compute-broad-ingress`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `google_compute_instance.web`
- Description: Traffic can cross from the public internet to google_compute_instance.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `google_storage_bucket.logs`
- Description: Traffic can cross from the public internet to google_storage_bucket.logs.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

No findings in this severity band.

### Medium

#### GCS bucket is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `google_storage_bucket.logs`
- Trust boundary: `internet-to-service:internet->google_storage_bucket.logs`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: google_storage_bucket.logs is publicly reachable through GCS IAM grants. Public bucket access is a common source of unintended object disclosure.
- Recommended mitigation: Remove `allUsers` and `allAuthenticatedUsers` from bucket-level IAM grants, enforce GCS Public Access Prevention, and use signed URLs, CDN origins, or narrow identities when objects must be distributed.
- Evidence:
  - public exposure reasons: google_storage_bucket_iam_member.public_logs_reader grants roles/storage.objectViewer to allUsers

#### Internet-exposed GCP compute instance permits broad ingress

- STRIDE category: Spoofing
- Affected resources: `google_compute_instance.web`, `google_compute_firewall.public_ssh`
- Trust boundary: `internet-to-service:internet->google_compute_instance.web`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: google_compute_instance.web has an external access config and matching GCP firewall rules allow administrative access or all ports from the public internet. That broad ingress raises the chance of unauthenticated probing and credential attacks.
- Recommended mitigation: Restrict GCP firewall source ranges and exposed ports, remove external IP access where possible, and use Identity-Aware Proxy, VPN, or a controlled bastion for administration.
- Evidence:
  - firewall rules: google_compute_firewall.public_ssh ingress tcp 22 from 0.0.0.0/0
  - network tags: web
  - public exposure reasons: compute instance has an external access config and matching firewall rules allow internet ingress

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- GCP support currently provides initial inventory normalization, internet-to-service trust-boundary detection, and limited GCP STRIDE rule coverage for compute, GCS, and project IAM only; GCP control coverage is not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
