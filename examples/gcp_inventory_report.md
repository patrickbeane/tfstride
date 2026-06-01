# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_plan.json`
- Provider: `gcp`
- Normalized resources: `6`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundaries** and **1 findings** across **6 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `1`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `6`
- Provider resources considered: `6`
- Normalized resources: `6`
- Unsupported resources: `0`
- Registered rules: `16`
- Enabled rules: `16`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-public-compute-broad-ingress`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `google_compute_instance.web`
- Description: Traffic can cross from the public internet to google_compute_instance.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

No findings in this severity band.

### Medium

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

- GCP support currently provides initial inventory normalization, internet-to-service trust-boundary detection, and limited GCP STRIDE rule coverage only; GCP control coverage is not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
