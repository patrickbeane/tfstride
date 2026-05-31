# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_plan.json`
- Provider: `gcp`
- Normalized resources: `6`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundaries** and **0 findings** across **6 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `6`
- Provider resources considered: `6`
- Normalized resources: `6`
- Unsupported resources: `0`
- Registered rules: `13`
- Enabled rules: `13`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`

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

No findings in this severity band.

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- GCP support currently provides initial inventory normalization and internet-to-service trust-boundary detection only; GCP STRIDE rule and control coverage are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
