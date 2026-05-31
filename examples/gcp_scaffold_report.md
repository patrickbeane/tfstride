# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_plan.json`
- Provider: `gcp`
- Normalized resources: `0`
- Unsupported resources: `6`

## Summary

This run identified **0 trust boundaries** and **0 findings** across **0 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `6`
- Provider resources considered: `6`
- Normalized resources: `0`
- Unsupported resources: `6`
- Registered rules: `13`
- Enabled rules: `13`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Unsupported resource types:
  - `google_compute_firewall`: `1`
  - `google_compute_instance`: `1`
  - `google_compute_network`: `1`
  - `google_compute_subnetwork`: `1`
  - `google_project_iam_member`: `1`
  - `google_storage_bucket`: `1`

## Discovered Trust Boundaries

No trust boundaries were discovered.

## Findings

### High

No findings in this severity band.

### Medium

No findings in this severity band.

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- GCP support currently recognizes Terraform Google provider resources but does not normalize GCP resource types yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
- Unsupported resource skipped: `google_compute_firewall.public_ssh`
- Unsupported resource skipped: `google_compute_instance.web`
- Unsupported resource skipped: `google_compute_network.main`
- Unsupported resource skipped: `google_compute_subnetwork.app`
- Unsupported resource skipped: `google_project_iam_member.web_viewer`
- Unsupported resource skipped: `google_storage_bucket.logs`
