# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_plan.json`
- Provider: `gcp`
- Normalized resources: `6`
- Unsupported resources: `0`

## Summary

This run identified **0 trust boundaries** and **0 findings** across **6 normalized resources**.

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

No trust boundaries were discovered.

## Findings

### High

No findings in this severity band.

### Medium

No findings in this severity band.

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- GCP support currently provides initial resource inventory normalization only; GCP trust-boundary and rule coverage are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
