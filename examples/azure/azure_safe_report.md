# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_safe_plan.json`
- Provider: `azure`
- Normalized resources: `3`
- Unsupported resources: `0`

## Summary

This run identified **0 trust boundaries** and **0 findings** across **3 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `3`
- Provider resources considered: `3`
- Normalized resources: `3`
- Unsupported resources: `0`
- Registered rules: `53`
- Enabled rules: `53`
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

- Azure support currently covers AzureRM storage posture and normalizes the initial VNet, subnet, NSG, NIC, public-IP, and virtual-machine relationship graph; Azure compute exposure findings, identity, database, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
