# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_safe_plan.json`
- Provider: `azure`
- Normalized resources: `4`
- Unsupported resources: `0`

## Summary

This run identified **0 trust boundaries** and **0 findings** across **4 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `4`
- Provider resources considered: `4`
- Normalized resources: `4`
- Unsupported resources: `0`
- Registered rules: `252`
- Enabled rules: `252`
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

- Azure support covers a curated AzureRM set including Storage, Service Bus, Container Registry, Key Vault, SQL/PostgreSQL, App Service/Function Apps, AKS, networking and public edge, Private Endpoint/DNS-zone-group, diagnostic/Defender, and RBAC/identity posture. Remaining limitations include full Private DNS record correctness, broader RBAC hierarchy, MySQL, runtime application authentication and routing, full AKS node/workload posture, and unsupported platform services; analysis remains plan-local.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
