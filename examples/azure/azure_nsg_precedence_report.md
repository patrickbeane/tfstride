# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_nsg_precedence_plan.json`
- Provider: `azure`
- Normalized resources: `7`
- Unsupported resources: `0`

## Summary

This run identified **0 trust boundaries** and **0 findings** across **7 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `7`
- Provider resources considered: `7`
- Normalized resources: `7`
- Unsupported resources: `0`
- Registered rules: `169`
- Enabled rules: `169`
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

- Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, SQL Database posture (public network access, firewall, TLS, security alerting), PostgreSQL Flexible Server posture (public network access, firewall, TLS/SSL, geo-redundant backup), Private Endpoint coverage for supported data-plane resources, AKS control-plane posture findings, and public virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC hierarchy, MySQL, Private Endpoint DNS correctness, load-balancer, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
