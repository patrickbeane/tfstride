# Cross-Provider Threat-Path Semantics

`tfstride` runs the same analysis *shape* across AWS, GCP, and AzureRM - shared evidence vocabulary, shared parity tests - while keeping every finding provider-owned, because AWS IAM, GCP IAM, and Azure RBAC are not interchangeable systems. This doc explains that shared shape; see the provider docs ([AWS](../providers/aws.md), [GCP](../providers/gcp.md), [Azure](../providers/azure.md)) for what's actually modeled per cloud.

## The "quiet vs. promoted" rule

A relationship only becomes a finding when it is backed by deterministic modeled evidence. Exact symbolic first-apply references may qualify when resolution is unambiguous. Denied or incompatible evidence stays **quiet**; condition-dependent, ambiguous, unresolved, unsupported, or incomplete expected relationships are retained as uncertainty where the provider model can identify them. Out-of-plan relationships are not inferred. This applies consistently to:

* Workload-to-data mutation and read paths (e.g., an ECS task role, Cloud Run service account, or App Service managed identity reaching a data store)
* Cryptographic-operation paths (decrypt, unwrap, sign, MAC-generate), which additionally require compatible key capabilities and effective operation authorization
* Managed-key administration paths (disruption, authorization delegation), which additionally require exact modeled key or management-target resolution
* Object-storage paths, which distinguish object writes and metadata mutation, object-level deletion, and bucket or container topology deletion while retaining provider-native recovery and prerequisite uncertainty
* Structured-data paths, which separate record mutation, item/entity deletion, and table/database/account/container topology deletion while retaining provider-native protection and recovery evidence
* Messaging paths, which separate send/publish mutation, receive/pull disclosure, message removal, and modeled topology deletion while retaining provider-native delivery and replay evidence
* Audit-telemetry disruption paths, which connect currently public workloads to exact current audit/security telemetry targets through provider-native runtime identity and authorization evidence
* Secret values themselves, which are never retained in evidence or reports

For object-storage paths, recovery uncertainty affects impact evidence, not deterministic deletion authority. Explicitly denied or incompatible deletion paths stay quiet; conditional, incomplete, ambiguous, or unresolved paths remain uncertainty where modeled. See [Object-Storage Paths](object-storage-paths.md) for the provider-native target and recovery boundaries.

For structured-data paths, protection controls can make topology deletion incompatible, while recovery evidence qualifies deterministic item/entity or topology deletion authority. It does not prove successful deletion, restoration, immediate item-level undo, or out-of-plan descendants. See [Structured-Data Paths](structured-data-paths.md) for provider-native target and recovery boundaries.

For messaging paths, delivery and replay posture qualifies impact without proving payload retrieval, successful removal, topology deletion, replay, or recovery. Only modeled queue, topic, subscription, and namespace deletion belongs to this path family; broader service or account destruction remains outside it. See [Messaging Paths](messaging-paths.md) for provider-native boundaries.

## Audit-telemetry disruption

Introduced in 0.4.40, this Repudiation path family models how compromise of a currently public workload could disrupt future audit/security telemetry recording or export for an exact plan-local target:

| Provider | Public workload and runtime identity | Exact target and operation | Current proof constraints |
| --- | --- | --- | --- |
| AWS | ECS service and task role | CloudTrail trail via `cloudtrail:StopLogging` or `cloudtrail:DeleteTrail` | Effective IAM, permissions-boundary compatibility, and current trail/logging state |
| GCP | Cloud Run service and service account | Active user-managed project logging sink via `logging.sinks.delete` | Effective project IAM, IAM deny policies, destination, filter/exclusions, and sink state |
| Azure | App Service and attached managed identity | Diagnostic-setting ARM extension resource via `Microsoft.Insights/DiagnosticSettings/Delete` | AzureRM state-ID/ARM-target correlation, Actions/NotActions RBAC, destination/categories, and applicable management locks |

Decorated paths are candidate relationships only. Each public-workload rule revalidates current exposure, runtime identity, authorization, exact target, lifecycle/configuration, and provider-native audit relevance before emission. Findings describe prospective weakening of auditability/accountability; they do not establish a successful destructive call, historical or already-delivered telemetry deletion, destination deletion, broad or out-of-plan disruption, or recovery/restoration.

## Identity and workload data-plane paths are provider-local

Privileged identity assignment posture is normalized into a shared provider-neutral vocabulary for evidence and parity tests, but findings stay provider-owned:

* **AWS** distinguishes ECS execution-role secret delivery from task-role permissions, and connects public ECS services to exact Secrets Manager, S3, SNS/SQS, DynamoDB, and KMS grants.
* **GCP** connects public Cloud Run service accounts to exact Secret Manager, GCS, Pub/Sub, Firestore, and Cloud KMS grants.
* **Azure** connects public App Service or Function App managed identities to exact Key Vault, Storage Account/container, Service Bus, or Cosmos DB for NoSQL authorization.

## Managed-key dependencies

Managed-key dependency analysis preserves provider-native key, alias, version, and vault identity, then enriches disruption findings only with exact modeled encrypted dependents. Ambiguous, unresolved, or unsupported expected dependencies remain uncertainty; incompatible consumers stay quiet, and out-of-plan consumers are not inferred. Full detail: [Managed-Key Paths](managed-key-paths.md).

## Network telemetry and public edge protection are provider-local checks

Both are conceptually the same check, implemented against each provider's native primitive:

| Concept | AWS | GCP | Azure |
| --- | --- | --- | --- |
| Network telemetry | Modeled VPC Flow Logs | Subnet Flow Logs | Modeled Network Watcher flow logs for NSGs |
| Public edge protection | Modeled WAFv2 Web ACL associations for public ALBs | Cloud Armor policy references on public load-balancer backends | Firewall policy or enabled WAF configuration for public Application Gateway listeners |

## Condition narrowing

Condition narrowing focuses on high-signal, provider-specific authorization keys (for example AWS's `SourceArn`, `SourceAccount`, and `ExternalId`) rather than exhaustive coverage of every service-specific authorization condition.

## Subnet classification

Subnet classification prefers explicit route table associations when available, but does not model main-route-table inheritance or every routing edge case.

Subnet posture in finding evidence resolves references through the provider's typed subnet index using the workload as the source. A uniquely resolved subnet supplies its name and routing posture; ambiguous or unresolved references remain explicit uncertainty, even when an aggregate workload flag says it is in a public subnet. AWS weak subnet IDs require known provider-configuration scope; exact Terraform addresses and subnet ARNs can resolve across configurations. Multiple aliases for one subnet do not duplicate its posture evidence.

Public-to-private subnet boundaries describe separate trust zones within one provider-resolved network. Common network membership does **not** prove packet reachability; routes, security groups, firewall rules, and other traffic controls require separate evaluation.

Network membership uses AWS VPC relationship keys, GCP project-scoped network resolution, or Azure subscription/resource-group-scoped VNet resolution. Exact Terraform addresses and strong native identities can resolve across provider configurations. Exact symbolic identity references from plan ingestion also qualify on first apply. Weak aliases need known provider scope (AWS), project scope (GCP), or subscription and resource-group scope (Azure); equal raw strings alone are insufficient. Unresolved or ambiguous references have no grouping key, and the resolution result retains the reason and modeled candidates. Plans without scope evidence can therefore have fewer subnet boundaries than otherwise equivalent plans that include configuration. This does not remove independently established workload-to-data findings.

Provider boundary contributors supply these resolutions to the shared subnet boundary builder. Disabling a provider's boundary contributor also disables its subnet boundaries; the shared builder never falls back to raw `vpc_id` equality.
