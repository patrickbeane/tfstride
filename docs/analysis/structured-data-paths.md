# Public Workload Structured-Data Disruption, Recovery, and Topology Paths

Structured-data analysis separates public-workload authority to mutate records, delete records, and delete their enclosing provider-native topology. It does not invent item, entity, or document instances.

## Shared boundary

* Create, update, replace, and upsert authority produces Tampering paths.
* Item or entity deletion authority produces item-level Denial of Service paths.
* Table, database, account, or container deletion authority produces topology-level Denial of Service paths.
* Deletion-only operations are excluded from mutation evidence; deterministic mixed authority may produce separate findings.
* Private workloads retain modeled paths but do not produce public-workload findings.
* Conditional, denied, incomplete, ambiguous, unresolved, and unsupported authority is not promoted.

## Target granularity

Item-level paths retain exact provider-native namespaces:

* AWS DynamoDB: exact table item namespace;
* GCP Firestore: exact database entity or bulk-entity namespace;
* Azure Cosmos DB for NoSQL: account, database, or container item namespace.

Topology paths target exact modeled DynamoDB tables, Firestore databases, or Cosmos DB accounts, databases, and containers. Broad grants fan out only to exact in-plan targets; parent authority preserves ancestry without manufacturing unmodeled descendants. On AWS, table-topology paths accept `*` and covering same-account ARN patterns, while item-deletion paths remain exact-table only.

## Protection and recovery

| Provider | Native boundary |
| --- | --- |
| AWS | DynamoDB deletion protection can make `DeleteTable` incompatible; point-in-time recovery qualifies impact without proving restoration. |
| GCP | Firestore delete protection can block database deletion; point-in-time recovery, native history, and Terraform deletion policy remain distinct from IAM authority. |
| Azure | Applicable `CanNotDelete` and `ReadOnly` locks block control-plane deletion; continuous, periodic, provider-default, and unknown backup posture remain recovery evidence only. |

Protection and recovery evidence is plan-local. It does not establish successful deletion, immediate item-level undo, successful restoration, or out-of-plan records and descendants. Project/subscription destruction, policy delegation, and backup-policy mutation remain outside this path family.

See [Cross-Provider Threat-Path Semantics](path-semantics.md) for the shared quiet-versus-promoted rule, and the provider coverage maps ([AWS](../providers/aws.md), [GCP](../providers/gcp.md), [Azure](../providers/azure.md)) for current scope.
