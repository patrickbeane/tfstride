# Public Workload Messaging Disclosure and Disruption Paths

Messaging analysis separates authority to send messages, receive their contents, and remove them. Findings remain provider-owned and preserve exact runtime identity, authorization scope, and consumable target ancestry.

## Shared boundary

* Send or publish authority produces Tampering paths.
* Receive or pull authority produces Information Disclosure paths.
* Delete, acknowledge, complete, purge, or modeled topology-deletion authority produces Denial of Service paths.
* One workload may produce multiple findings when the corresponding operation families are deterministic.
* Private workloads retain modeled paths but do not produce public-workload findings.
* Conditional, denied, incomplete, ambiguous, incompatible, or unresolved authority is not promoted into a deterministic path.

## Provider-native disruption

| Provider | Message removal | Topology deletion |
| --- | --- | --- |
| AWS | ECS `DeleteMessage` requires the same task role to receive from the exact SQS queue; `PurgeQueue` is queue-wide. | ECS `DeleteQueue` and `DeleteTopic` cover exact modeled SQS queues and SNS topics, granted by an exact resource or a covering wildcard. |
| GCP | Cloud Run `pubsub.subscriptions.consume` establishes acknowledgement authority only for exact modeled pull subscriptions. | Cloud Run `pubsub.topics.delete` and `pubsub.subscriptions.delete` retain exact target and cross-project ancestry. |
| Azure | App Service Service Bus receive authority establishes ReceiveAndDelete and PeekLock-completion capability for exact queues or topic subscriptions. | App Service ARM deletion covers exact modeled namespaces, queues, topics, and subscriptions; plan-local management locks qualify compatibility. |

## Delivery and replay evidence

SQS retention and redrive, Pub/Sub retention and acknowledged-message replay, and Service Bus TTL, lock, delivery-count, and dead-letter posture qualify impact only. They do not prove payload retrieval, successful removal, replay, restoration, or recovery. The model does not invent receipt handles, acknowledgement IDs, lock tokens, payloads, or operation outcomes.

## Scope limits

Topology deletion is limited to the modeled provider-native targets above. It does not establish successful deletion, descendant impact, recovery, or out-of-plan topology. Broad grants fan out only to exact modeled consumable or topology targets; out-of-plan message instances and runtime delivery mode selection are not inferred.

See [Cross-Provider Threat-Path Semantics](path-semantics.md) for the shared quiet-versus-promoted rule, and the provider coverage maps ([AWS](../providers/aws.md), [GCP](../providers/gcp.md), [Azure](../providers/azure.md)) for current implementation scope.
