# Threat Knowledge Base

Rule packs in this directory supply the deterministic findings the report
publishes. 21 modules load into a single database of roughly 180 rules.

## Modules

Loading is handled by `ThreatKnowledgeBase` in [loader.py](loader.py). Every
`*.json` file here is discovered automatically except those in
`EXCLUDED_KB_FILES`; a new pack needs no registration. Files named in the
loader's priority order load first and everything else follows alphabetically.

Two packs using the same threat ID are merged into one canonical record rather
than one silently replacing the other, and the collision is recorded in
`validation_issues`. Rules that fail schema validation are dropped and reported
the same way, so check that list after editing a pack.

| Module | Scope |
| --- | --- |
| `cloud_aws_threats.json` | S3, EC2, Lambda, IAM, RDS, and other AWS services |
| `cloud_azure_threats.json` | Azure services |
| `cloud_gcp_threats.json` | GCP services |
| `owasp_web_top10.json` | OWASP Top 10 for web applications |
| `owasp_api_top10.json` | OWASP API Security Top 10 |
| `container_k8s_threats.json` | Containers and Kubernetes |
| `auth_authz_threats.json` | Authentication and authorization |
| `infrastructure_threats.json` | Infrastructure components |
| `database_threats.json` | Databases |
| `supply_chain_threats.json` | Supply chain and CI/CD |
| `emerging_threats.json` | Recent and emerging patterns |
| `custom_ai_llm_threats.json` | Prompt injection, jailbreaks, model extraction |
| `domain_threats.json` | Domain-profile threats |
| `threats.json` | Base catalog |
| `ai_agent_threats.json` | Agent tool use, memory, autonomy, trace leakage |
| `rag_vector_store_threats.json` | RAG, retrieval, embedding corpora |
| `serverless_threats.json` | Function triggers, IAM, events, concurrency |
| `identity_zero_trust_threats.json` | Workload identity, OAuth scope, tenant isolation |
| `data_pipeline_threats.json` | ETL, analytics, streaming, orchestration |
| `secrets_management_threats.json` | Source, CI/CD, cloud key, and rotation risks |
| `professional_threat_catalog.json` | Cross-cutting professional catalog |

`schema.json` and `enhanced_schema.json` define the rule fields. They are the two
files excluded from discovery, so they are the only `*.json` here that are not
loaded as rules. MITRE ATT&CK techniques are carried on the rules themselves
rather than in a separate mapping file.

## Writing a rule

Match on architecture facts rather than wording. A rule fires against the
canonical model the parser produced, not the sentence the analyst typed.

**`resource_types` is matched loosely.** Comparison ignores spacing and casing,
so `StorageBucket`, `Storage Bucket`, and `Object Storage` all reach the same
components. A rule will not silently miss because a type is spelled as one word
in the pack and two in the model.

**Name the control the rule is about.** A rule that carries `controls` is
recognized as being about that control, so when a contextual pattern and the
description itself report the same absent control on the same component, the
analyzer keeps one finding and folds the others' CWE, OWASP, and MITRE mappings
into it. Without `controls`, the same gap can be reported more than once.

**Keep CWE and OWASP consistent.** Where a rule omits an OWASP category, one is
derived from its primary CWE by `owasp_for` in
[`../engine/owasp_mapping.py`](../engine/owasp_mapping.py). Where a rule declares
both, make them agree with that mapping: a rule stating a logging CWE but an
access-control category will contradict the rest of the report. The equivalent
generic weakness rules are held to this by
`test_declared_owasp_agrees_with_the_cwe_mapping`.

## After changing a pack

Reload the database and rebuild the local artifacts that depend on it:

```bash
cd backend
python scripts/retrain_local_models.py
```

`POST /admin/retrain-local-models` does the same thing on a running server. The
classifier's training corpus is derived from these packs, so skipping this step
leaves it stale and the analyzer will say so.

Then confirm the change did what you meant:

```bash
python -m pytest -q
python scripts/evaluate_threat_model.py
```
