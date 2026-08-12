# Threat-model evaluation corpus

`evaluation_corpus.json` is the release-gating benchmark for analysis quality.
Each scenario defines:

- architecture and domain input;
- stable finding IDs that must be detected;
- critical findings that must never regress;
- forbidden findings and components that indicate hallucination;
- required architecture terms and bounded topology counts;
- STRIDE categories that must be assessed.

Run the gate from `backend`:

```bash
python scripts/evaluate_threat_model.py --output threat-evaluation.json
```

Add a scenario when fixing a missed threat or false positive. Do not weaken an
expectation to make an engine change pass. Change an expected result only when
the architecture or reviewed security conclusion changed, and record that
reason in the pull request.

The seed corpus covers healthcare/FHIR, AWS serverless, multi-tenant SaaS,
AI/RAG/MCP, payments, web injection, Kubernetes supply chain, and resilience
and deletion workflows. It should grow with independently reviewed production
patterns; generated scenarios are not automatically trusted as ground truth.
