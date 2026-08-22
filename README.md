# Aegis Threat

Aegis Threat is a local React and FastAPI application for building technical threat models from architecture descriptions and uploaded design documents. It combines deterministic security rules, STRIDE coverage, local semantic search, optional LLM review, attack-path analysis, compliance mappings, and report exports.

The deterministic engine remains the source of published findings. Semantic models and optional LLMs rank candidates, identify gaps, and raise review questions; they do not silently create confirmed risks.

## What it does

- Parses components, assets, data flows, trust boundaries, assumptions, and known issues from text, Markdown, DOCX, PDF, JSON, YAML, and related text formats.
- Runs `fast`, `standard`, or `deep` analysis against web, API, identity, cloud, container, supply-chain, payment, healthcare, AI, LLM, agent, and MCP threat packs.
- Maps findings to STRIDE, affected components and flows, root causes, attack scenarios, evidence, mitigations, and compliance references.
- Produces Mermaid architecture diagrams, attack routes, missing-information questions, coverage summaries, and change summaries.
- Supports SaaS, fintech, healthcare, AI, platform, and general domain profiles.
- Includes an analyst workbench for notes, triage, ownership, action-register export, and local analysis assistance.
- Exports Markdown, JSON, CSV, PNG, and PDF reports.

## Repository layout

```text
src/                         React frontend
  components/
  hooks/
  services/
  utils/
backend/
  app/
    data/                    technology catalog: vendors, types, control domains
    engine/                  parsing and threat-analysis pipeline
    knowledge_base/          modular threat packs
    services/                document and external LLM integrations
    main.py                  FastAPI application
    models.py                API and analysis contracts
  scripts/                   evaluation, retraining, dataset, and probe tools
  tests/
```

Inside the engine, the passes that read prose and the passes that read the graph
are kept apart:

| Module | Responsibility |
| --- | --- |
| `prose.py` | Where sentences and clauses really begin and end |
| `source_index.py` | Which document, page and line a statement came from |
| `flow_extraction.py` | Which data flows a description states, and in which direction |
| `control_statements.py` | Whether a control is claimed or denied, and about what |
| `graph.py` | Reachability and how data classification travels |
| `parser.py` | Assembles the canonical architecture from all of the above |
| `stride_coverage_engine.py` | Assesses every element against every STRIDE category |
| `risk_scoring.py` | Turns exposure, classification, and reach into a severity |
| `attack_path_engine.py` | Routes from an entry point to a finding, and onward |

## How it reads an architecture

Everything downstream depends on the model built from your description, so it is
worth knowing what the parser takes from the words you write.

**Flows are either stated or assumed, and always labelled.** A flow the
description states is modelled as written, carries the sentence that states it,
and is marked `origin: stated`. Where a component is left unconnected, a
type-based template supplies one flow so the component is in scope; that flow is
marked `origin: assumed`, carries the assumption in plain words, and is drawn as
a guess in the diagram. Templates only fill in for components whose connections
were left unsaid, so no component ends up with a guessed path alongside one you
described.

**A component is named once and referred to loosely afterwards.** Introduce "a
Node.js REST API" and later sentences can say "the API" or "the backend". A bare
role noun resolves only when exactly one component can answer to it; where two
could, both keep their full names rather than the tool guessing between them.

**Each weakness belongs in its own clause.** These are read as two claims about
two components:

```text
The portal has no MFA and the ingestion bucket is not encrypted at rest.
```

A conjunction is treated as a new claim only when what follows has both a subject
and a predicate, so a list of destinations stays one statement:

```text
The API sends records to the database and the ingestion bucket.
```

**A list of verbs keeps the subject it was given.** All three of these belong to
the API, and all three flows are extracted:

```text
The API authenticates staff against Azure AD, stores patient records in a
PostgreSQL database, and uploads scanned documents to an S3 ingestion bucket.
```

**Data classification travels with the data.** Saying "patient records" once
classifies that store as PHI, and every component the records flow through
inherits it, so the API in front of the database is scored as handling PHI without
you having to repeat it. Each component records whether its classification was
`stated` or `propagated`, and a propagated value never overrides a stated one.

Anything the description does not say becomes a question rather than a finding.
The gaps report names components whose connections were guessed, and the evidence
requests list every unresolved control.

## Where a finding came from

Uploaded documents and the description you type are assembled into one text
before parsing, so `source_index.py` rebuilds the mapping from that text back to
its sources. Every piece of evidence is then cited with the document, the page or
table, and the line that stated it:

```text
- Evidence:
  - [architecture_input] storage.md, page 4, line 2: The S3 receipts bucket is not encrypted at rest.
```

Each evidence record carries `document`, `locator`, `line`, and a preformatted
`cite`, and the risk details panel lists them under "Cited in". A component also
records the `source_document` that named it, and `source_attribution` in the
architecture metadata counts what each source contributed, which answers whether
one document is carrying the model on its own.

A claim that no source states is marked as inference and cites nothing, rather
than naming a document that happens to have been uploaded. Document headers,
page markers, and section separators are never quoted as design statements, so a
component matched only against a filename such as `orders-service-design.docx`
is treated as inferred rather than as stated by the design.

## How risk is scored

Severity comes from one transparent calculation, published with each report under
`risk_methodology` (currently `technical-v3`). Every finding carries the inputs
that produced its score in `risk_factors`:

- **Reachability**: **exposure** and **privileges required** combined, then capped.
  Every producer derives both from the same trust level, so scoring each at full
  weight let one fact — whether the component faces the internet — decide the
  severity band by itself. The cap keeps the weaker signal meaningful without
  counting the same fact twice.
- **Control state**: whether the control the finding concerns is absent, present,
  or simply not stated. This replaced exploit complexity, which read `medium` on
  97% of findings because a design description carries no evidence of how hard a
  weakness is to exploit. A confirmed gap now outranks an unanswered question,
  which is the distinction a reader actually acts on.
- Whether the finding **crosses a trust boundary**. For a component-scoped finding
  only inbound crossings count: arriving from another trust zone is attack
  surface, whereas calling out to a less trusted place is covered by impact.
- **Asset sensitivity**, taken as the most sensitive classification carried by the
  finding's components and flows.
- **Blast radius**: the finding's own elements plus everything reachable from them
  over the flow graph. It counts toward impact once it covers roughly half the
  architecture, so the term means something in a large design as well as a small
  one.
- **Compensating controls**, up to two, which lower the result.

**Evidence confidence is reported but does not raise likelihood.** How sure we are
that a finding is real and how likely an attacker is to succeed are different
questions, and the Confirmed/Potential tier already carries the first. Findings
resting on an assumed flow are discounted separately.

The calculation runs again each time the architecture is refined, and is free to
fall as well as rise, so a control discovered on a later pass can lower a severity.
A severity authored by a curated rule, a taxonomy entry, or an analyst statement
is a floor the calculation may raise but not lower — a general formula cannot
rederive that, say, a privileged pod with a mounted service account token is
critical. `severity_source` records which applied, and `reported_severity` keeps
the original claim.

Confirmed findings need direct evidence from source, IaC, or the architecture
description. One absent control on one component is reported once: where a
knowledge-base rule, a contextual pattern, and the description itself all report
the same thing, the most specific finding is kept and the others' CWE, OWASP, and
MITRE mappings are folded into it.

Unspecified controls are raised as a capped, risk-ranked set of Potential threats
rather than one per STRIDE category, so a large architecture does not produce five
near-identical questions about whichever element happened to rank highest. The
cap is reported in the coverage `guarantee`, and every cell left out is still
listed in the evidence requests.

Each confirmed finding also carries an `attack_path`: the route from a modelled
entry point, hop by hop, with each hop marked `explicit` or `inferred`, plus the
sensitive stores reachable beyond the target. Where no route exists, the path says
so instead of being omitted.

## Requirements

- Node.js 18 or newer
- npm 9 or newer
- Python 3.10 or newer
- `python` and `pip` available on `PATH`

## Install and run

Install both sets of dependencies:

```bash
npm install
cd backend
pip install -r requirements.txt
cd ..
```

Start the frontend and backend together:

```bash
npm start
```

The application will be available at:

- Frontend: [http://localhost:5173](http://localhost:5173)
- Backend: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- API documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

For development, run each service in its own terminal:

```bash
# Terminal 1
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

```bash
# Terminal 2
npm run dev -- --host 127.0.0.1 --port 5173
```

Windows helper scripts are also included:

```powershell
.\start.ps1
```

```bat
start.bat
```

If Python is not found, add it to `PATH` before starting the backend.

## Use it on your local network

Find the machine's IPv4 address with `ipconfig`, then bind both services to all interfaces:

```bash
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

PowerShell:

```powershell
$env:VITE_API_URL="http://<YOUR_IP>:8000"
$env:VITE_WS_URL="ws://<YOUR_IP>:8000"
npm run dev -- --host 0.0.0.0 --port 5173
```

Command Prompt:

```bat
set VITE_API_URL=http://<YOUR_IP>:8000
set VITE_WS_URL=ws://<YOUR_IP>:8000
npm run dev -- --host 0.0.0.0 --port 5173
```

Open `http://<YOUR_IP>:5173` from the other device. If it cannot connect, allow ports `5173` and `8000` through the host firewall.

## Configuration

Frontend variables:

- `VITE_API_URL`: REST API base URL
- `VITE_WS_URL`: WebSocket base URL

Backend variables:

- `ENVIRONMENT`: `development` or `production`
- `ALLOWED_ORIGINS`: comma-separated CORS allowlist
- `ADMIN_API_TOKEN`: protects administrative endpoints when set
- `AEGIS_THREAT_ENABLE_TRANSFORMERS`: enables local transformer NER when its model is already cached
- `AEGIS_THREAT_NER_MODEL`: Hugging Face model ID used for NER enrichment
- `AEGIS_THREAT_LOCAL_SLM_MODEL`: locally available checkpoint for the review-only structured SLM
- `AEGIS_THREAT_LOCAL_SLM_TASK`: Transformers pipeline task; defaults to `text2text-generation`
- `AEGIS_THREAT_RERANKER_MODEL`: locally cached cross-encoder for second-stage retrieval; the built-in security-feature reranker is used when unset

The default local stack uses `blingfire` for segmentation, `all-MiniLM-L6-v2` through `sentence-transformers` for semantic retrieval, FAISS for vector search, and a scikit-learn STRIDE classifier. No spaCy model is required.

## API

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/analyze` | `POST` | Analyze an architecture description |
| `/analyze-documents` | `POST` | Analyze uploaded design documents |
| `/analyze-iac` | `POST` | Analyze Docker Compose or Kubernetes-style IaC |
| `/analyze-with-llm` | `POST` | Add an external LLM challenger with retrieved context |
| `/validate-api-key` | `POST` | Validate a provider API key |
| `/health` | `GET` | Check API and local ML readiness |
| `/cache` | `DELETE` | Clear analysis caches; admin protected |
| `/admin/retrain-local-models` | `POST` | Reload the knowledge base and retrain local artifacts |
| `/ws/analyze` | `WS` | Stream analysis progress |

Example request:

```json
{
  "project_name": "Payments Platform",
  "description": "React frontend, API gateway, JWT auth, PostgreSQL, Redis, S3, and Stripe integration.",
  "use_local_slm": true,
  "analysis_mode": "standard",
  "domain_profile": "fintech"
}
```

Important response fields include `threats`, `score`, `architecture`, `diagram`, `report_markdown`, `attack_chains`, `architecture_insights`, `coverage`, `risk_methodology`, `diff_summary`, `follow_up_questions`, `review_summary`, and `domain_context`.

Within each threat, `risk_factors` holds the inputs behind the score,
`evidence_details` holds each statement with the `document`, `locator`, `line`,
and `cite` it came from, `explanation.component_flows` holds the flows touching
the affected component, `explanation.flow_context` says why a finding has no flow
of its own, and `attack_path` holds the route in and the data reachable beyond it.

## Knowledge base and local models

Threat packs live in [`backend/app/knowledge_base`](backend/app/knowledge_base). They cover cloud and infrastructure, web and APIs, authentication and identity, containers and Kubernetes, software supply chain, databases, payments, healthcare, and AI/LLM threats including prompt injection, jailbreaks, data poisoning, model extraction, inference abuse, and denial of ML service.

A rule's `resource_types` are matched against component types without regard to
spacing or naming style, so `StorageBucket`, `Storage Bucket`, and `Object Storage`
all match the same components and a rule does not silently fail to fire over a
space.

Semantic retrieval uses domain-specific indexes, component and cloud filters, hard-negative rejection, and second-stage reranking. The STRIDE classifier is advisory. When a classifier or semantic candidate disagrees with a deterministic result, the report keeps the evidence-backed result and creates a review question.

Reload the knowledge base and rebuild local artifacts after changing a threat pack:

```bash
cd backend
python scripts/retrain_local_models.py
```

The same operation is available through `POST /admin/retrain-local-models`.

## Tests and probes

```bash
npm test          # backend suite without the slow tests, across processes
npm run test:all  # the whole backend suite
npm run lint      # frontend
```

Most of the suite's wall time is engine import rather than assertions, which is
why the fast lane parallelizes.

The probes in `backend/scripts` print what a change did to a real analysis, which
assertions alone do not show. Run them after touching the parser, the risk model,
or the coverage engine:

```bash
cd backend
python scripts/flow_probe.py      # stated versus assumed flows per scenario
python scripts/risk_probe.py      # classification, blast radius, boundary crossing
python scripts/path_probe.py      # which findings got an attack route, and how long
python scripts/severity_probe.py  # severity spread, to catch score inflation
```

## Evaluation and optional training

Run the release evaluation:

```bash
cd backend
python scripts/evaluate_threat_model.py
```

The gate measures overall and per-STRIDE recall, critical-threat recall, severity, component scope, evidence grounding, architecture accuracy, duplicate findings, false positives, technology hallucinations, retrieval ranking, hard-negative leakage, and classifier accuracy.

Build the reviewed instruction-tuning dataset with a named approver:

```bash
cd backend
python scripts/build_security_training_data.py --approved-by <review-group>
```

QLoRA training is optional and kept separate from the application dependencies:

```bash
pip install -r requirements-training.txt
python scripts/train_security_slm.py \
  --model <causal-model> \
  --dataset training/security_threat_training_v1.jsonl \
  --output training/output-adapter
```

The exporter rejects unnamed approval, and the trainer rejects unapproved records. A trained adapter is still a reviewer; deterministic evidence rules control confirmed findings and final publication.

## Report quality

Reports have three publication states:

- `ready`: final exports are available.
- `review`: assumptions or open questions remain, but exports are allowed.
- `blocked`: the architecture is invalid or confirmed findings contain unresolved evidence, scope, component, alias, or classification failures.

A document that could not be read in full marks the report for review rather than
blocking it, and names what was missed. Architecture diagrams are usually images,
and a PDF page with no extractable text contributes nothing to the model, so
`unread_document_content` on the quality gate lists each document and the pages
left unread, and the report states them beside the scope counts they qualify.
Findings from the pages that were read are still published.

The dashboard supports finding states such as open, mitigated, accepted, and false positive. Mermaid labels and IDs are sanitized before rendering, and frontend response normalization is handled in [`src/utils/analysisMapper.js`](src/utils/analysisMapper.js).

## License

NA
