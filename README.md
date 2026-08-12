# Aegis Threat

Aegis Threat is a local React and FastAPI application for building technical threat models from architecture descriptions and uploaded design documents. It combines deterministic security rules, STRIDE coverage, local semantic search, optional LLM review, attack-path analysis, compliance mappings, and report exports.

The deterministic engine remains the source of published findings. Semantic models and optional LLMs rank candidates, identify gaps, and raise review questions; they do not silently create confirmed risks.

## What it does

- Parses components, assets, data flows, trust boundaries, assumptions, and known issues from text, Markdown, DOCX, PDF, JSON, YAML, and related text formats.
- Runs `fast`, `standard`, or `deep` analysis against web, API, identity, cloud, container, supply-chain, payment, healthcare, AI, LLM, agent, and MCP threat packs.
- Maps findings to STRIDE, affected components and flows, root causes, attack scenarios, evidence, mitigations, and compliance references.
- Produces Mermaid architecture diagrams, attack paths, missing-information questions, coverage summaries, and change summaries.
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
    engine/                  parsing and threat-analysis pipeline
    knowledge_base/          modular threat packs
    services/                document and external LLM integrations
    main.py                  FastAPI application
    models.py                API and analysis contracts
  scripts/                   evaluation, retraining, and dataset tools
  tests/
```

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

Important response fields include `threats`, `score`, `architecture`, `diagram`, `report_markdown`, `attack_chains`, `architecture_insights`, `coverage`, `diff_summary`, `follow_up_questions`, `review_summary`, and `domain_context`.

## Knowledge base and local models

Threat packs live in [`backend/app/knowledge_base`](backend/app/knowledge_base). They cover cloud and infrastructure, web and APIs, authentication and identity, containers and Kubernetes, software supply chain, databases, payments, healthcare, and AI/LLM threats including prompt injection, jailbreaks, data poisoning, model extraction, inference abuse, and denial of ML service.

Semantic retrieval uses domain-specific indexes, component and cloud filters, hard-negative rejection, and second-stage reranking. The STRIDE classifier is advisory. When a classifier or semantic candidate disagrees with a deterministic result, the report keeps the evidence-backed result and creates a review question.

Reload the knowledge base and rebuild local artifacts after changing a threat pack:

```bash
cd backend
python scripts/retrain_local_models.py
```

The same operation is available through `POST /admin/retrain-local-models`.

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

The dashboard supports finding states such as open, mitigated, accepted, and false positive. Mermaid labels and IDs are sanitized before rendering, and frontend response normalization is handled in [`src/utils/analysisMapper.js`](src/utils/analysisMapper.js).

## License

NA
