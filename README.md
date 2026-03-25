# Aegis Threat

Aegis Threat is a React + FastAPI application that turns architecture descriptions into practical threat models. It combines rule-based analysis, hybrid NLP parsing, local semantic retrieval, optional LLM augmentation, attack-chain reasoning, compliance mappings, and exportable reports.

## Highlights

- `fast`, `standard`, and `deep` analysis modes
- Automatic component, flow, trust-boundary, and assumption extraction
- Local semantic matching and retrainable STRIDE-oriented intelligence
- Optional OpenAI, Claude, and Gemini augmentation
- Coverage summaries, diff summaries, and export-ready reports
- Guided follow-up questions that help reduce model uncertainty
- Explainable findings with impacted components and remediation priority
- Review workflow cards for triaging findings in the dashboard
- Domain-aware analysis profiles for SaaS, fintech, healthcare, AI, and platform systems
- Analyst workbench with action-register export, architecture notes, and a local analysis copilot
- Mermaid architecture diagrams with hardened label and ID sanitization

## What The App Produces

- Threat findings with STRIDE categories and mitigation guidance
- Parsed architecture model with components and data flows
- Architecture diagram output in Mermaid
- Attack chain summaries
- Coverage and assumption metadata
- Follow-up questions tied to assumptions and likely gaps
- Change summaries with score, component, flow, and severity deltas
- Domain guidance with priority controls and high-risk review areas
- Analyst workbench output for ownership, notes, and action export
- Markdown, JSON, CSV, and PDF exports

## Project Structure

```text
src/
  components/
  config.js
  hooks/
  services/
  utils/
backend/
  app/
    data/
    engine/
    knowledge_base/
    services/
    main.py
    models.py
  scripts/
  tests/
```

## Requirements

### Frontend

- Node.js 18+
- npm 9+

### Backend

- Python 3.10+
- pip
- Python should be available on your `PATH` as `python`

## Quick Start

1. Install frontend dependencies:

```bash
npm install
```

2. Install backend dependencies:

```bash
cd backend
pip install -r requirements.txt
cd ..
```

3. Start both frontend and backend (single command):

```bash
npm start
```

4. Open:

- Frontend: [http://localhost:5173](http://localhost:5173)
- Backend: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Install

### Frontend

```bash
npm install
```

### Backend

```bash
cd backend
pip install -r requirements.txt
```

The backend uses a hybrid NLP stack built from `blingfire`, `transformers`, `sentence-transformers`, and domain rules. No separate spaCy model download is required.

## Run Locally

### Option A: Start both at once

```bash
npm start
```

This uses the `start` script from [package.json](C:/Users/Ankit/Documents/codex/ai-threat-modeler/package.json) and launches:

- frontend on port `5173`
- backend on port `8000`

### Option B: Start backend and frontend separately (recommended for development)

Run these in two terminals.

Terminal 1 (Backend):

```bash
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Terminal 2 (Frontend):

```bash
npm run dev -- --host 127.0.0.1 --port 5173
```

### Option C: Run on your system IP (LAN / same Wi-Fi)

Use this if you want to open the tool from another device (phone, tablet, another laptop) on your local network.

1. Find your system IP (example: `192.168.1.25`).

Windows:

```powershell
ipconfig
```

Look for `IPv4 Address`.

2. Start backend on all interfaces:

```bash
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

3. Start frontend on all interfaces and point it to your IP.

PowerShell:

```powershell
$env:VITE_API_URL="http://<YOUR_IP>:8000"
$env:VITE_WS_URL="ws://<YOUR_IP>:8000"
npm run dev -- --host 0.0.0.0 --port 5173
```

CMD:

```bat
set VITE_API_URL=http://<YOUR_IP>:8000
set VITE_WS_URL=ws://<YOUR_IP>:8000
npm run dev -- --host 0.0.0.0 --port 5173
```

4. Open from another device:

- Frontend: `http://<YOUR_IP>:5173`
- Backend API docs: `http://<YOUR_IP>:8000/docs`

5. If it does not open, allow ports `5173` and `8000` in your firewall.

### Windows helper scripts

```powershell
.\start.ps1
```

```bat
start.bat
```

If `python` is not recognized on Windows, fix your Python installation or add Python to `PATH` first. The backend will not start until `python -m uvicorn ...` works from your terminal.

Default URLs:

- Frontend: [http://localhost:5173](http://localhost:5173)
- Backend: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Configuration

### Frontend env

- `VITE_API_URL`: override REST API base URL
- `VITE_WS_URL`: override WebSocket base URL

### Backend env

- `ENVIRONMENT`: `development` or `production`
- `ALLOWED_ORIGINS`: comma-separated CORS allowlist
- `ADMIN_API_TOKEN`: protects admin endpoints when set
- `AEGIS_THREAT_ENABLE_TRANSFORMERS`: set to `true` to enable local transformer NER if the model is already available in cache
- `AEGIS_THREAT_NER_MODEL`: optional Hugging Face model id for targeted NER enrichment

## API Surface

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | `POST` | Analyze a text-based architecture description |
| `/analyze-iac` | `POST` | Analyze Docker Compose or Kubernetes-style IaC input |
| `/analyze-with-llm` | `POST` | Run LLM-augmented analysis with retrieval context |
| `/validate-api-key` | `POST` | Validate provider API keys |
| `/health` | `GET` | Health status and local NLP/ML readiness |
| `/cache` | `DELETE` | Clear cached analysis results, admin protected |
| `/admin/retrain-local-models` | `POST` | Reload the KB and retrain local semantic/classifier artifacts |
| `/ws/analyze` | `WS` | Streaming analysis endpoint |

### Example request

```json
{
  "project_name": "Payments Platform",
  "description": "React frontend, API gateway, JWT auth, PostgreSQL, Redis, S3, and Stripe integration.",
  "use_local_slm": true,
  "analysis_mode": "standard",
  "domain_profile": "fintech"
}
```

### Result fields

Common response fields include:

- `threats`
- `score`
- `architecture`
- `architecture_diagram`
- `report_markdown`
- `attack_chains`
- `architecture_insights`
- `coverage`
- `diff_summary`
- `follow_up_questions`
- `review_summary`
- `domain_context`

## Knowledge Base And Local Intelligence

The backend auto-loads modular JSON threat packs from [backend/app/knowledge_base](C:/Users/Ankit/Documents/codex/ai-threat-modeler/backend/app/knowledge_base). Current packs include:

- cloud and infrastructure threats
- web and API threats
- auth and identity threats
- container and Kubernetes threats
- supply-chain threats
- AI and LLM threats, including MITRE ATLAS-backed prompt injection, jailbreak, prompt extraction, inference exfiltration, poisoning, and denial-of-ML-service scenarios
- domain-specific packs

The local intelligence layer can be rebuilt after KB changes with:

```bash
cd backend
python scripts/retrain_local_models.py
```

Or through:

```text
POST /admin/retrain-local-models
```

## Notes

- `fast` mode skips the heaviest optional analysis stages for lower latency.
- Admin cache clearing and local retraining use `ADMIN_API_TOKEN` when configured.
- Mermaid diagram generation now sanitizes node IDs, labels, and edge labels to reduce render failures from unusual component names or metadata.
- The dashboard includes a lightweight review workflow so teams can mark findings as open, mitigated, accepted, or false positive during triage.
- The static analysis intake now supports domain profiles so the UI can highlight domain-specific control priorities and risk areas.
- The analyst workbench adds a lightweight local copilot, component note-taking, and exportable action registers.
- Hybrid NLP uses `blingfire` for fast segmentation, `sentence-transformers` for semantic matching, and optional `transformers` pipelines for targeted NER/classification.
- Frontend result mapping is centralized in [analysisMapper.js](C:/Users/Ankit/Documents/codex/ai-threat-modeler/src/utils/analysisMapper.js).
- WebSocket and API URLs are environment-aware through [config.js](C:/Users/Ankit/Documents/codex/ai-threat-modeler/src/config.js).

## License

NA
