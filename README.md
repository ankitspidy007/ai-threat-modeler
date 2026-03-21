# Aegis Threat

Aegis Threat is a React + FastAPI application that turns architecture descriptions into practical threat models. It combines rule-based analysis, NLP-assisted parsing, local semantic retrieval, optional LLM augmentation, attack-chain reasoning, compliance mappings, and exportable reports.

## Highlights

- Left-side dashboard navigation with a cleaner analysis workspace
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

- Python 3.8+
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
python -m spacy download en_core_web_sm
cd ..
```

3. Start the app:

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
python -m spacy download en_core_web_sm
```

`en_core_web_sm` is optional but recommended. If it is unavailable, the backend falls back to regex/rule-based parsing for some NLP features.

## Run Locally

### Combined start

```bash
npm start
```

This uses the `start` script from [package.json](C:/Users/Ankit/Documents/codex/ai-threat-modeler/package.json) and launches:

- frontend on port `5173`
- backend on port `8000`

### Windows helpers

```powershell
.\start.ps1
```

```bat
start.bat
```

### Manual start

Backend:

```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
npm run dev
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
- AI and LLM threats
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
- Frontend result mapping is centralized in [analysisMapper.js](C:/Users/Ankit/Documents/codex/ai-threat-modeler/src/utils/analysisMapper.js).
- WebSocket and API URLs are environment-aware through [config.js](C:/Users/Ankit/Documents/codex/ai-threat-modeler/src/config.js).

## License

NA
