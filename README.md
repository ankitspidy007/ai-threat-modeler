# AI Threat Modeler (AITM) v2.0

AI Threat Modeler is a React + FastAPI application for turning architecture descriptions into practical threat models. It combines rule-based analysis, NLP-assisted parsing, local semantic retrieval, optional LLM augmentation, attack-chain reasoning, compliance mappings, and exportable reports.

## What It Does

- Parses architecture descriptions, IaC manifests, and known-issue sections
- Builds component and data-flow models automatically
- Detects threats using STRIDE-oriented rules plus semantic matching
- Produces confirmed risks, potential risks, assumptions, trust-boundary summaries, and coverage metadata
- Supports optional OpenAI, Claude, and Gemini augmentation with RAG context
- Exports Mermaid diagrams, Markdown reports, JSON, CSV, and PDF

## Key Capabilities

### Core Analysis
- Rule-based threat detection using a modular knowledge base
- `fast`, `standard`, and `deep` analysis modes
- Known-issue promotion into high-confidence findings
- Confidence-gated severity, tiering, and STRIDE normalization
- Delta summaries between consecutive analyses of the same project

### NLP and Local Intelligence
- spaCy-based entity extraction and security-signal parsing
- Component and flow extraction from natural-language descriptions
- Local semantic threat discovery using sentence embeddings
- Local STRIDE and severity refinement support
- Retrainable local semantic/classifier artifacts from the knowledge base

### Reporting and Dashboard
- Left-side persistent dashboard menu
- Clean glass-style UI with dark mode
- Risk matrix and STRIDE chart
- Coverage and assumption cards
- Architecture diagram rendering with Mermaid
- Markdown, PDF, JSON, and CSV export

## Project Structure

```text
src/
  components/
  hooks/
  services/
  utils/
backend/
  app/
    engine/
    knowledge_base/
    services/
    data/
    main.py
    models.py
  tests/
  scripts/
```

## Requirements

### Frontend
- Node.js 18+
- npm 9+

### Backend
- Python 3.8+
- pip

## Installation

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

## Running Locally

### One command

```bash
npm start
```

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

Frontend default URL: [http://localhost:5173](http://localhost:5173)  
Backend default URL: [http://127.0.0.1:8000](http://127.0.0.1:8000)

## Environment and Config

### Frontend

- `VITE_API_URL` - override API base URL
- `VITE_WS_URL` - override WebSocket base URL

### Backend

- `ENVIRONMENT` - `development` or `production`
- `ALLOWED_ORIGINS` - comma-separated origin list for production CORS
- `ADMIN_API_TOKEN` - required to use admin endpoints in production, and also in development if set

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | `POST` | Text architecture analysis |
| `/analyze-iac` | `POST` | Docker Compose / Kubernetes analysis |
| `/analyze-with-llm` | `POST` | LLM-enhanced analysis with RAG |
| `/validate-api-key` | `POST` | Validate provider API key |
| `/health` | `GET` | Health and ML capability status |
| `/cache` | `DELETE` | Clear cached results, admin protected |
| `/admin/retrain-local-models` | `POST` | Reload KB and retrain local intelligence, admin protected |
| `/ws/analyze` | `WS` | Streaming analysis progress |
| `/docs` | `GET` | Swagger UI |

### Analyze request example

```json
{
  "project_name": "Payments Platform",
  "description": "React frontend, API gateway, JWT auth, PostgreSQL, Redis, S3, and Stripe integration.",
  "use_local_slm": true,
  "analysis_mode": "standard"
}
```

### Result highlights

Results may include:

- `threats`
- `score`
- `architecture`
- `report_markdown`
- `attack_chains`
- `ml_enhanced`
- `architecture_insights`
- `coverage`
- `diff_summary`

## Knowledge Base

The backend loads modular JSON threat packs automatically from `backend/app/knowledge_base/`, including:

- cloud-specific threat packs
- OWASP web and API packs
- auth/authz threats
- container and Kubernetes threats
- supply-chain and infrastructure threats
- AI/LLM threats
- domain-specific threats

## Notes

- The local semantic engine and classifier can be rebuilt with `/admin/retrain-local-models`.
- The dashboard now surfaces assumptions and analysis coverage so missing architectural detail is easier to spot.
- In `fast` mode, the app skips the heaviest optional analysis stages for lower latency.

## Development Notes

- Frontend result mapping is centralized in [analysisMapper.js](C:/Users/Ankit/Documents/codex/ai-threat-modeler/src/utils/analysisMapper.js)
- WebSocket config is environment-aware through [config.js](C:/Users/Ankit/Documents/codex/ai-threat-modeler/src/config.js)
- Admin cache clear and retraining are protected by `ADMIN_API_TOKEN` when configured

## License

NA
