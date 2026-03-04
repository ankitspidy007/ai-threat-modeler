# AI Threat Modeler (AITM) v2.0

An advanced, AI-powered threat modeling tool that automatically identifies security vulnerabilities from system architecture descriptions. Built with React + Vite frontend and FastAPI backend, featuring **NLP-powered parsing (spaCy)**, **semantic threat matching (sentence-transformers + FAISS)**, **attack chain analysis (NetworkX)**, **ML-based severity classification**, STRIDE-based analysis, multi-LLM integration with RAG, and comprehensive compliance mapping.

## 🎯 Key Features

### 🧠 NLP & Deep Learning (NEW in v2.0)
- **spaCy NER**: Named Entity Recognition extracts technologies, services, and protocols from architecture text
- **Dependency Parsing**: Linguistic analysis identifies data flows from natural language descriptions
- **Semantic Threat Matching**: Sentence-transformer embeddings + FAISS vector search find threats that keyword rules miss
- **Zero-Shot STRIDE Classification**: Classifies novel threats into STRIDE categories using embedding similarity
- **Attack Chain Analysis**: NetworkX-based threat graph modeling discovers multi-step attack paths and critical chokepoints
- **ML Severity Classification**: Embedding-based classifier refines threat severity with architectural context
- **Semantic Deduplication**: Cosine similarity replaces naive keyword overlap for smarter threat merging
- **RAG for LLM**: Retrieval-Augmented Generation injects relevant KB threats into LLM prompts

### Intelligent Threat Detection
- **Comprehensive Knowledge Base**: 10+ modular threat databases covering cloud (AWS, Azure, GCP), OWASP Top 10, authentication/authorization, containers/Kubernetes, supply chain, infrastructure, and emerging threats
- **Known Issues Processing**: Automatically converts explicitly stated vulnerabilities into high-confidence threats
- **STRIDE Framework**: Maps all threats to STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- **Two-Tier Classification**: Separates findings into Confirmed Risks (verified evidence) and Potential Risks (assumption-based)
- **Confidence-Gated Severity**: Low-confidence findings capped at Medium severity; high-confidence can be High or Critical

### Compliance & Framework Mappings
- **CWE**: Common Weakness Enumeration IDs linked to each threat
- **MITRE ATT&CK**: Technique IDs mapped to detected threats
- **OWASP Top 10**: Direct mapping to OWASP 2021 categories
- **NIST 800-53**: Security control references for each finding
- Interactive badges displayed on the dashboard with links to external resources

### Multi-LLM Integration
- **OpenAI GPT**: Enhance analysis with GPT models
- **Anthropic Claude**: Use Claude for deeper threat insights
- **Google Gemini**: Leverage Gemini for AI-enhanced detection
- **API Key Configuration**: Provide your API key through the dashboard — no server-side storage
- **Merged Results**: LLM findings are merged and deduplicated with rule-based analysis

### Enhanced Architecture Diagrams
- **Microservice Extraction**: Parses individual services from numbered lists and bullet points
- **Database Detection**: Identifies PostgreSQL, MongoDB, MySQL, Redis, Elasticsearch, and more
- **Third-Party Integrations**: Detects Stripe, PayPal, SendGrid, Twilio, FedEx, and other external services
- **Layered Visualization**: Color-coded zones (Frontend, API Layer, Services, Data Layer, External)
- **Trust Boundaries**: Highlights flows crossing security boundaries with dotted lines

### Interactive Dashboard
- **Risk Matrix**: 3×3 heat map showing threat severity vs. likelihood
- **STRIDE Distribution Chart**: Visual bar chart of threats by STRIDE category
- **Remediation Progress**: Circular progress tracker for fixed vs. total risks
- **Threat Cards**: Detailed findings with evidence, mitigation steps, compliance badges, and affected components
- **Architecture Diagrams**: Auto-generated Mermaid.js diagrams with intelligent component grouping
- **Dark Mode**: Full dark mode support with smooth transition
- **Analysis History**: Save and reload previous analyses from local storage

### Export Options
- **PDF Report**: Professional report with rendered architecture diagram, risk matrix, STRIDE chart, components table, data flows table, and individual threat details with compliance mappings
- **Markdown**: Full analysis report with 12+ sections (executive summary, scope, architecture, asset inventory, threats, risk matrix, compliance mapping, metrics, risk treatment, testing plan, appendices)
- **JSON**: Structured data for automation and CI/CD integration
- **CSV**: Import into Jira, Excel, or other project management tools

## 🏗️ Architecture

```
Frontend (React + Vite)            Backend (FastAPI + Python)
├── components/                    ├── app/
│   ├── ThreatDashboard.jsx        │   ├── main.py (API endpoints)
│   ├── ThreatInput.jsx            │   ├── models.py (Pydantic models)
│   ├── Sidebar.jsx                │   ├── engine/
│   ├── RiskMatrix.jsx             │   │   ├── parser.py (NLP-enhanced parser)
│   ├── StrideChart.jsx            │   │   ├── nlp_processor.py ★ spaCy NER
│   ├── AIAnalysis.jsx             │   │   ├── embedding_service.py ★ Embeddings
│   ├── AnalysisHistory.jsx        │   │   ├── semantic_matcher.py ★ Vector search
│   ├── Toast.jsx                  │   │   ├── attack_chain.py ★ Attack paths
│   └── ErrorBoundary.jsx         │   │   ├── rules.py (threat rule engine)
├── utils/                         │   │   ├── analyzer.py (ML-enhanced)
│   ├── pdfGenerator.js            │   │   ├── reporter.py (markdown reports)
│   └── storage.js                 │   │   ├── mermaid_generator.py
├── services/                      │   │   └── graph_builder.py
│   └── mockAi.js                  │   ├── services/
└── config.js                      │   │   ├── llm_analyzer.py (RAG + dedup)
                                   │   │   ├── openai_service.py
                                   │   │   ├── claude_service.py
                                   │   │   └── gemini_service.py
                                   │   ├── knowledge_base/
                                   │   │   ├── threats.json (legacy rules)
                                   │   │   ├── cloud_aws_threats.json
                                   │   │   ├── cloud_azure_threats.json
                                   │   │   ├── cloud_gcp_threats.json
                                   │   │   ├── owasp_web_top10.json
                                   │   │   ├── auth_authz_threats.json
                                   │   │   ├── container_k8s_threats.json
                                   │   │   ├── domain_threats.json
                                   │   │   └── loader.py
                                   │   └── data/
                                   │       ├── framework_mappings.json
                                   │       ├── compliance_mappings.json
                                   │       └── stride_colors.json
                                   ├── tests/
                                   │   └── test_nlp_dl.py (20 golden tests)
                                   └── requirements.txt
```

## ⚡ Quick Start

### Option A: Docker (Recommended for hosting)

```bash
# Clone the project
git clone <repository-url>
cd ai-threat-modeler

# Build and run with Docker Compose
docker compose up --build

# Or run in background
docker compose up --build -d
```

The app will be available at **http://localhost:8000** — both frontend and API served from a single container.

```bash
# Standalone Docker (without Compose)
docker build -t aitm .
docker run -p 8000:8000 aitm

# Custom port
docker run -p 3000:8000 aitm             # Access at http://localhost:3000

# Stop
docker compose down
```

### Option B: Local Development

```bash
# Clone and navigate to the project
git clone <repository-url>
cd ai-threat-modeler

# Install dependencies
npm install
cd backend && pip install -r requirements.txt && cd ..
# Optional: Download spaCy model for full NLP features
# python -m spacy download en_core_web_sm

# Start the application (single command)
npm start
# OR use platform-specific scripts:
# .\start.ps1    (PowerShell)
# start.bat      (Windows Batch)
```

**The application will automatically:**
- Check and install any missing dependencies
- Start backend server on port 8000
- Start frontend server on port 5173
- Open in your default browser

## 📋 Prerequisites

- **Node.js**: Version 18 or higher
- **npm**: Version 9 or higher
- **Python**: Version 3.8 or higher
- **pip**: Latest version

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd ai-threat-modeler
```

### 2. Install Frontend Dependencies
```bash
npm install
```

### 3. Install Backend Dependencies
```bash
cd backend
pip install -r requirements.txt

# Optional: Download spaCy NLP model (enables NER-based entity extraction)
python -m spacy download en_core_web_sm
```

## ▶️ Running the Application

### Option 1: Single Command (Recommended)

**Windows (Batch Script):**
```bash
start.bat
```

**Windows (PowerShell):**
```powershell
.\start.ps1
```

**Cross-Platform (npm):**
```bash
npm start
```

This will automatically:
- Check and install dependencies if needed
- Start both backend and frontend servers
- Open the application in your browser

### Option 2: Manual Start (Separate Terminals)

**Terminal 1 — Start Backend Server:**
```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```
Backend will run at: `http://127.0.0.1:8000`

**Terminal 2 — Start Frontend Server:**
```bash
npm run dev
```
Frontend will run at: `http://localhost:5173/`

### Configuring Custom Ports

**PowerShell (with parameters):**
```powershell
# Use default ports (8000, 5173)
.\start.ps1

# Custom backend port only
.\start.ps1 -BackendPort 3000

# Custom frontend port only
.\start.ps1 -FrontendPort 3001

# Both custom ports
.\start.ps1 -BackendPort 3000 -FrontendPort 3001
```

**Batch Script (with arguments):**
```bash
# Use default ports
start.bat

# Custom backend port
start.bat --backend-port 3000

# Short form
start.bat -b 3000 -f 3001

# Show help
start.bat --help
```

**Environment Variables (.env file):**
```bash
# Copy the example file
cp .env.example .env

# Edit .env and set your preferred ports
BACKEND_PORT=3000
FRONTEND_PORT=3001
VITE_API_URL=http://127.0.0.1:3000
```

## 📖 Usage Guide

### 1. Describe Your System
Enter a detailed architecture description. For best results, include:
- **Microservices**: List services with tech stacks
  ```
  1. User Service (Node.js + Express): Handles authentication
  2. Payment Service (Java Spring Boot): Integrates with Stripe
  ```
- **Databases**: Specify types and purposes
  ```
  PostgreSQL database for user data
  MongoDB for order storage
  Redis cluster for session management
  ```
- **Third-Party Integrations**: Mention external services
  ```
  Integrates with Stripe for payments
  Sends emails via SendGrid
  ```
- **Known Issues**: List security concerns
  ```
  KNOWN ISSUES:
  - JWT signature is not validated
  - GraphQL has no depth limiting
  - CORS allows wildcard origins in production
  ```

### 2. Analyze System
Click **Analyze Threats** to process your architecture, or switch to the **AI Analysis** tab to use an LLM-enhanced analysis.

### 3. Review Results
- **Architecture Diagram**: View the auto-generated layered diagram
- **Risk Matrix**: Identify high-priority threats at a glance
- **Threat Cards**: Review evidence, severity, confidence, and mitigation steps
- **Compliance Badges**: Click CWE, MITRE ATT&CK, OWASP, and NIST badges for external references

### 4. Export Findings
- **PDF Report**: Professional report with rendered architecture diagram, risk matrix, STRIDE chart, and all threats with compliance mappings
- **Markdown**: Full analysis report with 12+ structured sections
- **JSON**: Structured data for automation
- **CSV**: Import into Jira, Excel, or other tools

## 🔍 Example Input

```
System: E-Commerce Platform

ARCHITECTURE:
1. User Service (Node.js + Express): Handles authentication with JWT
2. Product Catalog (Python FastAPI): GraphQL API for product search
3. Payment Service (Java Spring Boot): Integrates with Stripe and PayPal
4. Order Management (Go): Stores orders in MongoDB, sends confirmations via SendGrid

DATABASES:
- PostgreSQL with read replicas for user and product data
- MongoDB for order storage
- Redis cluster for session management

KNOWN ISSUES:
- JWT signature is not validated, only decoded
- GraphQL has no query depth limiting
- CORS allows wildcard origins in production
```

**Expected Output:**
- 8+ threats detected with severity and confidence levels
- Individual service nodes in architecture diagram
- Separate database nodes (PostgreSQL, MongoDB, Redis)
- External integrations (Stripe, PayPal, SendGrid)
- High-confidence threats from Known Issues
- CWE, MITRE ATT&CK, OWASP, and NIST compliance badges

## 🛡️ Threat Detection Capabilities

### Supported Threat Types
- **Authentication**: JWT validation, weak auth, session management, OAuth redirect manipulation
- **Injection**: SQL, NoSQL, CSV formula injection
- **API Security**: GraphQL DoS, rate limiting, webhook validation, SSRF
- **Web Security**: XSS, CORS misconfigurations, CSRF, broken access control
- **Data Protection**: Encryption at rest/transit, PII exposure, backup security, cryptographic failures
- **Infrastructure**: Network segmentation, VPN, bastion hosts, container escape
- **Cloud Security**: AWS, Azure, GCP-specific misconfigurations and threats
- **Supply Chain**: Compromised dependencies, CI/CD pipeline attacks
- **Third-Party**: Payment processor integration, external API security

### Knowledge Base Modules
| Module | Coverage |
|--------|----------|
| `threats.json` | Legacy rules (33 core threat patterns) |
| `cloud_aws_threats.json` | AWS-specific threats |
| `cloud_azure_threats.json` | Azure-specific threats |
| `cloud_gcp_threats.json` | GCP-specific threats |
| `owasp_web_top10.json` | OWASP Top 10 2021 |
| `auth_authz_threats.json` | Authentication & authorization |
| `container_k8s_threats.json` | Container & Kubernetes |
| `domain_threats.json` | Domain-specific threats |

### Architecture Components Detected
- **Frontend**: WebClient, Mobile Apps, CDN
- **API Layer**: API Gateway, Load Balancer
- **Services**: Individual microservices with tech stacks
- **Databases**: PostgreSQL, MongoDB, MySQL, Redis, Elasticsearch, DynamoDB, Redshift
- **External**: Stripe, PayPal, SendGrid, Twilio, FedEx, UPS, Auth0, Okta

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | `POST` | Analyze architecture (rule-based + semantic + attack chains) |
| `/analyze-with-llm` | `POST` | Analyze with LLM enhancement + RAG context + semantic dedup |
| `/validate-api-key` | `POST` | Validate an LLM provider API key |
| `/health` | `GET` | Health check, version, and ML feature status |
| `/cache` | `DELETE` | Clear the analysis cache |
| `/docs` | `GET` | Interactive Swagger UI documentation |

### Analyze Request
```json
{
  "project_name": "My Project",
  "description": "System architecture description..."
}
```

### Analyze with LLM Request
```json
{
  "project_name": "My Project",
  "description": "System architecture description...",
  "llm_provider": "openai",
  "api_key": "sk-...",
  "model": "gpt-4"
}
```

## 🔄 Dependency Management

This project uses **flexible versioning** to ensure you get security updates and new features while maintaining stability:

- **Frontend (NPM)**: Uses `^` notation — allows minor and patch updates automatically
- **Backend (Python)**: Uses range notation — allows updates within major versions

**Update to latest compatible versions:**
```bash
# Frontend
npm update

# Backend
cd backend && pip install --upgrade -r requirements.txt
```

**Check for security vulnerabilities:**
```bash
npm audit && npm audit fix
```

For detailed information, see [DEPENDENCY_MANAGEMENT.md](docs/DEPENDENCY_MANAGEMENT.md)

## 📚 Documentation

Comprehensive guides available in the `docs/` directory:

- **[PORT_CONFIGURATION.md](docs/PORT_CONFIGURATION.md)** — Custom port configuration
- **[DEPENDENCY_MANAGEMENT.md](docs/DEPENDENCY_MANAGEMENT.md)** — Dependency updates and management
- **[knowledge_base.md](docs/knowledge_base.md)** — Threat knowledge base details
- **[API Docs](http://127.0.0.1:8000/docs)** — Interactive Swagger UI documentation

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

[Add your license here]

## 🙏 Acknowledgments

Built with:
- React + Vite (Frontend)
- FastAPI + Pydantic (Backend)
- spaCy (NLP — NER + dependency parsing)
- sentence-transformers (Semantic embeddings)
- FAISS (Vector similarity search)
- NetworkX (Graph analysis + attack chain modeling)
- Mermaid.js (Architecture diagrams)
- jsPDF + html2canvas (PDF report generation)
- Tailwind CSS (Styling)
- Framer Motion (Animations)
- Lucide React (Icons)
- STRIDE threat modeling framework
- OWASP Top 10, CWE, MITRE ATT&CK, NIST 800-53 mappings
