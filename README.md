# AI Threat Modeler

An advanced, AI-powered threat modeling tool that automatically identifies security vulnerabilities from system architecture descriptions. Built with React + Vite frontend and FastAPI backend.

## 🎯 Key Features

### Intelligent Threat Detection
- **10+ Threat Categories**: Detects GraphQL DoS, webhook validation, XSS, CSV injection, CORS misconfigurations, JWT validation, and more
- **Known Issues Processing**: Automatically converts explicitly stated vulnerabilities into high-confidence threats
- **STRIDE Framework**: Maps all threats to STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- **Compliance Mapping**: Links threats to OWASP Top 10, CWE, and NIST 800-53 controls

### Enhanced Architecture Diagrams
- **Microservice Extraction**: Parses individual services from numbered lists and bullet points
- **Database Detection**: Identifies PostgreSQL, MongoDB, MySQL, Redis, Elasticsearch, and more
- **Third-Party Integrations**: Detects Stripe, PayPal, SendGrid, Twilio, FedEx, and other external services
- **Layered Visualization**: Color-coded zones (Frontend, API Layer, Services, Data Layer, External)
- **Trust Boundaries**: Highlights flows crossing security boundaries with dotted lines

### Interactive Dashboard
- **Risk Matrix**: 3x3 heat map showing threat severity vs. likelihood
- **Detailed Threat Table**: Comprehensive findings with evidence, mitigation steps, and attack simulations
- **Architecture Diagrams**: Auto-generated Mermaid.js diagrams with intelligent component grouping
- **Export Options**: PDF reports, JSON, and CSV downloads

## 🏗️ Architecture

```
Frontend (React + Vite)          Backend (FastAPI)
├── ThreatDashboard.jsx    ←→   ├── main.py
├── RiskMatrix.jsx               ├── engine/
└── ArchitectureDiagram.jsx      │   ├── parser.py (extracts components)
                                 │   ├── rules.py (evaluates threats)
                                 │   ├── analyzer.py (orchestrates analysis)
                                 │   └── mermaid_generator.py
                                 └── knowledge_base/
                                     └── threats.json (60+ threat rules)
```

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
```

## ▶️ Running the Application

### Start Backend Server
```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```
Backend will run at: `http://127.0.0.1:8000`

### Start Frontend Server
```bash
npm run dev
```
Frontend will run at: `http://localhost:5173/`

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
Click **Analyze System** to process your architecture.

### 3. Review Results
- **Architecture Diagram**: View the auto-generated layered diagram
- **Risk Matrix**: Identify high-priority threats
- **Threat Details**: Review evidence, severity, and mitigation steps
- **Compliance**: Check OWASP Top 10 and CWE mappings

### 4. Export Findings
- **PDF Report**: Comprehensive printable report
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
- 10+ threats detected
- Individual service nodes in diagram
- Separate database nodes (PostgreSQL, MongoDB, Redis)
- External integrations (Stripe, PayPal, SendGrid)
- High-confidence threats from Known Issues

## 📁 Project Structure

```
ai-threat-modeler/
├── src/                          # Frontend (React + Vite)
│   ├── components/
│   │   ├── ThreatDashboard.jsx   # Main dashboard
│   │   ├── RiskMatrix.jsx        # Risk visualization
│   │   └── ArchitectureDiagram.jsx
│   └── services/
│       └── api.js                # Backend API client
├── backend/                      # Backend (FastAPI)
│   ├── app/
│   │   ├── main.py               # FastAPI app
│   │   ├── engine/
│   │   │   ├── parser.py         # Architecture parser
│   │   │   ├── rules.py          # Threat rule engine
│   │   │   ├── analyzer.py       # Analysis orchestrator
│   │   │   └── mermaid_generator.py
│   │   ├── knowledge_base/
│   │   │   └── threats.json      # 60+ threat rules
│   │   └── models.py             # Data models
│   └── requirements.txt
└── README.md
```

## 🛡️ Threat Detection Capabilities

### Supported Threat Types
- **Authentication**: JWT validation, weak auth, session management
- **Injection**: SQL, NoSQL, CSV formula injection
- **API Security**: GraphQL DoS, rate limiting, webhook validation
- **Web Security**: XSS, CORS misconfigurations, CSRF
- **Data Protection**: Encryption at rest, PII exposure, backup security
- **Infrastructure**: Network segmentation, VPN, bastion hosts
- **Third-Party**: Payment processor integration, external API security

### Architecture Components Detected
- **Frontend**: WebClient, Mobile Apps, CDN
- **API Layer**: API Gateway, Load Balancer
- **Services**: Individual microservices with tech stacks
- **Databases**: PostgreSQL, MongoDB, MySQL, Redis, Elasticsearch, DynamoDB, Redshift
- **External**: Stripe, PayPal, SendGrid, Twilio, FedEx, UPS, Auth0, Okta

## 🔧 API Endpoints

- `POST /analyze`: Analyze architecture description
  - Request: `{ "architecture_description": "...", "project_name": "..." }`
  - Response: Threats, diagram, risk score

- `GET /health`: Health check
- `GET /docs`: Interactive API documentation (Swagger UI)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

[Add your license here]

## 🙏 Acknowledgments

Built with:
- React + Vite
- FastAPI
- NetworkX (graph analysis)
- Mermaid.js (diagrams)
- STRIDE threat modeling framework

