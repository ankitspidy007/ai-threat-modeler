# AITM (AI-based Threat Modeling)

AITM is a modern, AI-powered tool designed to help developers and security engineers generate threat models from simple system descriptions. It leverages keyword-based AI inference (extensible to LLMs) to identify potential security risks, map them to compliance standards, and visualize the findings.

## Key Features

- **AI Threat Inference**: Automatically identifies threats like SQL Injection, Weak Auth, and more based on architecture descriptions.
- **Interactive Dashboard**:
    - **Risk Matrix**: Visual 3x3 Heat Map of Threat Severity vs. Likelihood.
    - **Architecture Diagrams**: Auto-generated mermaid.js system diagrams.
    - **Detailed Table View**: Comprehensive findings including "Attack Simulation" narratives.
- **Compliance Mapping**: All threats are mapped to **OWASP Top 10** and **NIST 800-53** controls.
- **Rich PDF Reports**: Export extensive, landscape-oriented PDF reports for stakeholders.
- **Data Export**: Download findings as **JSON** or **CSV** for integration with Jira or other tools.
- **Secure by Design**: Client-side processing ensures your architecture data stays local (in this version).

## Prerequisites

Ensure you have the following installed on your local system:

- **Node.js**: Version 18 or higher
- **npm**: Version 9 or higher

## Installation

1. **Clone the repository** (if applicable) or navigate to the project folder.
2. **Install dependencies**:
   ```bash
   npm install
   ```

## Running the Application

1. **Start the development server**:
   ```bash
   npm run dev
   ```
2. **Open your browser** and navigate to the URL shown in the terminal (usually `http://localhost:5173/`).

## Usage Guide

1. **Describe System**: Enter a description of your system architecture (e.g., *"A public web app with a React frontend, Node.js API, and MongoDB database"*).
2. **Analyze**: Click the **Analyze System** button.
3. **Review Findings**:
    - Check the **Risk Matrix** for high-priority items.
    - Review the inferred **Compliance Mappings**.
    - Read the **Attack Simulations** to understand the exploit paths.
4. **Export**:
    - Click **Export PDF** for a printable report.
    - Click **JSON** or **CSV** to get raw data.

## Project Structure

- `src/components/RiskMatrix.jsx`: Visualization component for the 3x3 risk grid.
- `src/components/ThreatDashboard.jsx`: Main dashboard view with table, diagrams, and export buttons.
- `src/services/mockAi.js`: Logic for threat inference, diagram generation, and compliance mapping.
- `src/utils/pdfGenerator.js`: Utility for generating landscape PDFs.
