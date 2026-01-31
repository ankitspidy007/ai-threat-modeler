# Enhanced STRIDE Knowledge Base

## Overview
The knowledge base has been significantly upgraded to Version 2.0. It now supports a rich, nested schema for detailed threat modeling, complex detection logic, and enhanced risk assessment.

## Schema Structure
Each threat entry now follows this structure:

### Identity & Category
- `id`: Unique identifier (e.g., `S-005`).
- `category`: STRIDE category (Spoofing, Tampering, etc.) or `Combined` for chains.
- `resource_type`: The component type(s) the threat applies to.

### Detection Logic
The `detection` object now uses a structured `logic` block for deterministic parsing.
- `auto_detectable`: Boolean.
- `confidence`: "high" | "medium" | "low".
- `logic`:
    ```json
    {
        "operator": "AND",
        "conditions": [
            { "field": "auth_type", "op": "==", "value": "none" },
            { "field": "public_access", "op": "==", "value": true }
        ]
    }
    ```
    Supported operators: `==`, `!=`, `in`, `not_in`, `exists`.

### Threat Details
The `threat` object contains the core descriptive elements.
- `title`: Short name (e.g., "Missing Rate Limiting").
- `description`: Detailed explanation.

### Risk Assessment
The `risk` object defines the impact.
- `severity`: Critical, High, Medium, Low.
- `likelihood`: High, Medium, Low.
- `impact`: High, Medium, Low.
- `risk_score`: Calculated integer (0-100).

### Mitigation
The `mitigation` object provides actionable fixes.
- `primary`: The main fix.
- `defense_in_depth`: Additional layers required.
- `verification`: How to test the fix.

### Advanced Intelligence (v2.1)
The Knowledge Base now includes machine-readable intelligence.
- `evidence`: Why this threat applies.
    - `derived_from`: Fields or signals used.
    - `reasoning`: Human-readable explanation.
- `signal_source`: Origin of the detection (`architecture`, `configuration`, `code`, `runtime`).
- `applicability`:
    - `environment`: `prod`, `dev`, etc.
    - `exposed_to`: `internet`, `internal`.
    - `data_sensitivity`: `pii`, `public`.
- `negating_controls`: Existing controls that might reduce risk (e.g., `waf_enabled`, `api_gateway`).
- `mapped_controls`: Compliance mappings (`owasp_top_10`, `nist_800_53`).
- `maturity_level`: `baseline`, `intermediate`, `advanced`.

## Usage
The `RuleEngine` automatically parses `threats.json` and evaluates the `detection.condition` against the component properties provided in the system architecture description.

## Extending
To add a new threat:
1. Choose a unique ID (e.g., E-005).
2. specific the resource types (e.g., "Lambda").
3. Define the condition based on properties the AI might infer (e.g., `runtime`, `public_access`).
4. Fill in the Risk and Mitigation sections.
