# Examples

This folder contains example threat analysis outputs from the AI Threat Modeler.

## Files

### Example Analysis Outputs

These are sample JSON outputs from running the threat analysis on different scenarios:

- **`ecommerce_example.json`** - E-commerce platform analysis showing configuration-aware threat detection
- **`healthcare_example.json`** - Healthcare system analysis (if available)

## How to Use

1. **Run an analysis** using the web UI or API
2. **Save the output** to this folder for reference
3. **Compare results** before/after improvements

## Example API Call

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Your architecture description here...",
    "project_name": "Example Project"
  }' \
  -o examples/my_analysis.json
```

## What's in an Analysis File?

Each JSON file contains:
- **Project metadata** (name, timestamp)
- **Security score** (0-100)
- **Detected threats** with severity, category, and mitigation
- **Architecture components** and data flows
- **Known issues** (if parsed from description)

## Note

These are example outputs for reference and testing purposes. They are not part of the application source code.
