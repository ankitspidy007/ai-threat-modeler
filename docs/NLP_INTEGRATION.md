# NLP Integration Implementation Plan

## Overview

This document outlines how to integrate Natural Language Processing (NLP) into the AI Threat Modeler to enhance threat detection, architecture parsing, and user experience.

## Current State vs. NLP-Enhanced State

### Current Implementation (Rule-Based)
```python
# Current parser uses regex and keyword matching
if 'mongodb' in text_lower or 'mongo' in text_lower:
    component_type = 'Database'
    
if 'oauth' in text_lower or 'jwt' in text_lower:
    props['auth_type'] = 'oauth2'
```

**Limitations:**
- ❌ Rigid keyword matching
- ❌ Cannot understand context or synonyms
- ❌ Misses implicit information
- ❌ No semantic understanding

### NLP-Enhanced Implementation
```python
# NLP-powered parser understands context and semantics
nlp_model.extract_entities(text)
# Understands: "We use a document store" → MongoDB
# Understands: "User authentication via tokens" → JWT/OAuth
# Understands: "Data is encrypted" → encryption_at_rest = True
```

**Benefits:**
- ✅ Context-aware parsing
- ✅ Synonym recognition
- ✅ Implicit information extraction
- ✅ Better accuracy

---

## NLP Use Cases in Threat Modeler

### 1. Enhanced Architecture Parsing
**Goal**: Better component and relationship extraction

**NLP Techniques:**
- **Named Entity Recognition (NER)**: Extract components, technologies, services
- **Dependency Parsing**: Understand relationships between components
- **Coreference Resolution**: Link pronouns to entities ("it connects to the database")

**Example:**
```
Input: "Our React app talks to a Node API which stores data in Postgres. 
        The API also calls Stripe for payments."

Current Parser: Might miss "talks to" relationship
NLP Parser: Extracts:
  - Components: React (WebClient), Node API (API), Postgres (Database), Stripe (External)
  - Relationships: React → Node API, Node API → Postgres, Node API → Stripe
  - Data Flows: All connections properly mapped
```

### 2. Intelligent Threat Detection
**Goal**: Understand security implications from natural descriptions

**NLP Techniques:**
- **Sentiment Analysis**: Detect security concerns ("we're worried about...")
- **Intent Classification**: Identify security requirements vs. vulnerabilities
- **Semantic Similarity**: Match descriptions to known threat patterns

**Example:**
```
Input: "Users can upload files but we haven't implemented any validation yet"

Current: Might miss this entirely
NLP: Detects:
  - Missing input validation threat
  - File upload vulnerability
  - High confidence (explicitly stated)
```

### 3. Conversational Interface
**Goal**: Allow users to ask questions and get clarifications

**NLP Techniques:**
- **Question Answering**: Answer security questions about the architecture
- **Dialogue Management**: Multi-turn conversations for refinement

**Example:**
```
User: "What are the biggest risks in my architecture?"
AI: "Based on your architecture, the top 3 risks are:
     1. Missing authentication on the API (Critical)
     2. Unencrypted database (High)
     3. No rate limiting (Medium)"

User: "How do I fix the authentication issue?"
AI: "I recommend implementing OAuth2 with JWT tokens. Here's how..."
```

### 4. Automatic Report Generation
**Goal**: Generate human-readable security reports

**NLP Techniques:**
- **Text Generation**: Create detailed threat descriptions
- **Summarization**: Executive summaries of findings

---

## Implementation Options

### Option 1: Lightweight NLP (spaCy) - Recommended for Start

**Pros:**
- ✅ Fast and efficient
- ✅ Works offline (no API costs)
- ✅ Good for entity extraction
- ✅ Pre-trained models available
- ✅ Small footprint (~50MB)

**Cons:**
- ❌ Limited understanding of complex context
- ❌ Requires training for domain-specific terms

**Use Cases:**
- Entity extraction (components, technologies)
- Relationship parsing
- Basic semantic understanding

**Implementation:**
```python
import spacy

# Load pre-trained model
nlp = spacy.load("en_core_web_sm")

def extract_components_nlp(text):
    doc = nlp(text)
    
    components = []
    for ent in doc.ents:
        if ent.label_ in ["PRODUCT", "ORG", "GPE"]:
            component_type = classify_component(ent.text)
            components.append({
                "name": ent.text,
                "type": component_type
            })
    
    return components
```

---

### Option 2: Transformer Models (BERT/RoBERTa)

**Pros:**
- ✅ Deep semantic understanding
- ✅ Context-aware
- ✅ Can be fine-tuned for security domain
- ✅ State-of-the-art accuracy

**Cons:**
- ❌ Slower inference
- ❌ Larger model size (500MB+)
- ❌ Requires GPU for good performance
- ❌ More complex setup

**Use Cases:**
- Semantic similarity matching
- Classification of security issues
- Fine-grained threat detection

**Implementation:**
```python
from transformers import pipeline

# Load pre-trained model
classifier = pipeline("zero-shot-classification", 
                     model="facebook/bart-large-mnli")

def classify_security_concern(text):
    labels = ["authentication", "encryption", "injection", 
              "access_control", "data_leak"]
    
    result = classifier(text, labels)
    return result['labels'][0]  # Top prediction
```

---

### Option 3: LLM Integration (GPT-4/Claude) - Most Powerful

**Pros:**
- ✅ Best understanding of context
- ✅ Can generate detailed explanations
- ✅ Conversational capabilities
- ✅ No training required
- ✅ Handles complex scenarios

**Cons:**
- ❌ API costs (pay per request)
- ❌ Requires internet connection
- ❌ Slower response times
- ❌ Privacy concerns (data sent to third party)

**Use Cases:**
- Conversational threat modeling
- Detailed threat explanations
- Remediation recommendations
- Complex architecture understanding

**Implementation:**
```python
from openai import OpenAI

client = OpenAI(api_key="your-api-key")

def analyze_with_llm(architecture_description):
    prompt = f"""
    Analyze this architecture for security threats:
    {architecture_description}
    
    Identify:
    1. Components and their types
    2. Data flows
    3. Security threats (STRIDE categories)
    4. Risk severity
    """
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    return parse_llm_response(response.choices[0].message.content)
```

---

## Recommended Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
**Goal**: Add basic NLP capabilities without breaking existing functionality

**Tasks:**
1. Install spaCy and download models
2. Create NLP service layer
3. Enhance entity extraction with NER
4. Improve relationship parsing
5. A/B test against current parser

**Files to Create/Modify:**
- `backend/app/nlp/` (new directory)
- `backend/app/nlp/spacy_parser.py`
- `backend/app/nlp/entity_extractor.py`
- `backend/app/engine/parser.py` (integrate NLP)

### Phase 2: Enhanced Detection (Week 3-4)
**Goal**: Improve threat detection accuracy

**Tasks:**
1. Implement semantic similarity for threat matching
2. Add context-aware property inference
3. Train custom NER model for security terms
4. Implement confidence scoring

**Files to Create/Modify:**
- `backend/app/nlp/threat_matcher.py`
- `backend/app/nlp/security_ner_model/`
- `backend/app/engine/rules.py` (enhance with NLP)

### Phase 3: LLM Integration (Week 5-6)
**Goal**: Add optional LLM-powered analysis

**Tasks:**
1. Create LLM service with OpenAI/Anthropic
2. Implement hybrid approach (NLP + LLM)
3. Add conversational interface
4. Generate detailed explanations

**Files to Create/Modify:**
- `backend/app/llm/` (new directory)
- `backend/app/llm/openai_service.py`
- `backend/app/llm/claude_service.py`
- `backend/app/api/chat_endpoint.py`

### Phase 4: Advanced Features (Week 7-8)
**Goal**: Polish and optimize

**Tasks:**
1. Implement caching for LLM responses
2. Add fine-tuning for domain-specific model
3. Create feedback loop for improvement
4. Performance optimization

---

## Detailed Implementation: Phase 1

### Step 1: Install Dependencies

**Update `backend/requirements.txt`:**
```txt
# NLP Libraries
spacy>=3.7.0,<4.0.0
en-core-web-sm @ https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.0/en_core_web_sm-3.7.0-py3-none-any.whl

# Optional: For advanced NLP
transformers>=4.36.0,<5.0.0
torch>=2.1.0,<3.0.0  # Only if using transformers
```

### Step 2: Create NLP Service

**Create `backend/app/nlp/__init__.py`:**
```python
"""NLP services for enhanced architecture parsing and threat detection."""

from .spacy_parser import SpacyParser
from .entity_extractor import EntityExtractor

__all__ = ['SpacyParser', 'EntityExtractor']
```

**Create `backend/app/nlp/spacy_parser.py`:**
```python
import spacy
from typing import List, Dict, Tuple
from ..models import Component, DataFlow

class SpacyParser:
    """Enhanced parser using spaCy NLP."""
    
    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            # Download model if not available
            import subprocess
            subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
            self.nlp = spacy.load("en_core_web_sm")
    
    def extract_components(self, text: str) -> List[Dict]:
        """Extract components using NER and dependency parsing."""
        doc = self.nlp(text)
        components = []
        
        # Technology keywords mapping
        tech_mapping = {
            'react': ('WebClient', 'frontend'),
            'angular': ('WebClient', 'frontend'),
            'vue': ('WebClient', 'frontend'),
            'node': ('API', 'backend'),
            'express': ('API', 'backend'),
            'fastapi': ('API', 'backend'),
            'mongodb': ('Database', 'nosql'),
            'postgres': ('Database', 'sql'),
            'mysql': ('Database', 'sql'),
            'redis': ('Cache', 'inmemory'),
            'stripe': ('External', 'payment'),
            'aws': ('Cloud', 'infrastructure'),
        }
        
        # Extract entities
        for ent in doc.ents:
            if ent.label_ in ["PRODUCT", "ORG"]:
                comp_type, category = self._classify_component(ent.text.lower(), tech_mapping)
                if comp_type:
                    components.append({
                        'name': ent.text,
                        'type': comp_type,
                        'category': category,
                        'context': ent.sent.text
                    })
        
        # Extract from noun chunks for missed components
        for chunk in doc.noun_chunks:
            chunk_lower = chunk.text.lower()
            for tech, (comp_type, category) in tech_mapping.items():
                if tech in chunk_lower:
                    components.append({
                        'name': chunk.text,
                        'type': comp_type,
                        'category': category,
                        'context': chunk.sent.text
                    })
        
        return self._deduplicate_components(components)
    
    def extract_relationships(self, text: str) -> List[Tuple[str, str, str]]:
        """Extract relationships between components using dependency parsing."""
        doc = self.nlp(text)
        relationships = []
        
        # Relationship verbs
        connection_verbs = ['connect', 'call', 'use', 'access', 'store', 
                           'send', 'receive', 'communicate', 'integrate']
        
        for token in doc:
            if token.lemma_ in connection_verbs:
                # Find subject and object
                subject = None
                obj = None
                
                for child in token.children:
                    if child.dep_ in ["nsubj", "nsubjpass"]:
                        subject = child.text
                    elif child.dep_ in ["dobj", "pobj"]:
                        obj = child.text
                
                if subject and obj:
                    relationships.append((subject, token.lemma_, obj))
        
        return relationships
    
    def _classify_component(self, text: str, tech_mapping: Dict) -> Tuple[str, str]:
        """Classify component type based on text."""
        for tech, (comp_type, category) in tech_mapping.items():
            if tech in text:
                return comp_type, category
        return None, None
    
    def _deduplicate_components(self, components: List[Dict]) -> List[Dict]:
        """Remove duplicate components."""
        seen = set()
        unique = []
        
        for comp in components:
            key = (comp['name'].lower(), comp['type'])
            if key not in seen:
                seen.add(key)
                unique.append(comp)
        
        return unique
```

### Step 3: Integrate with Existing Parser

**Modify `backend/app/engine/parser.py`:**
```python
from ..nlp.spacy_parser import SpacyParser

class ArchitectureParser:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nlp_parser = SpacyParser()  # Add NLP parser
    
    def parse(self, description: str, project_name: str = "Unnamed Project") -> SystemArchitecture:
        """Enhanced parsing with NLP support."""
        
        # Use both rule-based and NLP parsing
        rule_based_components = self._extract_components_regex(description)
        nlp_components = self.nlp_parser.extract_components(description)
        
        # Merge results (NLP takes precedence for conflicts)
        components = self._merge_components(rule_based_components, nlp_components)
        
        # Extract relationships using NLP
        nlp_relationships = self.nlp_parser.extract_relationships(description)
        
        # Continue with existing logic...
```

---

## Configuration & Settings

**Create `backend/app/config/nlp_config.py`:**
```python
from pydantic import BaseSettings

class NLPSettings(BaseSettings):
    # NLP Model Selection
    USE_NLP: bool = True
    NLP_MODEL: str = "spacy"  # Options: spacy, transformers, llm
    
    # spaCy Settings
    SPACY_MODEL: str = "en_core_web_sm"
    
    # LLM Settings (optional)
    USE_LLM: bool = False
    LLM_PROVIDER: str = "openai"  # Options: openai, anthropic
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    LLM_MODEL: str = "gpt-4"
    
    # Performance
    NLP_BATCH_SIZE: int = 32
    NLP_CACHE_ENABLED: bool = True
    
    class Config:
        env_file = ".env"
```

---

## Testing Strategy

**Create `backend/tests/test_nlp_parser.py`:**
```python
import pytest
from app.nlp.spacy_parser import SpacyParser

def test_component_extraction():
    parser = SpacyParser()
    text = "A React frontend connects to a Node.js API that uses MongoDB"
    
    components = parser.extract_components(text)
    
    assert len(components) >= 3
    assert any(c['type'] == 'WebClient' for c in components)
    assert any(c['type'] == 'API' for c in components)
    assert any(c['type'] == 'Database' for c in components)

def test_relationship_extraction():
    parser = SpacyParser()
    text = "The API calls Stripe for payment processing"
    
    relationships = parser.extract_relationships(text)
    
    assert len(relationships) > 0
    assert any('call' in r for r in relationships)
```

---

## Performance Considerations

### Optimization Strategies:

1. **Caching**: Cache NLP results for identical inputs
2. **Lazy Loading**: Load models only when needed
3. **Batch Processing**: Process multiple descriptions together
4. **Model Selection**: Use smaller models for simple tasks

**Example Caching:**
```python
from functools import lru_cache

class SpacyParser:
    @lru_cache(maxsize=100)
    def extract_components(self, text: str) -> List[Dict]:
        # Cached for repeated inputs
        return self._extract_components_impl(text)
```

---

## Cost Analysis

### Option Comparison:

| Approach | Setup Cost | Runtime Cost | Accuracy | Speed |
|----------|-----------|--------------|----------|-------|
| spaCy | Free | Free | Good (75-85%) | Fast |
| Transformers | Free | Free | Better (85-92%) | Medium |
| GPT-4 API | Free | $0.01-0.03/request | Best (92-98%) | Slow |

**Recommendation**: Start with spaCy, add LLM as optional premium feature

---

## Next Steps

1. Review this implementation plan
2. Decide on Phase 1 timeline
3. Set up development environment with spaCy
4. Create feature branch for NLP integration
5. Implement and test incrementally

Would you like me to start implementing Phase 1?
