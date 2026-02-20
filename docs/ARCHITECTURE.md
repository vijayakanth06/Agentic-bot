# Agentic Honeypot — Architecture Documentation

## Overview

Single-file FastAPI server (`api/index.py`) that acts as an intelligent honeypot agent. It engages scammers in natural conversation using LLM-powered personas while extracting intelligence data (phone numbers, UPI IDs, bank accounts, URLs, emails) — all through a single LLM call per turn.

## Key Design Decisions

1. **LLM-First Intelligence Extraction** — The LLM extracts all data (phones, UPIs, accounts, URLs, emails) as part of its JSON response. A lightweight regex safety-net catches anything the LLM misses.
2. **Dual API Key Fallback** — Primary `GROQ_API_KEY` + `RECOVERY_KEY` with automatic failover across 2 keys × 2 models = 4 fallback combinations before rule-based fallback.
3. **Single LLM Call Per Turn** — One call handles: persona response + scam classification + intelligence extraction via `response_format={"type": "json_object"}`.
4. **Engagement-First Persona** — The agent plays a trusting, naive victim who actively cooperates with scammers to maximize conversation length and data extraction.

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/honeypot` | POST | Main honeypot — process scam message, return reply + analysis |
| `/api/voice/detect` | POST | Detect AI-generated speech from audio |
| `/api/tts` | POST | Text-to-speech via ElevenLabs |
| `/api/session/end` | POST | End session, persist to PostgreSQL |
| `/api/admin/stats` | GET | Dashboard statistics |
| `/api/admin/sessions` | GET | List/search sessions |
| `/health` | GET | Health check |

## Request/Response Format

**Request** (POST `/api/honeypot`):
```json
{
  "sessionId": "uuid",
  "message": { "sender": "scammer", "text": "...", "timestamp": "..." },
  "conversationHistory": [],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

**Response**:
```json
{
  "status": "success",
  "reply": "Oh no! What happened to my account?",
  "scamDetected": true,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer@fakebank"],
    "phishingLinks": ["http://fake-site.com"],
    "emailAddresses": ["scam@fraud.com"]
  },
  "engagementMetrics": {
    "engagementDurationSeconds": 90.0,
    "totalMessagesExchanged": 12
  },
  "agentNotes": "Scam type: bank_fraud (LLM-classified). Confidence: 0.85..."
}
```

## Fallback Chain

```
Primary Key + Primary Model (llama-3.1-8b-instant, 12s)
    ↓ fail
Primary Key + Fallback Model (llama-3.3-70b-versatile, 8s)
    ↓ fail
Recovery Key + Primary Model (12s)
    ↓ fail
Recovery Key + Fallback Model (8s)
    ↓ fail
Rule-Based Fallback (instant, no API call)
```

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI + Uvicorn |
| LLM | GROQ (Llama 3.1 8B / 3.3 70B) |
| TTS | ElevenLabs Turbo v2.5 |
| STT | Whisper Large v3 (via GROQ) |
| Database | PostgreSQL + asyncpg (optional) |
| Frontend | Vanilla HTML/CSS/JS |
