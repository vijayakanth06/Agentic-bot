# Agentic Honeypot — Architecture Documentation

## Overview

Single-file FastAPI server (`api/index.py`) that acts as an intelligent honeypot agent. It engages scammers in natural conversation using LLM-powered personas while extracting intelligence data (phone numbers, UPI IDs, bank accounts, URLs, emails, case IDs, policy numbers, order numbers) — all through a single LLM call per turn.

## Key Design Decisions

1. **LLM-First Intelligence Extraction** — The LLM extracts all 8 intelligence types (phones, UPIs, accounts, URLs, emails, case IDs, policy numbers, order numbers) as part of its JSON response. A lightweight regex safety-net catches anything the LLM misses.
2. **Dual API Key Fallback with Global Timeout** — Primary `GROQ_API_KEY` + `RECOVERY_KEY` with automatic failover across 2 keys × 2 models = 4 fallback combinations. A 24-second global deadline ensures we never exceed the 30-second API timeout.
3. **Single LLM Call Per Turn** — One call handles: persona response + scam classification + intelligence extraction via `response_format={"type": "json_object"}`.
4. **Engagement-First Persona with Red Flag Awareness** — The agent plays a trusting, naive victim who actively cooperates with scammers. It subtly identifies red flags (urgency, OTP requests, suspicious links) through innocent observations while maintaining engagement.
5. **Serverless-Safe History Re-extraction** — On every turn, safety regex runs on the full conversation history to recover intelligence from previous turns, ensuring no data loss on stateless platforms like Vercel.
6. **Complete Response Structure** — Every response includes all scored fields: status, sessionId, reply, scamDetected, scamType, confidenceLevel, extractedIntelligence, engagementMetrics, engagementDurationSeconds, totalMessagesExchanged, and agentNotes.

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
  "scamType": "bank_fraud",
  "confidenceLevel": 0.85,
  "totalMessagesExchanged": 12,
  "engagementDurationSeconds": 300.0,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer@fakebank"],
    "phishingLinks": ["http://fake-site.com"],
    "emailAddresses": ["scam@fraud.com"],
    "caseIds": ["REF-2026-78432"],
    "policyNumbers": [],
    "orderNumbers": []
  },
  "engagementMetrics": {
    "engagementDurationSeconds": 300.0,
    "totalMessagesExchanged": 12
  },
  "agentNotes": "Scam type: bank_fraud (LLM-classified). Confidence: 0.85..."
}
```

## Fallback Chain

```
Primary Key + Primary Model (llama-3.1-8b-instant, up to 12s)
    ↓ fail
Primary Key + Fallback Model (llama-3.3-70b-versatile, up to 8s)
    ↓ fail
Recovery Key + Primary Model (up to remaining budget)
    ↓ fail
Recovery Key + Fallback Model (up to remaining budget)
    ↓ fail
Rule-Based Fallback (instant, no API call)

Global timeout budget: 24 seconds (never exceeds 30s API limit)
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
