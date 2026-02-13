# 🍯 Agentic Honeypot

AI-powered honeypot system for scam detection & intelligence extraction. Built for the HCL GUVI Buildathon.

## Features

### Problem 2: Agentic Honey-Pot
- **AI persona (Priya Sharma)** engages scammers naturally via GROQ Llama 3.3
- **Hybrid scam detection** — 35+ regex patterns + keyword matching + behavioral analysis
- **Intelligence extraction** — UPI IDs, phone numbers, bank accounts, phishing URLs
- **9-state finite state machine** for conversation flow control
- **Real-time dashboard** with WebSocket live updates
- **PDF report generation** for law enforcement

### Problem 1: AI Voice Detection
- **GROQ Whisper STT** for audio transcription
- **Heuristic AI speech analysis** — grammar perfection, filler absence, TTS artifacts, sentence uniformity
- Audio upload → classification result with confidence score

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/honeypot` | Process scam message (GUVI eval) |
| `POST` | `/api/voice/detect` | Detect AI-generated speech |
| `GET` | `/api/dashboard` | Dashboard statistics |
| `GET` | `/api/sessions` | List all sessions |
| `GET` | `/api/sessions/{id}` | Session detail + intel |
| `GET` | `/api/reports/{id}` | PDF report download |
| `GET` | `/health` | Health check |

## Auth

All protected endpoints require the `x-api-key` header:
```
x-api-key: fae26946fc2015d9bd6f1ddbb447e2f7
```

## Setup

```bash
# 1. Clone
git clone https://github.com/tejash-sr/AGENTIC-POT.git
cd AGENTIC-POT

# 2. Install
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env with your GROQ, ElevenLabs, Twilio keys

# 4. Run
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Deploy to Vercel

```bash
# Push to GitHub, then:
# 1. Go to vercel.com → Import repo
# 2. Set env vars: GROQ_API_KEY, API_KEY, ELEVENLABS_API_KEY
# 3. Deploy → Get your live URL
```

## Tech Stack

- **Backend**: FastAPI + Python 3.10+
- **LLM**: GROQ Llama 3.3 70B
- **Voice**: GROQ Whisper STT + ElevenLabs TTS
- **Database**: SQLite (aiosqlite)
- **Deployment**: Vercel Serverless (Python)

## Project Structure

```
├── api/index.py              # Vercel serverless entry point
├── app/
│   ├── main.py               # FastAPI app + all endpoints
│   ├── config.py             # Settings from .env
│   ├── database.py           # SQLite async DB
│   ├── llm/groq_client.py    # GROQ LLM integration
│   ├── detection/             # Scam detection engine
│   ├── extraction/            # Intelligence extraction
│   ├── state/                 # FSM conversation state
│   ├── handoff/               # AI/user handoff handler
│   ├── voice/                 # STT, TTS, voice detection
│   └── reports/               # PDF report generator
├── frontend/index.html        # Dashboard UI
├── vercel.json                # Vercel config
└── requirements.txt           # Python dependencies
```

## License

MIT
