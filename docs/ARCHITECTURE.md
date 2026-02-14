# Agentic Honeypot — Architecture Documentation

## System Architecture

```mermaid
graph TB
    subgraph "Frontend Layer"
        UI["Chat UI<br/>(index.html)"]
        ADMIN["Admin Dashboard<br/>(admin.html)"]
    end

    subgraph "FastAPI Server (api/index.py)"
        direction TB
        MW["CORS Middleware"]
        
        subgraph "API Endpoints"
            HP["/api/honeypot<br/>POST"]
            VD["/api/voice/detect<br/>POST"]
            TTS_EP["/api/tts<br/>POST"]
            ES["/api/session/end<br/>POST"]
            AS["/api/admin/stats<br/>GET"]
            AL["/api/admin/sessions<br/>GET/DELETE"]
            AST["/api/admin/settings<br/>GET/PUT"]
            HEALTH["/health<br/>GET"]
        end

        subgraph "Core Engines"
            SD["Scam Detection Engine<br/>55+ regex patterns<br/>Hybrid scoring"]
            IE["Intelligence Extraction<br/>10 pattern types<br/>UPI, phone, bank, URL..."]
            LLM["LLM Client<br/>GROQ Llama 3.3 70B<br/>Persona-driven responses"]
        end

        subgraph "Session Management"
            SM["In-Memory Sessions<br/>(live sessions dict)"]
        end
    end

    subgraph "External Services"
        GROQ["GROQ Cloud API<br/>Llama 3.3 70B"]
        ELEVEN["ElevenLabs API<br/>Turbo v2.5 TTS"]
    end

    subgraph "Database Layer"
        PG["PostgreSQL<br/>asyncpg pool"]
        subgraph "Tables"
            T1["sessions"]
            T2["messages"]
            T3["intelligence"]
            T4["settings"]
        end
    end

    UI -->|"HTTP POST"| HP
    UI -->|"HTTP POST"| VD
    UI -->|"HTTP POST"| TTS_EP
    UI -->|"HTTP POST"| ES
    ADMIN -->|"HTTP GET/PUT/DELETE"| AS
    ADMIN -->|"HTTP GET/PUT/DELETE"| AL
    ADMIN -->|"HTTP GET/PUT"| AST

    HP --> SD
    HP --> IE
    HP --> LLM
    HP --> SM
    ES --> SM
    ES --> PG

    LLM -->|"Chat Completion"| GROQ
    TTS_EP -->|"Text-to-Speech"| ELEVEN
    VD -->|"Whisper STT"| GROQ

    PG --> T1
    PG --> T2
    PG --> T3
    PG --> T4

    AS --> PG
    AL --> PG
    AST --> PG

    classDef frontend fill:#4a9eff,stroke:#2d7dd2,color:#fff
    classDef engine fill:#ff6b6b,stroke:#c0392b,color:#fff
    classDef external fill:#ffa726,stroke:#ef6c00,color:#fff
    classDef db fill:#66bb6a,stroke:#388e3c,color:#fff
    classDef endpoint fill:#ab47bc,stroke:#7b1fa2,color:#fff

    class UI,ADMIN frontend
    class SD,IE,LLM engine
    class GROQ,ELEVEN external
    class PG,T1,T2,T3,T4 db
    class HP,VD,TTS_EP,ES,AS,AL,AST,HEALTH endpoint
```

---

## Data Flow — Scam Interaction Pipeline

```mermaid
sequenceDiagram
    participant S as Scammer
    participant UI as Chat UI
    participant API as FastAPI Server
    participant SD as Scam Detector
    participant IE as Intel Extractor
    participant LLM as GROQ LLM
    participant DB as PostgreSQL

    S->>UI: Sends scam message
    UI->>API: POST /api/honeypot
    
    API->>SD: detect_scam(message, history)
    SD-->>API: DetectionResult (confidence, type, urgency)
    
    API->>IE: extract_intelligence(message, session_id)
    IE-->>API: Extracted items (UPI, phone, bank...)
    
    API->>LLM: generate_llm_response(message, history, persona)
    LLM-->>API: Persona-driven reply (stalling, engaging)
    
    API-->>UI: JSON response (reply + analysis + intel)
    UI-->>S: Displays AI persona reply
    
    Note over S,UI: Conversation continues...<br/>Scammer reveals more info

    UI->>API: POST /api/session/end
    API->>DB: save_session_to_db()
    DB-->>API: Persisted
    API-->>UI: Session summary
```

---

## Database Schema (ER Diagram)

```mermaid
erDiagram
    SESSIONS {
        text id PK
        jsonb persona
        text scam_type
        real scam_confidence
        integer turn_count
        text status
        timestamptz started_at
        timestamptz ended_at
    }

    MESSAGES {
        serial id PK
        text session_id FK
        text sender
        text text
        timestamptz timestamp
        integer seq
    }

    INTELLIGENCE {
        serial id PK
        text session_id FK
        text type
        text value
        real confidence
        timestamptz extracted_at
    }

    SETTINGS {
        text key PK
        jsonb value
        timestamptz updated_at
    }

    SESSIONS ||--o{ MESSAGES : "has"
    SESSIONS ||--o{ INTELLIGENCE : "extracted from"
```

---

## Scam Detection Scoring Model

```mermaid
graph LR
    subgraph "Input Signals"
        P["Pattern Matching<br/>55+ regex rules<br/>Weight: 45%"]
        K["Keyword Scoring<br/>High/Medium risk<br/>Weight: 25%"]
        B["Behavioral Analysis<br/>Length, ALL CAPS, ₹<br/>Weight: 15%"]
        H["History Analysis<br/>Cumulative evidence<br/>Weight: 15%"]
    end

    subgraph "Boosters"
        U["Urgency Boost<br/>×1.3 if urgent"]
        MC["Multi-Category Boost<br/>3+ categories → min 50%"]
    end

    subgraph "Output"
        R["Final Confidence<br/>Threshold: 0.30"]
        T["Scam Type<br/>12 categories"]
        UL["Urgency Level<br/>low/medium/high/critical"]
    end

    P --> R
    K --> R
    B --> R
    H --> R
    R --> U
    R --> MC
    U --> T
    MC --> T
    T --> UL

    classDef input fill:#42a5f5,stroke:#1976d2,color:#fff
    classDef boost fill:#ff7043,stroke:#d84315,color:#fff
    classDef output fill:#66bb6a,stroke:#388e3c,color:#fff

    class P,K,B,H input
    class U,MC boost
    class R,T,UL output
```

---

## Folder Structure

```
AGENTIC-POT/
├── api/
│   └── index.py          # Self-contained FastAPI server (~1200 lines)
├── frontend/
│   ├── index.html         # Chat UI (dark theme, glass-morphism)
│   └── admin.html         # Admin dashboard (stats, sessions, settings)
├── docs/
│   └── ARCHITECTURE.md    # This file
├── .env                   # Environment variables (git-ignored)
├── .env.example           # Template for .env
├── .gitignore             # Git exclusions
├── requirements.txt       # Python dependencies
├── vercel.json            # Vercel deployment config
└── README.md              # Project documentation
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Backend** | FastAPI 3.0.0 | Async Python web framework |
| **LLM** | GROQ (Llama 3.3 70B) | AI persona response generation |
| **TTS** | ElevenLabs (Turbo v2.5) | Text-to-speech for voice mode |
| **STT** | Whisper Large v3 (via GROQ) | Speech-to-text for voice input |
| **Database** | PostgreSQL + asyncpg | Session persistence & analytics |
| **Frontend** | Vanilla HTML/CSS/JS | Zero-dependency chat & admin UI |
| **Deployment** | Vercel / Uvicorn | Serverless or standalone hosting |

---

## Security Considerations

- **API Key Auth**: Optional header-based authentication (`X-API-Key`)
- **CORS**: Currently `allow_origins=["*"]` for development — restrict in production
- **DB Credentials**: Stored in `.env` (git-ignored), never hardcoded
- **JSONB Sanitization**: All persona/settings data serialized via `json.dumps()` before DB insert
- **Memory Bounds**: `_seen_intel` dict capped at 500 sessions to prevent unbounded growth
- **Input Validation**: Pydantic models enforce request schema
- **No Real Secrets Exposed**: The honeypot persona never reveals it's an AI or investigation tool
