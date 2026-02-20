# Agentic Honeypot — Architecture Documentation

## Overview

Single-file FastAPI server (`api/index.py`, ~1400 lines) that acts as an intelligent honeypot agent. It engages scammers in natural conversation using LLM-powered personas while extracting intelligence data (phone numbers, UPI IDs, bank accounts, URLs, emails, IFSC codes, case IDs, policy numbers, order numbers) — all through a single LLM call per turn with comprehensive fallback systems.

## Key Design Decisions

1. **LLM-First Intelligence Extraction** — The LLM extracts all data types as part of its JSON response. A compiled regex safety-net catches anything the LLM misses. History re-extraction ensures no data loss on stateless platforms.
2. **Dual API Key Fallback with Global Timeout** — Primary `GROQ_API_KEY` + `RECOVERY_KEY` with automatic failover across 2 keys × 2 models = 4 LLM fallback combinations + 1 rule-based fallback. A 24-second global deadline ensures we never exceed the 30-second API timeout.
3. **Single LLM Call Per Turn** — One call handles response generation + scam classification + intelligence extraction via `response_format={"type": "json_object"}`.
4. **Engagement-First Persona** — The agent plays a trusting, naive victim who actively cooperates with scammers while subtly identifying red flags through innocent observations.
5. **Serverless-Safe History Re-extraction** — On every turn, safety regexes run on the full conversation history to recover intelligence from previous turns, ensuring no data loss on stateless platforms like Vercel.
6. **Complete Response Structure** — Every response includes all required fields: status, sessionId, reply, scamDetected, scamType, confidenceLevel, extractedIntelligence, engagementMetrics, engagementDurationSeconds, totalMessagesExchanged, and agentNotes.

---

## Request Processing Pipeline

```
Incoming POST /api/honeypot
    │
    ├─ 1. Parse request (sessionId, message, conversationHistory, metadata)
    │
    ├─ 2. Session management (get or create in-memory session)
    │
    ├─ 3. LLM Call (with 5-level fallback chain)
    │     ├─ Build system prompt (persona + extraction instructions)
    │     ├─ Trim conversation history (last 4 messages for token efficiency)
    │     ├─ Call Groq with JSON response format
    │     ├─ Parse JSON → extract reply, scam classification, intelligence
    │     └─ On failure → next fallback level
    │
    ├─ 4. Regex Safety-Net Extraction
    │     ├─ Run on current message
    │     ├─ Run on full conversation history (serverless recovery)
    │     └─ Merge + deduplicate with LLM-extracted data
    │
    ├─ 5. Red Flag Analysis
    │     ├─ Scan all scammer messages against 10 pattern categories
    │     └─ Generate natural-language flag descriptions
    │
    ├─ 6. Scam Classification (if LLM didn't classify)
    │     ├─ Keyword-based classifier: 150+ keywords, 18 categories
    │     └─ Confidence escalation (never decreases)
    │
    ├─ 7. Agent Notes Generation
    │     ├─ Scam type + confidence
    │     ├─ Red flag count + descriptions
    │     └─ Extracted intelligence summary
    │
    └─ 8. Build response JSON → return 200
```

---

## Intelligence Extraction Pipeline

### Strategy: LLM + Regex Dual Extraction

**LLM Extraction** (primary):
- The system prompt instructs the LLM to return a JSON object with 11 typed arrays
- Data types: `phones`, `accounts`, `upis`, `urls`, `emails`, `names`, `ifsc`, `case_ids`, `policy_numbers`, `order_numbers`, `other_ids`
- Scam classification: `scam_type` + `confidence` in same response

**Regex Safety-Net** (backup):
- Compiled regex patterns run on every message after LLM extraction
- Also runs on full `conversationHistory` for serverless state recovery

### Regex Patterns

| Type | Pattern | Notes |
|---|---|---|
| Phone | `\+91[\s-]?\d{10}` or `\b[6-9]\d{9}\b` | All +91 prefixes + Indian mobile numbers |
| Bank Account | `\b\d{11,18}\b` | 11-18 digit numbers (excludes 10-digit phones) |
| UPI | `[\w.\-]+@[a-zA-Z]{2,}` | Handles sentence-ending periods via `(?!\.[a-zA-Z]{2,})` |
| URL | `https?://\S+` | Standard URL detection |
| Email | `[\w.\-+]+@[\w.\-]+\.\w{2,}` | Standard email format |
| IFSC | `\b[A-Z]{4}0[A-Z0-9]{6}\b` | Indian bank IFSC format |
| Case ID | `(?:case\|ref\|complaint\|ticket\|file)[\s\-:#]*[\w\-]+(?=\S*\d)` | Requires at least 1 digit (prevents false positives) |
| Policy Number | `(?:policy\|insurance\|claim\|lic)[\s\-:#]*[\w\-]+(?=\S*\d)` | Requires at least 1 digit |
| Order Number | `(?:order\|tracking\|shipment\|delivery\|awb)[\s\-:#]*[\w\-]+(?=\S*\d)` | Requires at least 1 digit |

### Deduplication

All extracted values are deduplicated within each session by type + normalized value. The `extractedIntelligence` object in the response always contains the cumulative set across all turns.

---

## Scam Classification System

### Hybrid Approach: LLM + Keyword Fallback

**LLM Classification** (primary):
- The LLM returns `scam_type` and `confidence` in its JSON response
- Has full conversation context for accurate classification

**Keyword-Based Classification** (fallback):
- Used when LLM is unavailable or returns "generic"
- Scans all conversation text against keyword dictionaries for 18 categories:

| Category | Example Keywords |
|---|---|
| `bank_fraud` | bank, account, NEFT, debit, credit, statement |
| `upi_fraud` | UPI, Google Pay, PhonePe, Paytm, @, QR code |
| `kyc_scam` | KYC, Aadhaar, PAN, verify, update, expire |
| `otp_fraud` | OTP, one time, verification code, 2FA |
| `lottery_scam` | lottery, prize, winner, lucky, jackpot, draw |
| `job_scam` | job, vacancy, hiring, salary, resume, interview |
| `investment_scam` | invest, returns, guaranteed, profit, mutual fund |
| `crypto_investment` | bitcoin, crypto, ethereum, blockchain, wallet |
| `threat_scam` | arrest, warrant, CBI, court, prosecution |
| `phishing` | click, link, verify, login, password, suspicious |
| `tech_support` | virus, malware, remote access, TeamViewer |
| `customs_fraud` | customs, parcel, seized, courier, warehouse |
| `insurance_fraud` | insurance, claim, premium, policy, coverage |
| `electricity_scam` | electricity, bill, disconnect, meter, payment |
| `loan_approval` | loan, EMI, approved, pre-approved, interest rate |
| `income_tax` | income tax, ITR, refund, TDS, notice, assessment |
| `govt_scheme` | government, subsidy, scheme, registration, benefit |
| `generic` | Default when no category matches |

### Confidence Escalation

Scam confidence is **monotonically increasing** — once a confidence level is set, it can only go up, never down. This prevents false negatives when scammers change tactics mid-conversation.

---

## Red Flag Analysis Engine

Scans ALL scammer messages against 10 pattern categories. Results are reported in `agentNotes` with counts and descriptions.

| Category | Detection Patterns |
|---|---|
| Urgency/time pressure | "immediately", "hurry", "expires", "last chance", "act now" |
| OTP/credential request | "OTP", "password", "CVV", "PIN", "verification code" |
| Account block/freeze | "blocked", "frozen", "suspended", "restricted", "hold" |
| Legal/arrest threats | "arrest", "warrant", "CBI", "court order", "prosecution" |
| Too-good-to-be-true | "won", "prize", "guaranteed returns", "jackpot", "lucky" |
| Suspicious links/downloads | "click here", "download", "verify link", "install" |
| Sensitive data request | "share account", "send money", "provide details", "transfer" |
| Unsolicited contact | "calling from", "this is from", "we have noticed" |
| Upfront fee demand | "processing fee", "advance payment", "service charge", "registration fee" |
| Authority impersonation | "from SBI", "from RBI", "officer", "department", "government" |

**Output format in agentNotes**: `"Red flags identified (6): Urgency/time pressure tactics; Account block/freeze threat; OTP/credential request; ..."`

---

## Fallback Chain

5-level fallback ensures the API **always** returns a valid response:

```
Level 1: Primary Key + Primary Model (llama-3.1-8b-instant, 12s timeout)
    ↓ failure (rate limit, timeout, parse error)
Level 2: Primary Key + Fallback Model (llama-3.3-70b-versatile, 8s timeout)
    ↓ failure
Level 3: Recovery Key + Primary Model (remaining budget)
    ↓ failure
Level 4: Recovery Key + Fallback Model (remaining budget)
    ↓ failure
Level 5: Rule-Based Response (instant, no API call)
         + Keyword Scam Classification
         + Regex Intelligence Extraction

Global timeout budget: 24 seconds (always under 30s API limit)
```

### Rule-Based Fallback Responses

18 pre-written responses cover 3 conversation phases (6 per phase):

- **Early (turns 1-2)**: Surprise and concern — "Oh my god, what happened?", "Are you serious sir?"
- **Mid (turns 3-5)**: Willing but confused — "Which department are you calling from?", "Can you tell me your good name?"
- **Late (turns 6+)**: Active cooperation — "What UPI ID should I send to?", "What was the reference number again?"

All 18 responses end with exactly one question mark to ensure continued engagement scoring.

---

## Session Management

### In-Memory Sessions

Each `sessionId` maps to an in-memory dict containing:
- `history`: List of `{sender, text}` messages
- `start_time`: Session start timestamp
- `scam_type`: Current classification
- `confidence`: Current confidence level
- `intel_*`: Accumulated intelligence sets (phones, accounts, UPIs, etc.)

### Stateless Recovery

Because Vercel serverless functions are stateless, the system reconstructs state from `conversationHistory` on every request:
1. Count turns from history length
2. Re-extract intelligence from all historical scammer messages via regex
3. Merge with any in-memory state (if available)

### PostgreSQL Persistence (Optional)

When configured, `POST /api/session/end` persists the session to PostgreSQL:
- `sessions` table: session metadata, scam type, confidence
- `messages` table: full conversation history
- `intelligence` table: extracted data points
- `settings` table: admin-configurable parameters

---

## API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/honeypot` | POST | Main honeypot — process scam message, return reply + analysis |
| `/api/voice/detect` | POST | Detect AI-generated speech from audio |
| `/api/tts` | POST | Text-to-speech via ElevenLabs |
| `/api/session/end` | POST | End session, persist to PostgreSQL |
| `/api/admin/stats` | GET | Dashboard statistics |
| `/api/admin/sessions` | GET | List/search sessions |
| `/api/admin/sessions/{id}` | GET | Full session detail |
| `/api/admin/sessions/{id}` | DELETE | Delete session |
| `/api/admin/settings` | GET/PUT | Read/update settings |
| `/health` | GET | Health check |

---

## Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend | FastAPI 3.0 + Uvicorn | Async HTTP server with auto-validation |
| Primary LLM | Groq — Llama 3.1 8B Instant | Fast response generation (12s timeout) |
| Fallback LLM | Groq — Llama 3.3 70B Versatile | Higher quality fallback (8s timeout) |
| TTS | ElevenLabs Turbo v2.5 | Text-to-speech with free voices |
| STT | Whisper Large v3 (via Groq) | Speech transcription |
| Database | PostgreSQL + asyncpg | Optional session persistence |
| Frontend | Vanilla HTML/CSS/JS | Dark-theme chat UI + admin dashboard |
| Deployment | Vercel Serverless | Serverless with 60s max duration |
