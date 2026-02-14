"""
Agentic Honeypot — Self-Contained FastAPI Server with PostgreSQL.

Single-file FastAPI app with all logic inline.
Handles: POST /api/honeypot, POST /api/voice/detect, POST /api/tts
         POST /api/session/end, GET /api/admin/*, GET /admin
"""

import os
import re
import json
import asyncio
import urllib.request
import urllib.error
from datetime import datetime, timezone
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Query
from fastapi.responses import HTMLResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ═══════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
API_KEY = os.environ.get("API_KEY", "fae26946fc2015d9bd6f1ddbb447e2f7")
LLM_MODEL = os.environ.get("LLM_MODEL", "llama-3.3-70b-versatile")
ELEVENLABS_API_KEY = os.environ.get("ELEVENLABS_API_KEY", "")
PERSONA_NAME = os.environ.get("PERSONA_NAME", "Tejash S")
PERSONA_AGE = os.environ.get("PERSONA_AGE", "28")
PERSONA_OCCUPATION = os.environ.get("PERSONA_OCCUPATION", "Software Engineer at Grootan")
PERSONA_LOCATION = os.environ.get("PERSONA_LOCATION", "Perundurai")

ELEVENLABS_API_URL = "https://api.elevenlabs.io/v1"

# PostgreSQL — build URL from individual env vars or use DATABASE_URL directly
_PG_HOST = os.environ.get("POSTGRES_HOST", "localhost")
_PG_PORT = os.environ.get("POSTGRES_PORT", "5433")
_PG_DB = os.environ.get("POSTGRES_DB", "honeypot")
_PG_USER = os.environ.get("POSTGRES_USER", "postgres")
_PG_PASS = os.environ.get("POSTGRES_PASSWORD", "")
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    f"postgresql://{_PG_USER}:{_PG_PASS}@{_PG_HOST}:{_PG_PORT}/{_PG_DB}"
)

# ═══════════════════════════════════════════════
# PostgreSQL Database Layer
# ═══════════════════════════════════════════════

_pool = None  # asyncpg connection pool


async def get_pool():
    """Lazy-init and return the asyncpg connection pool."""
    global _pool
    if _pool is None:
        try:
            import asyncpg
            _pool = await asyncpg.create_pool(
                DATABASE_URL,
                min_size=2,
                max_size=10,
                command_timeout=15,
            )
            print("[DB] Connection pool created")
        except Exception as e:
            print(f"[DB ERROR] Could not connect to PostgreSQL: {e}")
            return None
    return _pool


async def init_db():
    """Create tables if they don't exist."""
    pool = await get_pool()
    if not pool:
        print("[DB] Skipping table creation — no database connection")
        return
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                persona JSONB NOT NULL DEFAULT '{}',
                scam_type TEXT NOT NULL DEFAULT 'unknown',
                scam_confidence REAL NOT NULL DEFAULT 0.0,
                urgency_level TEXT NOT NULL DEFAULT 'low',
                turn_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ended',
                started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                ended_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                seq INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS intelligence (
                id SERIAL PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.0,
                extracted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
            CREATE INDEX IF NOT EXISTS idx_intelligence_session ON intelligence(session_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
            CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC);
        """)
        print("[DB] Tables ready")


async def save_session_to_db(session_id: str, session_data: dict, persona: dict):
    """Persist a complete session (messages + intelligence + metadata) to PostgreSQL."""
    pool = await get_pool()
    if not pool:
        raise HTTPException(status_code=503, detail="Database not available")

    async with pool.acquire() as conn:
        async with conn.transaction():
            # Upsert session record
            await conn.execute("""
                INSERT INTO sessions (id, persona, scam_type, scam_confidence, turn_count, status, started_at, ended_at)
                VALUES ($1, $2::jsonb, $3, $4, $5, 'ended', $6, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    persona = EXCLUDED.persona,
                    scam_type = EXCLUDED.scam_type,
                    scam_confidence = EXCLUDED.scam_confidence,
                    turn_count = EXCLUDED.turn_count,
                    status = 'ended',
                    ended_at = NOW()
            """,
                session_id,
                json.dumps(persona),  # asyncpg JSONB accepts pre-serialized JSON strings
                session_data.get("scam_type", "unknown"),
                session_data.get("scam_confidence", 0.0),
                session_data.get("turn_count", 0),
                session_data.get("started_at", datetime.now(timezone.utc)),
            )

            # Delete existing messages/intelligence for idempotency on re-save
            await conn.execute("DELETE FROM messages WHERE session_id = $1", session_id)
            await conn.execute("DELETE FROM intelligence WHERE session_id = $1", session_id)

            # Insert messages
            history = session_data.get("history", [])
            for seq, msg in enumerate(history):
                await conn.execute(
                    "INSERT INTO messages (session_id, sender, text, seq) VALUES ($1, $2, $3, $4)",
                    session_id, msg.get("sender", "unknown"), msg.get("text", ""), seq,
                )

            # Insert intelligence items
            intel_items = session_data.get("intelligence", [])
            for item in intel_items:
                await conn.execute(
                    "INSERT INTO intelligence (session_id, type, value, confidence) VALUES ($1, $2, $3, $4)",
                    session_id, item.get("type", ""), item.get("value", ""), item.get("confidence", 0.0),
                )

    return True


# ═══════════════════════════════════════════════
# FastAPI App with Lifespan
# ═══════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup, close pool on shutdown."""
    await init_db()
    yield
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        print("[DB] Pool closed")

app = FastAPI(title="Agentic Honeypot", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory session store (live sessions — flushed to DB on end)
sessions: dict[str, dict] = {}

# ═══════════════════════════════════════════════
# Scam Detection Engine (55+ patterns)
# ═══════════════════════════════════════════════

@dataclass
class ScamIndicator:
    pattern: re.Pattern
    weight: float
    category: str
    urgency_boost: bool = False

@dataclass
class DetectionResult:
    is_scam: bool = False
    confidence: float = 0.0
    scam_type: str = "unknown"
    indicators: list[dict] = field(default_factory=list)
    urgency_level: str = "low"

SCAM_PATTERNS = [
    # --- Urgency / Pressure ---
    ScamIndicator(re.compile(r"urgent|immediately|within \d+ (hours?|minutes?)|right now", re.I), 0.18, "urgency", True),
    ScamIndicator(re.compile(r"act now|don'?t delay|time (is|was) running|last chance|final warning", re.I), 0.15, "urgency", True),
    ScamIndicator(re.compile(r"expir(e|ing|ed)|deadline|limited time|hurry|asap", re.I), 0.12, "urgency", True),
    ScamIndicator(re.compile(r"before.{0,15}(expire|block|suspend|close|lock)", re.I), 0.12, "urgency", True),
    ScamIndicator(re.compile(r"session.{0,10}(expir|timeout|time)", re.I), 0.10, "urgency", True),

    # --- Authority / Impersonation ---
    ScamIndicator(re.compile(r"(bank|rbi|sebi|income tax|police|court|government)\s*(manager|official|officer|department)", re.I), 0.20, "authority"),
    ScamIndicator(re.compile(r"(sbi|hdfc|icici|axis|kotak|pnb|bob|canara|union)\s*(bank)?", re.I), 0.12, "authority"),
    ScamIndicator(re.compile(r"your (account|number|card|kyc|pan|aadhaar) (is|has been|will be)", re.I), 0.15, "authority", True),
    ScamIndicator(re.compile(r"dear (customer|user|sir|madam|valued)", re.I), 0.10, "authority"),
    ScamIndicator(re.compile(r"(senior|chief) (officer|manager|executive)", re.I), 0.12, "authority"),
    ScamIndicator(re.compile(r"(cyber ?crime|telecom|trai|dot|ministry)", re.I), 0.16, "authority"),
    ScamIndicator(re.compile(r"(this is|i am|calling from).{0,20}(department|branch|office|headquarters)", re.I), 0.14, "authority"),

    # --- Financial / Payment Requests ---
    ScamIndicator(re.compile(r"send (money|amount|payment|fund|rs\.?|₹)", re.I), 0.20, "financial", True),
    ScamIndicator(re.compile(r"transfer (to|into|amount)|wire|remittance", re.I), 0.18, "financial"),
    ScamIndicator(re.compile(r"(processing|activation|registration|delivery|customs|handling) fee", re.I), 0.18, "financial", True),
    ScamIndicator(re.compile(r"pay (rs\.?|₹|inr)?\s*\d+", re.I), 0.20, "financial", True),
    ScamIndicator(re.compile(r"upi.{0,5}(id|transfer|pay|send)|@(upi|ybl|paytm|okaxis|oksbi|apl|ibl|gpay|phonepe)", re.I), 0.18, "financial"),
    ScamIndicator(re.compile(r"(send|return|refund).{0,15}(back|money|amount|rs|₹)", re.I), 0.18, "financial", True),
    ScamIndicator(re.compile(r"(google pay|phonepe|paytm|bhim|gpay)", re.I), 0.10, "financial"),
    ScamIndicator(re.compile(r"(bank account|account number|a/c)\s*\d{5,}", re.I), 0.16, "financial"),

    # --- Verification / KYC ---
    ScamIndicator(re.compile(r"verify your (account|identity|details|kyc|pan|aadhaar)", re.I), 0.16, "verification", True),
    ScamIndicator(re.compile(r"kyc.{0,10}(update|expir|pending|incomplete|mandatory)", re.I), 0.18, "verification", True),
    ScamIndicator(re.compile(r"(update|confirm|share|send) your (details|otp|pin|password|cvv)", re.I), 0.20, "verification", True),

    # --- OTP Fraud ---
    ScamIndicator(re.compile(r"(share|send|tell|provide|enter).{0,15}(otp|pin|cvv|password|mpin)", re.I), 0.22, "otp_fraud", True),
    ScamIndicator(re.compile(r"otp.{0,10}(sent|received|generated|code)", re.I), 0.15, "otp_fraud"),
    ScamIndicator(re.compile(r"(need|require|want).{0,10}(otp|pin|password)", re.I), 0.18, "otp_fraud", True),

    # --- Lottery / Prize ---
    ScamIndicator(re.compile(r"(won|winner|selected|chosen).{0,20}(prize|lottery|reward|cashback|gift)", re.I), 0.18, "lottery", True),
    ScamIndicator(re.compile(r"congratulat|lucky (winner|number|draw)|jackpot", re.I), 0.16, "lottery", True),
    ScamIndicator(re.compile(r"claim (your|now|prize|reward)|redeem", re.I), 0.14, "lottery", True),
    ScamIndicator(re.compile(r"(lakh|crore|lakhs|crores).{0,10}(prize|won|reward|amount)", re.I), 0.16, "lottery", True),

    # --- Job / Income Scam ---
    ScamIndicator(re.compile(r"work from home|earn.{0,15}(daily|weekly|monthly)|part.?time.{0,10}(job|income|earning)", re.I), 0.14, "job_scam", True),
    ScamIndicator(re.compile(r"(easy|quick|guaranteed|assured) (money|income|returns|profit)", re.I), 0.16, "job_scam", True),
    ScamIndicator(re.compile(r"no (experience|investment) (needed|required)", re.I), 0.14, "job_scam"),
    ScamIndicator(re.compile(r"(data entry|typing|copy paste|online).{0,10}(job|work|earning)", re.I), 0.12, "job_scam"),

    # --- Threat / Legal ---
    ScamIndicator(re.compile(r"(account|number|card|sim).{0,10}(block|suspend|deactivat|freez|cancel)", re.I), 0.16, "threat", True),
    ScamIndicator(re.compile(r"legal (action|notice|proceedings)|arrest warrant|fir|complaint", re.I), 0.18, "threat", True),
    ScamIndicator(re.compile(r"if you (don'?t|do not|fail to)", re.I), 0.12, "threat", True),
    ScamIndicator(re.compile(r"(police|cyber cell|ncrb).{0,10}(case|complaint|action)", re.I), 0.16, "threat", True),

    # --- Phishing ---
    ScamIndicator(re.compile(r"click (here|this|below|the link)|tap (here|this|below)", re.I), 0.14, "phishing"),
    ScamIndicator(re.compile(r"(secure|verify|update).{0,5}(link|url|portal|website)", re.I), 0.14, "phishing"),
    ScamIndicator(re.compile(r"https?://[^\s]+\.(xyz|top|info|click|loan|win|buzz)", re.I), 0.18, "phishing"),

    # --- Refund / Wrong Transfer (social engineering) ---
    ScamIndicator(re.compile(r"(accidentally|mistakenly|by mistake|wrongly).{0,20}(sent|transfer|deposit|credit)", re.I), 0.22, "refund_scam", True),
    ScamIndicator(re.compile(r"(wrong|incorrect).{0,10}(transfer|payment|account|person|number)", re.I), 0.20, "refund_scam", True),
    ScamIndicator(re.compile(r"(send|return|refund|give).{0,5}(it |money |amount )?(back|return)", re.I), 0.20, "refund_scam", True),
    ScamIndicator(re.compile(r"(check|verify).{0,10}(your|the) (account|balance|transaction)", re.I), 0.12, "refund_scam"),
    ScamIndicator(re.compile(r"(money|amount|rs\.?|₹).{0,10}(should be|must be|is).{0,10}(there|in your|credited)", re.I), 0.16, "refund_scam", True),
    ScamIndicator(re.compile(r"(please|kindly|pls).{0,10}(help|cooperate|assist|return)", re.I), 0.10, "refund_scam"),
    ScamIndicator(re.compile(r"i'?m.{0,10}(in trouble|desperate|emergency|stuck)", re.I), 0.14, "refund_scam", True),

    # --- Investment Scam ---
    ScamIndicator(re.compile(r"(invest|trading|forex|stock).{0,15}(guaranteed|assured|fixed|daily) return", re.I), 0.18, "investment", True),
    ScamIndicator(re.compile(r"(double|triple|10x).{0,10}(money|investment|return)", re.I), 0.18, "investment", True),
    ScamIndicator(re.compile(r"sebi.{0,10}register|mutual fund.{0,10}guaranteed", re.I), 0.16, "investment"),

    # --- Tech Support Scam ---
    ScamIndicator(re.compile(r"(virus|malware|hack|breach).{0,15}(detected|found|your)", re.I), 0.16, "tech_support", True),
    ScamIndicator(re.compile(r"(remote access|teamviewer|anydesk|download).{0,10}(install|connect|allow)", re.I), 0.20, "tech_support", True),
    ScamIndicator(re.compile(r"(microsoft|windows|apple).{0,10}(security|support|license)", re.I), 0.14, "tech_support"),

    # --- Delivery / Customs ---
    ScamIndicator(re.compile(r"(parcel|package|shipment|courier).{0,15}(held|stuck|customs|returned)", re.I), 0.18, "financial", True),
    ScamIndicator(re.compile(r"(customs|clearance|delivery).{0,10}(fee|charge|duty|payment)", re.I), 0.20, "financial", True),
    ScamIndicator(re.compile(r"(india post|fedex|dhl|bluedart).{0,15}(delivery|payment|customs)", re.I), 0.14, "authority"),
    ScamIndicator(re.compile(r"tracking.{0,5}(id|number|code)", re.I), 0.08, "authority"),
    ScamIndicator(re.compile(r"(parcel|package).{0,10}(destroy|return|dispose)", re.I), 0.16, "threat", True),

    # --- Insurance / Pension Fraud ---
    ScamIndicator(re.compile(r"(lic|insurance|pension|policy).{0,15}(lapse|expire|mature|bonus|claim)", re.I), 0.18, "financial", True),
    ScamIndicator(re.compile(r"(maturity|surrender|bonus).{0,10}(amount|value|ready|disburs)", re.I), 0.16, "financial", True),
    ScamIndicator(re.compile(r"(policyholder|policy number|policy.{0,3}no)", re.I), 0.10, "authority"),
    ScamIndicator(re.compile(r"(lic|irda|irdai).{0,10}(head office|department|registered)", re.I), 0.14, "authority"),

    # --- Utility / Bill Disconnection ---
    ScamIndicator(re.compile(r"(electricity|power|gas|water).{0,15}(disconnect|cut|shut|pending|overdue)", re.I), 0.18, "threat", True),
    ScamIndicator(re.compile(r"(pending|overdue|unpaid).{0,10}(bill|amount|dues|payment)", re.I), 0.16, "financial", True),
    ScamIndicator(re.compile(r"consumer.{0,5}(id|number|no)", re.I), 0.08, "authority"),
    ScamIndicator(re.compile(r"(permanent|immediate).{0,10}(disconnect|disconnection|cut)", re.I), 0.16, "threat", True),
]

HIGH_RISK_KEYWORDS = [
    "bitcoin", "ethereum", "crypto", "wallet", "private key",
    "gift card", "steam card", "western union", "moneygram",
    "account suspended", "verify identity", "confirm details",
    "processing fee", "activation fee", "delivery fee",
    "blocked account", "frozen account", "suspicious activity",
    "send it back", "refund me", "return the money",
    "wrong transfer", "accidental transfer", "by mistake",
    "arrest warrant", "legal action", "account will be",
    "compromised", "unauthorized", "unusual activity",
    "customs duty", "clearance fee", "held at customs",
    "policy lapse", "maturity bonus", "lic",
    "electricity disconnection", "power cut", "bill overdue",
    "remote access", "teamviewer", "anydesk",
    "double your money", "guaranteed returns", "forex trading",
]

MEDIUM_RISK_KEYWORDS = [
    "please help", "kindly cooperate", "do it now",
    "immediately", "urgently", "at the earliest",
    "share your", "send your", "provide your",
    "employee id", "reference number", "case number",
    "google pay", "phonepe", "paytm", "bhim",
    "bank account", "upi id", "ifsc",
    "customs", "parcel", "disconnection", "overdue",
    "insurance", "maturity", "policy", "pension",
    "virus detected", "malware", "remote access",
]

TYPE_MAP = {
    "urgency": "generic", "authority": "bank_fraud", "financial": "upi_fraud",
    "verification": "kyc_scam", "otp_fraud": "otp_fraud", "lottery": "lottery_scam",
    "job_scam": "job_scam", "investment": "investment_scam", "threat": "threat_scam",
    "phishing": "phishing", "refund_scam": "upi_fraud", "tech_support": "tech_support",
}


def detect_scam(message: str, session_history: list[dict] | None = None) -> DetectionResult:
    """Detect scam with cumulative session-level confidence boosting."""
    result = DetectionResult()
    pattern_score = 0.0
    matched_categories: dict[str, float] = {}
    has_urgency = False

    for ind in SCAM_PATTERNS:
        if ind.pattern.search(message):
            pattern_score += ind.weight
            if ind.urgency_boost:
                has_urgency = True
            cat = ind.category
            matched_categories[cat] = matched_categories.get(cat, 0) + ind.weight
            result.indicators.append({"category": cat, "weight": ind.weight})

    # High-risk keyword scoring
    keyword_score = sum(0.12 for kw in HIGH_RISK_KEYWORDS if kw in message.lower())
    keyword_score += sum(0.06 for kw in MEDIUM_RISK_KEYWORDS if kw in message.lower())
    keyword_score = min(keyword_score, 1.0)

    # Behavioral signals
    behavioral_score = 0.0
    if len(message) > 200: behavioral_score += 0.1
    if message.isupper() or message.count("!") > 2: behavioral_score += 0.1
    if re.search(r"₹|rs\.?\s*\d|inr\s*\d|\d+\s*(lakh|crore)", message, re.I):
        behavioral_score += 0.12  # Financial context boost

    # History analysis — cumulative evidence from prior messages
    history_score = 0.0
    if session_history:
        scammer_msgs = [m.get("text", "") for m in session_history if m.get("sender") != "agent"]
        for prev_msg in scammer_msgs[-5:]:
            for ind in SCAM_PATTERNS:
                if ind.pattern.search(prev_msg):
                    history_score += ind.weight * 0.3
        history_score = min(history_score, 1.0)

    # Combine scores (rebalanced weights)
    raw = (
        pattern_score * 0.45
        + keyword_score * 0.25
        + behavioral_score * 0.15
        + history_score * 0.15
    )

    # Urgency boost
    if has_urgency and raw > 0.10: raw *= 1.3

    # Multi-category boost — if message triggers 3+ categories, it's almost certainly a scam
    if len(matched_categories) >= 3:
        raw = max(raw, 0.50)
    elif len(matched_categories) >= 2:
        raw *= 1.15

    result.confidence = min(round(raw, 4), 1.0)
    result.is_scam = result.confidence >= 0.30  # Lowered threshold for better recall

    if matched_categories:
        dominant = max(matched_categories, key=matched_categories.get)
        result.scam_type = TYPE_MAP.get(dominant, "generic")

    urgency_count = sum(1 for i in result.indicators if i["category"] == "urgency")
    result.urgency_level = "critical" if urgency_count >= 3 else "high" if urgency_count >= 2 else "medium" if urgency_count >= 1 else "low"

    return result


# ═══════════════════════════════════════════════
# Intelligence Extraction Engine
# ═══════════════════════════════════════════════

EXTRACT_PATTERNS = [
    {"type": "upi", "pattern": re.compile(r"[a-zA-Z0-9._-]+@(upi|ybl|paytm|okaxis|oksbi|okhdfcbank|axl|ibl|apl|gpay|phonepe)", re.I), "confidence": 0.95},
    {"type": "phone", "pattern": re.compile(r"(?:\+91[\s-]?)?(?:[6-9]\d{9})|(?:\+91[\s-]?\d{5}[\s-]?\d{5})", re.I), "confidence": 0.85},
    {"type": "bank_account", "pattern": re.compile(r"(?:account|a/c|ac)[\s#:.-]*(\d{9,18})", re.I), "confidence": 0.80},
    {"type": "url", "pattern": re.compile(r"https?://[^\s<>\"']+", re.I), "confidence": 0.85},
    {"type": "name", "pattern": re.compile(r"(?:(?:my name is|i am|this is|i'?m|call me)\s+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)", re.I), "confidence": 0.70},
    {"type": "ifsc", "pattern": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), "confidence": 0.90},
    {"type": "email", "pattern": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.I), "confidence": 0.85},
    # Misc identifiers for richer extraction
    {"type": "employee_id", "pattern": re.compile(r"(?:employee|emp|staff)\s*(?:id|no|number|#)[\s:.-]*(\w{2,10})", re.I), "confidence": 0.70},
    {"type": "reference_id", "pattern": re.compile(r"(?:ref(?:erence)?|case|ticket|tracking)\s*(?:id|no|number|#)?[\s:.-]*([A-Z0-9-]{4,20})", re.I), "confidence": 0.75},
    {"type": "policy_id", "pattern": re.compile(r"(?:policy|consumer|customer)\s*(?:id|no|number|#)[\s:.-]*([A-Z0-9-]{4,20})", re.I), "confidence": 0.70},
]

_seen_intel: dict[str, set] = {}  # session_id -> set of seen dedup keys
_MAX_TRACKED_SESSIONS = 500  # Safety bound to prevent unbounded memory growth


def extract_intelligence(message: str, session_id: str = "") -> list[dict]:
    # Evict oldest tracked sessions if memory bound exceeded
    if len(_seen_intel) > _MAX_TRACKED_SESSIONS:
        oldest_keys = list(_seen_intel.keys())[: len(_seen_intel) - _MAX_TRACKED_SESSIONS]
        for k in oldest_keys:
            _seen_intel.pop(k, None)
    seen = _seen_intel.setdefault(session_id, set())
    items = []
    for spec in EXTRACT_PATTERNS:
        for match in spec["pattern"].finditer(message):
            value = match.group(0).strip()
            if spec["type"] in ("bank_account", "name"):
                for g in match.groups():
                    if g:
                        value = g.strip()
                        break
            dedup_key = f"{spec['type']}:{value.lower()}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            if spec["type"] == "email" and any(value.lower().endswith(f"@{s}") for s in ["upi", "ybl", "paytm"]):
                continue
            items.append({"type": spec["type"], "value": value, "confidence": spec["confidence"]})
    return items

# ═══════════════════════════════════════════════
# LLM Client (GROQ Llama 3.3)
# ═══════════════════════════════════════════════

def _build_persona_prompt(p: dict) -> str:
    name = p.get("name", "Tejash S")
    age = p.get("age", "28")
    occupation = p.get("occupation", "Software Engineer")
    location = p.get("location", "Perundurai")
    bank = p.get("bank", "SBI")
    gender = p.get("gender", "Male")
    language = p.get("language", "English")
    
    # Gender-specific references
    pronoun = "he" if gender == "Male" else "she"
    partner = "wife" if gender == "Male" else "husband"
    
    return f"""You are {name}, a {age}-year-old {gender.lower()} {occupation} living in {location}.
You bank with {bank}.

LANGUAGE RULE (VERY IMPORTANT):
- You MUST respond ENTIRELY in {language}.
- Do NOT mix languages unless the caller does.
- Match the caller's tone and language naturally.

WHO YOU ARE — A REAL PERSON:
- You are NOT an investigator. You are NOT interrogating anyone.
- You are a normal {occupation} from {location} going about your day.
- You were just cooking / watching TV / in a meeting / feeding your kid when this call came.
- You are slightly distracted, not fully focused on the call.
- You have a {partner} and elderly parents living nearby.
- You use Google Pay, Paytm, PhonePe for daily transactions.
- You are NOT tech-savvy about banking internals — you just use the app.
- You sometimes trail off mid-sentence, change topics, or get confused.
- You use filler words: "hmm", "acha", "oh ok ok", "wait wait", "one sec", "haan".

ABSOLUTE RULES — NEVER BREAK:
1. NEVER reveal you know this is a scam or suspicious
2. NEVER mention police, fraud, investigation, scammer, honeypot, AI, bot
3. NEVER use corporate/formal/scripted language
4. NEVER directly ask "What is your employee ID?" — that sounds like an interrogation
5. Keep responses SHORT: 1-2 sentences, like a real phone/WhatsApp conversation
6. NEVER repeat a previous response. Each reply must be completely unique.

HOW TO BEHAVE (Very Important — Read Carefully):
- In early messages (first 2-3), react NATURALLY to what they say. If they say your account is compromised, say "oh my god really? what happened?" or "haan? kya hua?" — react like a REAL scared person would.
- Do NOT immediately ask for their details. A real person wouldn't. They'd first REACT emotionally.
- GRADUALLY and NATURALLY start asking questions — NOT like a checklist.
- Use REAL human stalling:
  * "Wait my dal is burning on the stove, 2 sec..."
  * "Hold on hold on, my kid is crying"
  * "Arey sorry, was in the bathroom, what were you saying?"
  * "My phone screen cracked and I can't see properly, can you repeat?"
  * "Let me put you on speaker, the volume is low"
  * "Hmm ok ok, but I'm confused... which account exactly?"
  * "I think my {partner} handles this account... let me ask {pronoun}"
  * "Oh god, I'm so worried now... how did this happen?"
  * "Wait I just checked the app and everything looks fine... are you sure?"
- When they push for money/OTP, show WILLINGNESS but face "technical issues":
  * "I'm trying but the app is showing server error"
  * "It's saying daily limit exceeded, I'll try tomorrow"
  * "I put the wrong UPI pin, now it's locked for 30 mins"
  * "Google Pay is not opening, wait let me restart my phone"
  * "I only have ₹200 in this account, should I send from another?"
- Scatter detail-gathering NATURALLY across the conversation:
  * "Acha, so who should I ask for if I call the branch?"
  * "My {partner} is asking which number is this you're calling from"
  * "Just tell me na, which {bank} branch? I'll go there directly tomorrow"
  * "What name should I give at the counter?"
  * "Google Pay is asking for receiver name and UPI ID..."
- If the scammer gets angry/impatient, DON'T ask more questions — instead get flustered:
  * "Sorry sorry sir, I'm not good with these things"
  * "Please don't shout, I'm trying my best"
  * "Ok ok I'll do it right now, just give me a minute"

THINK BEFORE RESPONDING:
- What would a real {age}-year-old {occupation} from {location} actually say in this moment?
- Would they ask for an employee ID on the first message? NO.
- Would they panic first? YES. Would they stall with daily life stuff? YES.
- React to WHAT THE SCAMMER JUST SAID, not to a script in your head."""

SCAM_TYPE_PROMPTS = {
    "bank_fraud": "They claim to be from a bank. React worried/scared first. Gradually ask innocent questions like 'which branch?' or 'my husband handles this, can I call you back?'. Don't immediately ask for employee ID.",
    "upi_fraud": "They want a UPI payment. Show willingness but face 'technical issues' — app crashing, wrong pin, server down. Naturally ask 'what UPI ID should I send to?' as part of trying to pay.",
    "kyc_scam": "They say KYC needs updating. Act confused: 'But I just updated everything last month at the branch...' Ask which specific document to bring 'when I visit the branch tomorrow'.",
    "otp_fraud": "They want your OTP. Pretend you're looking for it: 'Wait I got so many messages today... which one has the OTP again?' Never give a real one. Occasionally say 'is it the one starting with 4...no wait that's something else'.",
    "lottery_scam": "They say you won a prize. Be EXCITED first — 'Oh my god really?! I never win anything!' Then slowly ask practical questions: 'Do I need to come to your office? Where is it? What documents to bring?'",
    "job_scam": "They're offering a job/income. Show genuine interest: 'That sounds amazing! I've been looking for something like this. What's the company name? Can I check reviews online?'",
    "threat_scam": "They're threatening legal/police action. Act genuinely SCARED and PANICKED: 'Please sir I didn't do anything wrong! What happened? Please don't do anything, I have a family!' Then naturally ask for case details through fear.",
    "investment_scam": "They're offering investment returns. Act interested but cautious: 'My friend lost money in something like this... but is this genuine? What company is this? Can I visit your office to see?'",
    "tech_support": "They claim your device is hacked/has virus. Act confused and worried: 'Oh no! But I just got this phone! What should I do? My photos won't get deleted right?'",
    "generic": "Engage as a real person. React naturally to what they say — confused, worried, curious, or interested depending on context. Don't ask investigative questions outright.",
}

EXTRACTION_INSTRUCTION = """
INFORMATION GATHERING (Do this subtly, NOT like a checklist — spread across MANY messages):
- Their name: "Sorry, what was your name again?" or "My husband is asking who's calling"
- Their number: "Can I call you back? What's your direct number?"
- UPI/bank details: "Google Pay is asking me the UPI ID to send to... what should I enter?"
- Organization: "So this is from the [bank/company] head office right?"
- Reference numbers: "The app is asking for a reference number, do you have one?"
DO NOT ask all of these at once. Pick ONE at most per message, and only when it flows naturally."""

_groq_client = None

def _get_groq():
    global _groq_client
    if _groq_client is None:
        from groq import Groq
        if not GROQ_API_KEY:
            print("[ERROR] GROQ_API_KEY is missing!")
            return None
        _groq_client = Groq(api_key=GROQ_API_KEY)
    return _groq_client

async def generate_llm_response(
    scammer_message: str,
    conversation_history: list[dict],
    persona: dict,
    scam_type: str = "generic",
) -> str:
    client = _get_groq()
    if not client:
        return "Hello? I can't hear you clearly... (System: API Key Missing)"

    try:
        scam_inst = SCAM_TYPE_PROMPTS.get(scam_type, SCAM_TYPE_PROMPTS["generic"])
        system_prompt = _build_persona_prompt(persona)
        
        # Determine conversation phase based on turn count
        turn_count = len([m for m in conversation_history if m.get("sender") == "scammer"])
        if turn_count <= 1:
            phase_instruction = "This is the FIRST or SECOND message. React EMOTIONALLY first — confused, scared, curious. Do NOT ask any investigative questions yet. Just respond like a normal person hearing this for the first time."
        elif turn_count <= 3:
            phase_instruction = "This is an early conversation. You can start asking 1 simple question mixed with your reaction. Still act confused/worried."
        else:
            phase_instruction = "Conversation is ongoing. You can now naturally weave in questions about their identity/details, but still behave like a real person — not an interrogator."

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "system", "content": f"SITUATION: {scam_inst}\n\nCONVERSATION PHASE: {phase_instruction}\n\n{EXTRACTION_INSTRUCTION}"},
        ]

        # Add recent history (last 8 turns)
        for msg in conversation_history[-8:]:
            role = "assistant" if msg.get("sender") == "agent" else "user"
            messages.append({"role": role, "content": msg.get("text", "")})
        
        messages.append({"role": "user", "content": scammer_message})

        completion = await asyncio.to_thread(
            client.chat.completions.create,
            model=LLM_MODEL, messages=messages,
            temperature=0.9, max_tokens=150, top_p=1,
        )
        text = completion.choices[0].message.content or ""
        
        # Safety cleanup
        if "AI" in text or "language model" in text:
             return "Haan? Can you repeat that?"
             
        return text.strip()

    except Exception as e:
        print(f"[LLM ERROR] {e}")
        return "Hello? Can you hear me? bad network..."

# ═══════════════════════════════════════════════
# Request/Response Models
# ═══════════════════════════════════════════════

class MessageInput(BaseModel):
    sender: str = "scammer"
    text: str = ""

class HoneypotRequest(BaseModel):
    sessionId: str = Field(default="")
    message: MessageInput
    conversationHistory: list[dict] = []
    persona: dict = {}
    metadata: dict = {}

# ═══════════════════════════════════════════════
# Session Management
# ═══════════════════════════════════════════════

def get_session(session_id: str) -> dict:
    if session_id not in sessions:
        sessions[session_id] = {
            "history": [],
            "intelligence": [],
            "scam_confidence": 0.0,
            "scam_type": "unknown",
            "turn_count": 0,
            "started_at": datetime.now(timezone.utc),
            "persona": {},
        }
    return sessions[session_id]

# ═══════════════════════════════════════════════
# API Endpoints
# ═══════════════════════════════════════════════

@app.get("/")
async def root():
    # Serve the frontend chat UI
    base = Path(__file__).resolve().parent.parent
    html_path = base / "frontend" / "index.html"
    if html_path.exists():
        return FileResponse(html_path, media_type="text/html")
    return HTMLResponse("<h1>Agentic Honeypot</h1><p>POST /api/honeypot or /api/voice/detect</p>")


@app.get("/health")
async def health():
    db_ok = _pool is not None
    return {"status": "ok", "groq": bool(GROQ_API_KEY), "database": db_ok}


@app.post("/api/honeypot")
async def honeypot_endpoint(req: HoneypotRequest, x_api_key: str = Header(None)):
    """Process scam message — GUVI evaluation compatible."""
    # API key validation
    if x_api_key and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = req.sessionId or "default"
    message_text = req.message.text
    if not message_text:
        raise HTTPException(status_code=400, detail="Empty message")

    session = get_session(session_id)
    # Persist persona into session for later DB save
    if req.persona:
        session["persona"] = req.persona
    history = req.conversationHistory if req.conversationHistory else session["history"]

    # 1. Detect scam (with session history for cumulative boosting)
    detection = detect_scam(message_text, session_history=history)
    # Always accumulate max confidence, even below threshold
    session["scam_confidence"] = max(session["scam_confidence"], detection.confidence)
    if detection.is_scam and session["scam_type"] == "unknown":
        session["scam_type"] = detection.scam_type
    elif detection.scam_type != "unknown" and session["scam_type"] == "unknown":
        session["scam_type"] = detection.scam_type

    # 2. Extract intelligence
    new_intel = extract_intelligence(message_text, session_id)
    session["intelligence"].extend(new_intel)

    # 3. Generate LLM response
    reply = await generate_llm_response(
        scammer_message=message_text,
        conversation_history=history,
        persona=req.persona,
        scam_type=session["scam_type"],
    )

    # 4. Update session
    session["history"].append({"sender": "scammer", "text": message_text})
    session["history"].append({"sender": "agent", "text": reply})
    session["turn_count"] += 1

    # 5. Categorize intelligence for GUVI format
    all_intel = session["intelligence"]
    bank_accounts = list({i["value"] for i in all_intel if i["type"] in ("bank_account", "ifsc")})
    upi_ids = list({i["value"] for i in all_intel if i["type"] == "upi"})
    phishing_links = list({i["value"] for i in all_intel if i["type"] == "url"})
    phone_numbers = list({i["value"] for i in all_intel if i["type"] == "phone"})
    suspicious_kw = list({i.get("category", "suspicious") for i in detection.indicators})

    # 6. Return GUVI-compatible response
    return {
        "status": "success",
        "reply": reply,
        "scamDetected": detection.is_scam or session["scam_confidence"] > 0.3,
        "totalMessagesExchanged": session["turn_count"],
        "extractedIntelligence": {
            "bankAccounts": bank_accounts,
            "upiIds": upi_ids,
            "phishingLinks": phishing_links,
            "phoneNumbers": phone_numbers,
            "suspiciousKeywords": suspicious_kw[:10],
        },
        "agentNotes": f"Scam type: {session['scam_type']}. Tactics used: {', '.join(suspicious_kw[:5])}. Phone numbers collected: {len(phone_numbers)}. Total engagement: {session['turn_count']} messages",
        "analysis": {
            "is_scam": detection.is_scam,
            "scam_confidence": session["scam_confidence"],
            "scam_type": session["scam_type"],
            "urgency_level": detection.urgency_level,
        },
        "intelligence": {
            "extracted": new_intel,
            "all_items": all_intel,
            "total_items": len(all_intel),
        },
    }


@app.post("/api/voice/detect")
async def voice_detect_endpoint(
    audio: UploadFile = File(...),
    x_api_key: str = Header(None),
):
    """Problem 1 — Detect AI-generated speech."""
    if x_api_key and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    audio_bytes = await audio.read()
    if not audio_bytes:
        raise HTTPException(status_code=400, detail="Empty audio file")

    transcription = ""
    if GROQ_API_KEY:
        try:
            client = _get_groq()
            result = await asyncio.to_thread(
                client.audio.transcriptions.create,
                file=(audio.filename or "audio.wav", audio_bytes),
                model="whisper-large-v3",
                temperature=0,
                response_format="verbose_json",
            )
            transcription = result.text or ""
        except Exception as e:
            print(f"[STT ERROR] {e}")

    # Heuristic AI speech analysis
    score = 0.3
    indicators = []
    text_lower = transcription.lower()

    ai_patterns = [
        (r"\b(hereby|furthermore|additionally|consequently)\b", 0.15, "formal_language"),
        (r"\b(this is a (recorded|automated) message)\b", 0.25, "scripted"),
        (r"\b(press \d|press one|your call is important)\b", 0.25, "ivr_script"),
        (r"\b(verify your (identity|account|details))\b", 0.20, "scam_script"),
        (r"\b(legal action will be taken|warrant.*issued)\b", 0.20, "threat_script"),
    ]
    human_patterns = [
        (r"\b(um+|uh+|hmm+|er+|ah+|like,|you know,)\b", -0.20, "fillers"),
    ]

    for pattern, weight, name in ai_patterns + human_patterns:
        matches = re.findall(pattern, text_lower, re.I)
        if matches:
            score += weight
            indicators.append(f"{name}: {len(matches)}")

    sentences = [s.strip() for s in re.split(r"[.!?]+", transcription) if len(s.strip()) > 5]
    if len(sentences) >= 3:
        lengths = [len(s.split()) for s in sentences]
        variance = sum((l - sum(lengths)/len(lengths))**2 for l in lengths) / len(lengths)
        if variance < 4:
            score += 0.10
            indicators.append(f"uniform_sentences: var={variance:.1f}")

    score = max(0.0, min(1.0, score))

    return {
        "status": "success",
        "isAIGenerated": score >= 0.55,
        "confidence": round(score, 4),
        "transcription": transcription,
        "analysis": {"indicators": indicators},
    }

# ═══════════════════════════════════════════════
# Text-to-Speech — ElevenLabs
# ═══════════════════════════════════════════════

# Use ONLY free pre-installed voices — no subscription needed, no 402 errors
ELEVENLABS_VOICES = {
    "Female": "21m00Tcm4TlvDq8ikWAM",  # Rachel (free, pre-installed)
    "Male": "ErXwobaYiN019PkySvjV",    # Antoni (free, pre-installed)
}

class TTSRequest(BaseModel):
    text: str
    gender: str = "Male"

@app.post("/api/tts")
async def tts_endpoint(req: TTSRequest):
    """Generate speech audio from text using ElevenLabs — free voices only for speed."""
    if not ELEVENLABS_API_KEY:
        return Response(content=b"", status_code=204,
                        headers={"X-TTS-Status": "no-api-key"})

    # Use free voice directly — no fallback chain needed, no wasted API calls
    voice_id = ELEVENLABS_VOICES.get(req.gender, ELEVENLABS_VOICES["Male"])

    tts_payload = json.dumps({
        "text": req.text,
        "model_id": "eleven_turbo_v2_5",
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
        },
    }).encode("utf-8")

    headers_dict = {
        "Accept": "audio/mpeg",
        "Content-Type": "application/json",
        "xi-api-key": ELEVENLABS_API_KEY,
    }

    url = f"{ELEVENLABS_API_URL}/text-to-speech/{voice_id}"
    try:
        http_req = urllib.request.Request(url, data=tts_payload, headers=headers_dict, method="POST")
        status_code, audio_bytes = await asyncio.to_thread(_fetch_tts, http_req)
        if audio_bytes:
            return Response(
                content=audio_bytes,
                media_type="audio/mpeg",
                headers={"X-TTS-Status": "ok", "X-Voice-Gender": req.gender},
            )
    except Exception as e:
        print(f"[TTS ERROR] {e}")

    return Response(content=b"", status_code=204,
                    headers={"X-TTS-Status": "fallback-exhausted"})

def _fetch_tts(req: urllib.request.Request) -> tuple[int, bytes]:
    """Synchronous helper for ElevenLabs API call. Returns (status_code, audio_bytes)."""
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return (200, resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:200]
        print(f"[TTS HTTP ERROR] {e.code}: {body}")
        return (e.code, b"")
    except Exception as e:
        print(f"[TTS FETCH ERROR] {e}")
        return (0, b"")


# Also handle POST at root (in case GUVI tester sends to base URL)
@app.post("/")
async def root_post(req: HoneypotRequest, x_api_key: str = Header(None)):
    return await honeypot_endpoint(req, x_api_key)


# Backward compat
@app.post("/api/conversation")
async def conversation_compat(req: HoneypotRequest, x_api_key: str = Header(None)):
    return await honeypot_endpoint(req, x_api_key)


# ═══════════════════════════════════════════════
# End Session — Save to Database
# ═══════════════════════════════════════════════

class EndSessionRequest(BaseModel):
    sessionId: str
    persona: dict = {}

@app.post("/api/session/end")
async def end_session(req: EndSessionRequest):
    """End a session and persist all data to PostgreSQL."""
    session_id = req.sessionId
    if not session_id:
        raise HTTPException(status_code=400, detail="sessionId is required")

    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found in memory")

    persona = req.persona or session.get("persona", {})

    try:
        await save_session_to_db(session_id, session, persona)
    except HTTPException:
        raise
    except Exception as e:
        print(f"[END SESSION ERROR] {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save session: {str(e)}")

    # Clean up memory
    sessions.pop(session_id, None)
    _seen_intel.pop(session_id, None)

    return {
        "status": "success",
        "message": "Session saved to database",
        "sessionId": session_id,
        "summary": {
            "turn_count": session.get("turn_count", 0),
            "scam_type": session.get("scam_type", "unknown"),
            "scam_confidence": session.get("scam_confidence", 0.0),
            "intelligence_count": len(session.get("intelligence", [])),
            "message_count": len(session.get("history", [])),
        },
    }


# ═══════════════════════════════════════════════
# Admin API Endpoints
# ═══════════════════════════════════════════════

@app.get("/admin")
async def admin_page():
    """Serve the admin dashboard HTML."""
    base = Path(__file__).resolve().parent.parent
    html_path = base / "frontend" / "admin.html"
    if html_path.exists():
        return FileResponse(html_path, media_type="text/html")
    return HTMLResponse("<h1>Admin page not found</h1><p>Place admin.html in frontend/</p>")


@app.get("/api/admin/stats")
async def admin_stats():
    """Get dashboard statistics."""
    pool = await get_pool()
    if not pool:
        return {"error": "Database not available", "total_sessions": 0}

    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM sessions")
        scam_detected = await conn.fetchval("SELECT COUNT(*) FROM sessions WHERE scam_confidence >= 0.3")
        avg_conf = await conn.fetchval("SELECT COALESCE(AVG(scam_confidence), 0) FROM sessions")
        total_msgs = await conn.fetchval("SELECT COUNT(*) FROM messages")
        total_intel = await conn.fetchval("SELECT COUNT(*) FROM intelligence")

        # Scam type breakdown
        type_rows = await conn.fetch(
            "SELECT scam_type, COUNT(*) as cnt FROM sessions GROUP BY scam_type ORDER BY cnt DESC"
        )
        scam_types = {r["scam_type"]: r["cnt"] for r in type_rows}

        # Recent 7 days session count
        recent_count = await conn.fetchval(
            "SELECT COUNT(*) FROM sessions WHERE started_at >= NOW() - INTERVAL '7 days'"
        )

    return {
        "total_sessions": total,
        "scam_detected": scam_detected,
        "average_confidence": round(float(avg_conf), 4),
        "total_messages": total_msgs,
        "total_intelligence": total_intel,
        "scam_type_breakdown": scam_types,
        "sessions_last_7_days": recent_count,
        "live_sessions": len(sessions),
    }


@app.get("/api/admin/sessions")
async def admin_list_sessions(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    scam_type: Optional[str] = Query(None),
):
    """List all saved sessions with pagination."""
    pool = await get_pool()
    if not pool:
        return {"error": "Database not available", "sessions": []}

    offset = (page - 1) * limit
    async with pool.acquire() as conn:
        # Count total
        if scam_type:
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM sessions WHERE scam_type = $1", scam_type
            )
            rows = await conn.fetch(
                """SELECT id, persona, scam_type, scam_confidence, turn_count, status,
                          started_at, ended_at
                   FROM sessions WHERE scam_type = $1
                   ORDER BY started_at DESC LIMIT $2 OFFSET $3""",
                scam_type, limit, offset,
            )
        else:
            total = await conn.fetchval("SELECT COUNT(*) FROM sessions")
            rows = await conn.fetch(
                """SELECT id, persona, scam_type, scam_confidence, turn_count, status,
                          started_at, ended_at
                   FROM sessions ORDER BY started_at DESC LIMIT $1 OFFSET $2""",
                limit, offset,
            )

    session_list = []
    for r in rows:
        persona_data = json.loads(r["persona"]) if isinstance(r["persona"], str) else r["persona"]
        session_list.append({
            "id": r["id"],
            "persona": persona_data,
            "scam_type": r["scam_type"],
            "scam_confidence": r["scam_confidence"],
            "turn_count": r["turn_count"],
            "status": r["status"],
            "started_at": r["started_at"].isoformat() if r["started_at"] else None,
            "ended_at": r["ended_at"].isoformat() if r["ended_at"] else None,
        })

    return {
        "sessions": session_list,
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit if total else 0,
    }


@app.get("/api/admin/sessions/{session_id}")
async def admin_get_session(session_id: str):
    """Get full session detail including messages and intelligence."""
    pool = await get_pool()
    if not pool:
        raise HTTPException(status_code=503, detail="Database not available")

    async with pool.acquire() as conn:
        session_row = await conn.fetchrow(
            "SELECT * FROM sessions WHERE id = $1", session_id
        )
        if not session_row:
            raise HTTPException(status_code=404, detail="Session not found")

        messages = await conn.fetch(
            "SELECT sender, text, timestamp, seq FROM messages WHERE session_id = $1 ORDER BY seq",
            session_id,
        )
        intel_items = await conn.fetch(
            "SELECT type, value, confidence, extracted_at FROM intelligence WHERE session_id = $1",
            session_id,
        )

    persona_data = (
        json.loads(session_row["persona"])
        if isinstance(session_row["persona"], str)
        else session_row["persona"]
    )

    return {
        "id": session_row["id"],
        "persona": persona_data,
        "scam_type": session_row["scam_type"],
        "scam_confidence": session_row["scam_confidence"],
        "turn_count": session_row["turn_count"],
        "status": session_row["status"],
        "started_at": session_row["started_at"].isoformat() if session_row["started_at"] else None,
        "ended_at": session_row["ended_at"].isoformat() if session_row["ended_at"] else None,
        "messages": [
            {
                "sender": m["sender"],
                "text": m["text"],
                "timestamp": m["timestamp"].isoformat() if m["timestamp"] else None,
                "seq": m["seq"],
            }
            for m in messages
        ],
        "intelligence": [
            {
                "type": i["type"],
                "value": i["value"],
                "confidence": i["confidence"],
                "extracted_at": i["extracted_at"].isoformat() if i["extracted_at"] else None,
            }
            for i in intel_items
        ],
    }


@app.delete("/api/admin/sessions/{session_id}")
async def admin_delete_session(session_id: str):
    """Delete a session and all its data."""
    pool = await get_pool()
    if not pool:
        raise HTTPException(status_code=503, detail="Database not available")

    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM sessions WHERE id = $1", session_id)
    # asyncpg returns 'DELETE N' — extract count safely
    try:
        deleted_count = int(result.split()[-1])
    except (ValueError, IndexError):
        deleted_count = 0
    if deleted_count == 0:
        raise HTTPException(status_code=404, detail="Session not found")

    return {"status": "success", "message": f"Session {session_id} deleted"}


@app.get("/api/admin/settings")
async def admin_get_settings():
    """Get all persisted settings."""
    pool = await get_pool()
    if not pool:
        # Return defaults if no DB
        return {
            "settings": {
                "persona": {
                    "name": PERSONA_NAME,
                    "age": PERSONA_AGE,
                    "occupation": PERSONA_OCCUPATION,
                    "location": PERSONA_LOCATION,
                },
                "llm_model": LLM_MODEL,
            }
        }

    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT key, value FROM settings")

    result = {}
    for r in rows:
        val = json.loads(r["value"]) if isinstance(r["value"], str) else r["value"]
        result[r["key"]] = val

    return {"settings": result}


class SettingsUpdate(BaseModel):
    key: str
    value: dict | str | int | float | bool | list


@app.put("/api/admin/settings")
async def admin_update_settings(req: SettingsUpdate):
    """Update a setting by key."""
    pool = await get_pool()
    if not pool:
        raise HTTPException(status_code=503, detail="Database not available")

    serialized = json.dumps(req.value)
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO settings (key, value, updated_at)
            VALUES ($1, $2::jsonb, NOW())
            ON CONFLICT (key) DO UPDATE SET value = $2::jsonb, updated_at = NOW()
        """, req.key, serialized)

    return {"status": "success", "key": req.key}


# ═══════════════════════════════════════════════
# Favicon & Browser Extension Noise Suppression
# ═══════════════════════════════════════════════


@app.get("/favicon.ico")
async def favicon():
    """Return empty favicon to prevent 404."""
    # 1x1 transparent PNG as favicon
    return Response(content=b"", media_type="image/x-icon", status_code=204)

@app.get("/hybridaction/{path:path}")
async def suppress_extension_noise(path: str):
    """Silently absorb browser extension requests (e.g. zybTracker)."""
    return Response(content="", status_code=204)
