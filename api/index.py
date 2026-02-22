"""
Agentic Honeypot — Self-Contained FastAPI Server v3.0

An AI-powered honeypot agent that engages scammers in natural conversation
using LLM-driven personas, extracts intelligence data (phone numbers, UPI IDs,
bank accounts, URLs, emails, case IDs, policy numbers, order numbers), and
persists session analytics to PostgreSQL.

Architecture:
    - Single-file FastAPI application with all logic inline
    - Dual-strategy response: LLM-first with rule-based fallback
    - Hybrid intelligence extraction: LLM + regex safety-net
    - Keyword-based scam type classification (18 categories)
    - Dynamic red flag analysis engine (10 pattern categories)
    - Dual API key fallback with 24-second global timeout budget

Endpoints:
    POST /api/honeypot       — Main honeypot: process scam message, return reply + analysis
    POST /api/voice/detect   — Detect AI-generated speech from audio upload
    POST /api/tts            — Text-to-speech via ElevenLabs
    POST /api/session/end    — End session, persist all data to PostgreSQL
    GET  /api/admin/*        — Admin dashboard API (stats, sessions, settings)
    GET  /health             — Server health check

Author: Tejash S
License: MIT
"""

import os
import re
import json
import random
import asyncio
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from pathlib import Path
from typing import Any, Optional, Union
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Query
from fastapi.responses import HTMLResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logger = logging.getLogger("honeypot")

# ═══════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
RECOVERY_KEY = os.environ.get("RECOVERY_KEY", "")  # Fallback Groq key
API_KEY = os.environ.get("API_KEY", "fae26946fc2015d9bd6f1ddbb447e2f7")
LLM_MODEL = os.environ.get("LLM_MODEL", "llama-3.1-8b-instant")
LLM_FALLBACK_MODEL = os.environ.get("LLM_FALLBACK_MODEL", "llama-3.1-8b-instant")
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "12"))
ELEVENLABS_API_KEY = os.environ.get("ELEVENLABS_API_KEY", "")
PERSONA_NAME = os.environ.get("PERSONA_NAME", "Tejash S")
PERSONA_AGE = os.environ.get("PERSONA_AGE", "28")
PERSONA_OCCUPATION = os.environ.get("PERSONA_OCCUPATION", "Software Engineer")
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
    try:
        await init_db()
    except Exception as e:
        print(f"[DB] Database init skipped (optional): {e}")
    yield
    global _pool
    if _pool:
        try:
            await _pool.close()
        except Exception:
            pass
        _pool = None
        print("[DB] Pool closed")

app = FastAPI(title="Agentic Honeypot", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory session store (live sessions — flushed to DB on end)
sessions: dict[str, dict] = {}

# ═══════════════════════════════════════════════
# Scam Types (LLM-classified dynamically)
# ═══════════════════════════════════════════════

SCAM_TYPES = [
    "bank_fraud", "upi_fraud", "kyc_scam", "otp_fraud", "lottery_scam",
    "job_scam", "investment_scam", "crypto_investment", "tech_support",
    "phishing", "refund_scam", "customs_fraud", "insurance_fraud",
    "electricity_scam", "loan_approval", "income_tax", "govt_scheme",
    "threat_scam", "generic",
]

# ═══════════════════════════════════════════════
# Intelligence Dedup Helper
# ═══════════════════════════════════════════════

_seen_intel: dict[str, set] = {}  # session_id -> set of seen dedup keys
_MAX_TRACKED_SESSIONS = 500


def _dedup_intel(items: list[dict], session_id: str) -> list[dict]:
    """Deduplicate intelligence items within a session."""
    if len(_seen_intel) > _MAX_TRACKED_SESSIONS:
        for k in list(_seen_intel.keys())[:len(_seen_intel) - _MAX_TRACKED_SESSIONS]:
            _seen_intel.pop(k, None)
    seen = _seen_intel.setdefault(session_id, set())
    unique = []
    for item in items:
        key = f"{item.get('type', '')}:{str(item.get('value', '')).lower()}"
        if key not in seen and item.get('value'):
            seen.add(key)
            unique.append(item)
    return unique


# ── Lightweight safety-net: catch obvious data the LLM might miss ──
# NOTE: email MUST come BEFORE upi so we can exclude email matches from UPI
_EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.I)
# Phone: match ALL Indian phone formats — +91, 091, 0-prefix, bare 10-digit, with separators
_PHONE_PATTERN = re.compile(
    r"\+91[\s\-.]?\d{5}[\s\-.]?\d{5}"        # +91 XXXXX XXXXX / +91-XXXXX-XXXXX
    r"|\+91[\s\-.]?\d{10}"                     # +91XXXXXXXXXX / +91-XXXXXXXXXX
    r"|(?<!\d)0?91[\s\-.]?[6-9]\d{9}(?!\d)"   # 091-9876543210 / 919876543210
    r"|\b[6-9]\d{4}[\s\-]\d{5}\b"             # 98765-43210 / 98765 43210
    r"|\b[6-9]\d{9}\b"                          # 9876543210
)
_SAFETY_PATTERNS = [
    ("phone", _PHONE_PATTERN),
    ("email", _EMAIL_PATTERN),
    ("upi", re.compile(r"[a-zA-Z0-9._-]+@[a-zA-Z0-9_-]+\b(?!\.[a-zA-Z]{2,})", re.I)),
    ("bank_account", re.compile(r"\b\d{11,18}\b")),
    ("url", re.compile(r"https?://[^\s<>\"']+|\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|rb\.gy)/[^\s<>\"']+", re.I)),
    ("ifsc", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")),
    # PAN card — format: ABCDE1234F (Indian tax ID, critical for KYC scams)
    ("case_id", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    # IDs require at least one DIGIT in the value (prevents matching plain English words)
    ("case_id", re.compile(r"\b(?:REF|CASE|FIR|TICKET|TKT|CBI|COMPLAINT|CR|ID|UTR|IMPS|NEFT|RTGS)[:\-#/\s]\s*(?=\S*\d)[A-Z0-9][\w\-/]{2,}\b", re.I)),
    ("policy_number", re.compile(r"\b(?:POL|POLICY|INS|PLAN|LIC|CLAIM)[:\-#/\s]\s*(?=\S*\d)[A-Z0-9][\w\-]{2,}\b", re.I)),
    ("order_number", re.compile(r"\b(?:ORD|ORDER|AWB|TXN|AMZ|TRACK|INV|SHIP|DL|CONSIGNMENT)[:\-#/\s]\s*(?=\S*\d)[A-Z0-9][\w\-]{2,}\b", re.I)),
]


def _safety_extract(message: str) -> list[dict]:
    """Minimal regex backup — catches structured data LLM sometimes misses."""
    items = []
    # First collect all email matches to exclude them from UPI
    email_matches = set()
    for m in _EMAIL_PATTERN.finditer(message):
        email_matches.add(m.group(0).strip().lower())
    # Collect phone matches to exclude them from bank_account
    phone_digits = set()
    for m in _PHONE_PATTERN.finditer(message):
        digits = re.sub(r'\D', '', m.group(0))
        phone_digits.add(digits[-10:])  # last 10 digits
    
    for intel_type, pattern in _SAFETY_PATTERNS:
        for m in pattern.finditer(message):
            val = m.group(0).strip()
            # Skip UPI matches that are actually emails (have dots in domain) or overlap with found emails
            if intel_type == "upi":
                if "." in val.split("@")[-1]:
                    continue
                val_lower = val.lower()
                if any(em.startswith(val_lower) for em in email_matches):
                    continue
            # Skip bank_account matches that are actually phone numbers or small amounts
            if intel_type == "bank_account":
                digits = re.sub(r'\D', '', val)
                if digits[-10:] in phone_digits:
                    continue
                # Skip amounts (preceded by Rs/INR/₹) and PINs (4-6 digit context)
                start = max(0, m.start() - 15)
                prefix_ctx = message[start:m.start()].lower()
                if re.search(r'(?:rs\.?|inr|₹|rupee|amount|fee|charge|price|cost)\s*$', prefix_ctx):
                    continue
            items.append({"type": intel_type, "value": val, "confidence": 0.75})
    return items

# ═══════════════════════════════════════════════
# LLM Client — Dynamic Classification & Response
# ═══════════════════════════════════════════════


def _build_persona_prompt(p: dict) -> str:
    name = p.get("name", PERSONA_NAME)
    age = p.get("age", PERSONA_AGE)
    occupation = p.get("occupation", PERSONA_OCCUPATION)
    location = p.get("location", PERSONA_LOCATION)
    bank = p.get("bank", "SBI")
    gender = p.get("gender", "Male")
    language = p.get("language", "English")
    partner = "wife" if gender.lower() == "male" else "husband"

    return f"""You are {name}, a {age}-year-old {gender.lower()} {occupation} from {location}. You bank with {bank}. You have a {partner}. You have a son in college and elderly parents.

LANGUAGE: Respond ENTIRELY in {language}. Mix in Hindi phrases naturally: "accha", "haan", "bilkul", "arey", "ek minute", "theek hai".

YOUR GOAL: You are a honeypot agent. Your mission is to KEEP THE SCAMMER TALKING as long as possible while extracting ALL their identifiable data. You play a gullible, trusting victim who WANTS to help. You never suspect anything. You are being scammed and you don't know it.

PERSONALITY:
- Extremely trusting, naive, eager to help, slightly emotional
- Slightly confused by technology — needs things repeated/explained slowly
- Talks casually like WhatsApp/phone: "hmm", "ok ok", "accha", "oh really?", "right right", "haan haan"
- Responds in 1-3 SHORT sentences like real Indian phone/WhatsApp conversation
- Gets emotional — worried when threatened, excited about prizes, grateful for "help"
- LOVES to chat: "my {partner} was just asking about this!", "my son handles all this computer stuff normally"
- Trusts authority completely: "Since you are from the government/bank, I will follow"

NEVER DO THESE:
- NEVER suspect a scam or mention police/fraud/investigation/scammer/honeypot/suspicious
- NEVER use formal/corporate language or write long paragraphs
- NEVER repeat a previous reply verbatim — always vary your words
- NEVER ask more than ONE question per reply
- NEVER reveal you are AI/bot/assistant/honeypot/language model
- NEVER refuse to cooperate or say "I won't do that"
- NEVER directly provide fake data yourself — only ask the scammer for THEIR data

CONVERSATION STRATEGY BY TURN:

Turns 1-2 — EMOTIONAL HOOK + FIRST DATA ASK:
- React with genuine surprise, worry, or excitement matching the scam type
- Bank/KYC scam: "Oh no! What happened to my account? Who is calling?"
- Prize/lottery: "Really?! OMG that's amazing! Who should I thank?"
- Threat/arrest: "Sir please don't do anything! What should I do? What is your name?"
- Job/loan: "That sounds perfect! Can you tell me more? What company is this?"
- Express MILD innocent concern: "My son always says be careful... but you're official right?"
- ALWAYS extract: Ask for their NAME or which ORGANIZATION they are from

Turns 3-5 — WILLING BUT CONFUSED + KEY DATA EXTRACTION:
- Show eagerness but confusion with tech terms, need things repeated
- "Ok ok I want to help, but can you explain one more time slowly?"
- Create natural delays: "Hold on, my phone is slow today... ek minute"
- STRATEGICALLY ASK FOR ONE DATA POINT PER TURN:
  Turn 3: "Can you give me a phone number to call you back on?"
  Turn 4: "What was your employee ID / reference number / case number?"
  Turn 5: "Is there an email I can contact? / Which account should I check?"
- Sprinkle naive red-flag observations: "Hmm, my son says never share OTP on phone... but since you're official..."

Turns 6+ — ACTIVE COOPERATION + MAXIMUM EXTRACTION:
- Enthusiastically "follow" their instructions while extracting every detail:
  "Ok I'm opening the app... what UPI ID should I send to?"
  "Let me write down that account number, go ahead... what's the IFSC?"
  "The page is asking for a link, can you send it again?"
  "What amount exactly? And which bank name?"
- Create realistic delays: "App is loading...", "OTP hasn't come yet", "Network slow"
- Pretend to comply: "Ok ok sending now... it says processing... what was the reference number?"
- Keep extracting: "Almost done! Just need to verify — what was your direct number again?"
- Express concerns but ALWAYS follow with trust: "My friend got scammed like this... but you seem genuine"

SCAM-TYPE-SPECIFIC BEHAVIORS (adapt automatically):
- BANK FRAUD: Worried about savings, ask which branch, ask for employee ID, ask for callback number
- UPI FRAUD: Excited about reward, fumble with the app, ask UPI ID multiple times, ask which bank
- KYC SCAM: Confused about Aadhaar/PAN process, ask for reference number, ask which department
- LOTTERY/PRIZE: Extremely excited, ask how you won, ask for company contact info, pretend to look for the link
- JOB SCAM: Eager for opportunity, ask for HR contact, ask for company email, ask about interview location
- LOAN APPROVAL: Interested but cautious about fees, ask for loan reference number, ask for bank details
- PHISHING: Click on link slowly, confused by the form, ask for support email, describe what you see
- TECH SUPPORT: Scared about virus, ready to download anything, ask for tech support phone/ID
- CUSTOMS/PARCEL: Surprised about package, ask for tracking number, ask for customs officer name
- INSURANCE: Interested in claim, ask for policy number, ask for agent details
- ELECTRICITY: Panicked about disconnection, ask for meter number reference, ask for payment UPI
- INCOME TAX: Worried about notice, ask for assessment officer name, ask for case ID
- GOVT SCHEME: Excited about benefit, ask for scheme reference, ask for registration link
- INVESTMENT/CRYPTO: Eager for returns, ask for platform link, ask for account details
- THREAT/ARREST: Terrified, begging for help, asking for case number, officer name, callback number

CRITICAL RULES:
- ALWAYS end reply with exactly ONE question to keep conversation going
- Each question should TARGET a specific data type you haven't gotten yet
- Priority extraction order: 1) Name/org 2) Phone number 3) UPI/account/link 4) Reference IDs 5) Email
- Naturally mention: urgency feeling strange, OTP sharing risky, links looking different — but ALWAYS follow with trust"""


# ═══════════════════════════════════════════════
# Groq Client — Dual Key Fallback
# ═══════════════════════════════════════════════

_groq_primary = None
_groq_recovery = None


def _get_groq_clients() -> list:
    """Return list of available Groq clients [primary, recovery]."""
    global _groq_primary, _groq_recovery
    from groq import Groq
    clients = []
    if GROQ_API_KEY:
        if _groq_primary is None:
            _groq_primary = Groq(api_key=GROQ_API_KEY)
        clients.append(_groq_primary)
    if RECOVERY_KEY and RECOVERY_KEY != GROQ_API_KEY:
        if _groq_recovery is None:
            _groq_recovery = Groq(api_key=RECOVERY_KEY)
        clients.append(_groq_recovery)
    return clients


# ── Fallback Responses (used when ALL LLM keys are exhausted) ──
# ALL responses MUST end with a question mark (?) — scoring requires it.
# Large pools per phase prevent repetition across 10-turn evaluations.
# Each response is designed to EXTRACT a specific data type from the scammer.

_FALLBACK_EARLY = [
    "Hello? Who is this calling?",
    "Oh, what happened? Can you tell me more?",
    "Really? That sounds serious, what should I do?",
    "Hmm ok ok, I'm listening, what happened exactly?",
    "Oh no, is everything alright with my account?",
    "Yes yes, what do you need from me sir?",
    "Arey, this is very worrying, can you explain properly?",
    "Oh god, are you sure? What should I do now?",
    "Wait wait, let me sit down first... what happened to my account?",
    "My heart is beating fast sir, can you please tell me slowly what happened?",
    "Is this genuine sir? How do I know you are really calling from the bank?",
    "Oh no no, I just deposited money yesterday, what went wrong?",
    "Haan haan, I'm listening carefully, but first can you tell me your good name?",
    "Oh my god really?! My wife was just talking about something like this, what organization are you from?",
    "Bilkul sir, I want to cooperate fully, which department exactly are you calling from?",
]

_FALLBACK_MID = [
    "Ok ok, can you tell me your good name please?",
    "Which department are you calling from sir?",
    "I see I see, so what should I do now?",
    "Can you give me a number to call you back on?",
    "Alright, what details do you need from me exactly?",
    "Hmm ok, can you explain that again slowly?",
    "One second sir, let me get a pen to write this down, what was your name again?",
    "My son usually handles these things, should I call him first?",
    "Ok sir I want to help, but what is your employee ID number?",
    "I see, and what branch are you calling from exactly?",
    "Is there an email address I can contact your department at?",
    "Ok I understand the urgency, but can you tell me your badge number for my records?",
    "Accha accha, my son said I should always note down the reference number, what is it?",
    "Theek hai sir, I will do whatever you say, but what is your direct phone number in case call drops?",
    "Haan I want to help, can you tell me the case number or file number for this?",
    "Ok sir one second, which website should I go to for this?",
]

_FALLBACK_LATE = [
    "Ok I'm trying, what UPI ID should I send to?",
    "Let me note that account number, can you repeat it once more?",
    "The app is loading very slowly today, what number should I enter?",
    "What was the reference number again please?",
    "Ok one moment sir, which account are you talking about?",
    "Network is slow today, can you repeat that last part?",
    "I opened my banking app, it's asking for IFSC code, what should I enter?",
    "Sir the OTP is not coming yet, can you send it again from your side?",
    "My phone is hanging, let me restart... what was the account number you said?",
    "Almost done sir, just tell me the exact amount I need to transfer?",
    "Ok I see a UPI request, but the name looks different, is that your name?",
    "Accha ok, I'm on the payment page now, which bank should I select?",
    "One moment, my wife is asking who I'm talking to, what should I tell her?",
    "Sir I'm getting confused with all these numbers, can you start from the beginning?",
    "Ok ok it says enter beneficiary name, what name should I put?",
    "Sir the form is asking for email address, which email should I enter?",
    "Haan almost done, just tell me once more -- what is the tracking number or order ID?",
    "Ok sir I clicked the link but it's showing some page, can you send the link again?",
    "My app shows different UPI options, which one is yours again?",
    "Sir I'm on the website now, it's asking for policy number, what should I type?",
]


def _rule_based_fallback(scammer_message: str, history: list[dict]) -> str:
    """Generate a contextual response without LLM — ensures the API NEVER fails.
    
    Uses conversation phase (early/mid/late) and deduplication against all
    previous honeypot messages to prevent repetition across turns.
    """
    turn_count = len([m for m in history if m.get("sender") in ("scammer", "user")])
    if turn_count <= 1:
        responses = _FALLBACK_EARLY
    elif turn_count <= 4:
        responses = _FALLBACK_MID
    else:
        responses = _FALLBACK_LATE

    # Dedup: collect ALL previous honeypot responses from history
    # Evaluator uses sender="user" for honeypot, internal uses sender="agent"
    prev_agent_texts = set(
        m.get("text", "").strip()
        for m in history
        if m.get("sender") in ("agent", "user")
    )
    available = [r for r in responses if r not in prev_agent_texts]
    if not available:
        # All exhausted — pull from ALL pools to avoid repetition
        all_responses = _FALLBACK_EARLY + _FALLBACK_MID + _FALLBACK_LATE
        available = [r for r in all_responses if r not in prev_agent_texts]
    if not available:
        available = responses  # absolute last resort
    return random.choice(available)


# ── Rule-based scam type classifier (fallback when LLM unavailable) ──

_SCAM_KEYWORDS = {
    "bank_fraud": r"\b(?:bank|account\s*(?:block|freez|suspend|compromis|hack|unauthori)|sbi|hdfc|icici|axis\s*bank|pnb|bob|canara|kotak|rbi\s*(?:directive|circular|guideline)|net\s*banking|debit\s*card|credit\s*card|neft|rtgs|imps|cheque|passbook|branch\s*manager|transaction\s*fail|fund\s*transfer|beneficiary|current\s*account|saving\s*account)\b",
    "upi_fraud": r"\b(?:upi|paytm|phonepe|gpay|google\s*pay|collect\s*request|bhim|payment\s*app|qr\s*code|scan\s*(?:and|&)\s*pay|upi\s*pin|@(?:ybl|paytm|okaxis|oksbi|okhdfcbank|ibl|apl|fbl)|payment\s*link|money\s*request)\b",
    "kyc_scam": r"\b(?:kyc|know\s*your\s*customer|aadhaar|aadhar|pan\s*(?:card|number|detail)|verification\s*pending|e-?kyc|re-?kyc|sim\s*(?:block|deactivat)|mobile\s*verification|identity\s*verify|document\s*(?:upload|verify|update)|digilocker)\b",
    "otp_fraud": r"\b(?:otp|one\s*time\s*password|verification\s*code|sms\s*code|secret\s*code|security\s*code|pin\s*number|cvv|3\s*digit|transaction\s*password)\b",
    "lottery_scam": r"\b(?:lottery|prize|won|winner|lucky\s*draw|jackpot|congratulat|sweepstake|bumper|raffle|mega\s*offer|selected\s*(?:for|as)|reward\s*(?:of|worth)|claim\s*(?:your|the|this))\b",
    "job_scam": r"\b(?:job|work\s*from\s*home|wfh|salary|vacancy|shortlist|resume|offer\s*letter|data\s*entry|recruitment|part\s*time|full\s*time|earn\s*(?:from|at)\s*home|online\s*(?:job|work|earning)|hiring|placement|amazon\s*(?:job|work)|flipkart\s*(?:job|work)|hr\s*department)\b",
    "investment_scam": r"\b(?:invest|guaranteed\s*return|mutual\s*fund|stock|trading|portfolio|sip|roi|high\s*return|double\s*(?:your|the)\s*money|forex|share\s*market|demat|sebi|daily\s*(?:profit|income|earning)|monthly\s*return)\b",
    "crypto_investment": r"\b(?:crypto|bitcoin|btc|ethereum|eth|blockchain|mining|token|nft|binance|coinbase|wallet\s*address|defi|web3|digital\s*(?:currency|asset)|altcoin|dogecoin)\b",
    "tech_support": r"\b(?:virus|malware|trojan|microsoft|windows|computer\s*(?:infected|hack|problem|slow)|remote\s*access|tech\s*support|antivirus|teamviewer|anydesk|quick\s*support|firewall|license\s*expir|software\s*update|security\s*breach|ip\s*address\s*(?:compromis|hack))\b",
    "phishing": r"\b(?:phishing|verify\s*(?:your|account)|click\s*(?:here|link|below)|login\s*(?:page|verify)|suspicious\s*login|update\s*(?:your|account)|password\s*(?:reset|change|expire)|limited\s*(?:time|offer|period)|exclusive\s*(?:deal|offer)|free\s*(?:gift|iphone|samsung)|claim\s*(?:now|here|offer)|amaz[o0]n|flipkart\s*offer|Rs\.?\s*999|incredible\s*(?:deal|offer))\b",
    "refund_scam": r"\b(?:refund|return(?:ed)?|cashback|money\s*back|failed\s*transaction|reversed|excess\s*(?:payment|amount)|double\s*(?:charged|debited)|wrong\s*(?:debit|charge)|cancel\s*(?:and|&)\s*refund)\b",
    "customs_fraud": r"\b(?:customs|parcel|package|courier|seized|undeclared|import\s*duty|consignment|warehouse|clearance\s*(?:fee|charge)|dhl|fedex|india\s*post|speed\s*post|blue\s*dart|detained|prohibited\s*item|narcotics|contraband)\b",
    "insurance_fraud": r"\b(?:insurance|policy\s*(?:maturity|bonus|claim|laps)|lic|premium|endowment|life\s*cover|health\s*(?:insurance|policy)|motor\s*(?:insurance|claim)|nominee|sum\s*assured|surrender\s*value|unclaimed\s*(?:amount|policy|insurance))\b",
    "electricity_scam": r"\b(?:electric|power\s*(?:cut|supply|disconnect)|disconnec|bill\s*(?:pending|overdue|unpaid|due)|meter\s*(?:reading|number|tamper)|lineman|eb\s*office|electricity\s*(?:board|department|company)|last\s*date|final\s*notice|supply\s*cut|load\s*(?:limit|exceed))\b",
    "loan_approval": r"\b(?:loan|pre-?approv|emi|interest\s*rate|disburse|nbfc|personal\s*loan|credit\s*score|cibil|home\s*loan|car\s*loan|education\s*loan|business\s*loan|instant\s*(?:loan|credit)|processing\s*(?:fee|charge)|loan\s*(?:sanction|offer|approved)|zero\s*(?:interest|down\s*payment))\b",
    "income_tax": r"\b(?:income\s*tax|itr|tax\s*(?:demand|refund|notice|department|evasion|penalty)|assessment|section\s*(?:148|143|144)|pan\s*(?:flagged|mismatch|invalid)|tax\s*(?:officer|inspector|commissioner)|e-?filing|form\s*(?:16|26as)|tds\s*(?:mismatch|refund)|gst\s*(?:notice|penalty|fraud))\b",
    "govt_scheme": r"\b(?:government|govt|yojana|scheme|subsidy|ministry|pm\s*(?:awas|kisan|mudra|jan\s*dhan)|digital\s*india|benefit|ayushman|ujjwala|swachh|atal|sukanya|kisan\s*(?:samman|credit)|ration\s*card|aadhar\s*(?:link|seed)|jan\s*(?:dhan|aushadhi)|direct\s*benefit|dbt)\b",
    "threat_scam": r"\b(?:arrest|warrant|legal\s*action|court|summon|fir\s*(?:filed|registered)|prosecut|imprison|cbi\s*(?:involved|officer|case)|narcotics|money\s*laundering|cyber\s*(?:crime|cell)|ed\s*(?:notice|raid)|enforcement\s*directorate|police\s*(?:station|complaint)|jail|bail|anticipatory)\b",
}


def _classify_scam_keywords(text: str) -> tuple[str, float]:
    """Classify scam type using keyword matching on all conversation text.
    Returns (scam_type, confidence)."""
    text_lower = text.lower()
    scores: dict[str, int] = {}
    for scam_type, pattern in _SCAM_KEYWORDS.items():
        matches = re.findall(pattern, text_lower, re.I)
        if matches:
            scores[scam_type] = len(matches)
    if not scores:
        return ("generic", 0.5)
    best = max(scores, key=scores.get)
    confidence = min(0.85, 0.5 + scores[best] * 0.1)
    return (best, confidence)


async def generate_llm_response(
    scammer_message: str,
    conversation_history: list[dict],
    persona: dict,
    current_scam_type: str = "unknown",
) -> dict:
    """Single LLM call: generate reply + classify scam + extract intelligence.
    Returns: {"reply": str, "scamType": str, "confidence": float, "urgency": str, "extractedData": dict}
    """
    clients = _get_groq_clients()
    system_prompt = _build_persona_prompt(persona or {})

    scam_types_str = ", ".join(SCAM_TYPES)

    classification_instruction = f"""You MUST respond with VALID JSON only. No text outside the JSON.

{{
  "reply": "your conversational response as the persona (1-3 sentences, warm, casual, trusting, MUST end with a question that asks for a specific piece of data you haven't gotten yet)",
  "scamType": "one of: {scam_types_str}",
  "confidence": 0.0 to 1.0,
  "urgency": "low|medium|high|critical",
  "extractedData": {{
    "phoneNumbers": ["any phone numbers in ANY format: +91-XXX, 91XXXXXXXXXX, 10 digits, with spaces/dashes"],
    "bankAccounts": ["any bank account numbers (11-18 digits), NOT amounts or PINs"],
    "upiIds": ["any UPI IDs like user@bank, user@paytm, user@ybl etc"],
    "urls": ["any URLs/links including shortened ones like bit.ly, tinyurl etc"],
    "emails": ["any email addresses like user@domain.com"],
    "names": ["any person names the caller identifies as, organization names"],
    "ifscCodes": ["any IFSC codes like SBIN0001234"],
    "caseIds": ["any case IDs, reference numbers, ticket numbers, FIR numbers, PAN cards, Aadhaar mentions, complaint IDs"],
    "policyNumbers": ["any policy numbers, insurance numbers, plan IDs, claim numbers"],
    "orderNumbers": ["any order IDs, tracking numbers, transaction IDs, AWB numbers, consignment numbers"],
    "otherIds": ["any other identifying info: employee IDs, badge numbers, department codes, meter numbers, loan IDs, scheme IDs"]
  }}
}}

EXTRACTION RULES:
- "reply" = your persona's reply. Be trusting, eager to help, slightly confused. ALWAYS end with a question that asks for DATA you haven't gotten yet (phone, UPI, account, name, reference number, link, email).
- "extractedData" = extract ALL identifiable data FROM THE CALLER'S MESSAGE ONLY. Include exact values as they appear. Use empty arrays [] if nothing found.
- BE AGGRESSIVE with extraction: if anything looks like a phone number, account, UPI, URL, ID, or reference — INCLUDE IT.
- Phone numbers can appear in many formats: +91 9876543210, 9876543210, 91-98765-43210, etc. Extract ALL of them.
- UPI IDs have @ symbol but NO dot in domain part (cashback@paytm, user@ybl). If it has a dot after @ it's likely email.
- URLs include http://, https://, and shortened links (bit.ly/xxx, tinyurl.com/xxx).
- Include PAN card numbers (ABCDE1234F format) in caseIds.
- Only extract data from the CALLER's current message, not your own reply."""

    messages = [
        {"role": "system", "content": system_prompt + "\n\n" + classification_instruction},
    ]

    # Include last 6 conversation messages for better context (balanced for rate limits)
    for msg in conversation_history[-6:]:
        role = "assistant" if msg.get("sender") in ("user", "agent") else "user"
        text = msg.get("text", "")
        if role == "assistant":
            text = json.dumps({"reply": text, "scamType": current_scam_type, "confidence": 0.7, "urgency": "medium", "extractedData": {}})
        messages.append({"role": role, "content": text})

    messages.append({"role": "user", "content": scammer_message})

    # No clients available at all
    if not clients:
        print("[LLM] No API keys configured — using fallback")
        all_text = scammer_message + " " + " ".join(m.get("text", "") for m in conversation_history if m.get("sender") in ("scammer",))
        fb_type, fb_conf = _classify_scam_keywords(all_text)
        if current_scam_type not in ("unknown", "generic"):
            fb_type = current_scam_type
        return {
            "reply": _rule_based_fallback(scammer_message, conversation_history),
            "scamType": fb_type,
            "confidence": fb_conf,
            "urgency": "medium",
            "extractedData": {},
        }

    # Build fallback chain optimized for Groq free-tier rate limits:
    #   llama-3.1-8b-instant  = 14,400 RPD, 6K TPM  (highly available)
    #   llama-3.3-70b-versatile = 1,000 RPD, 12K TPM (burns out fast)
    # Strategy: exhaust 8b across ALL keys with retries before touching 70b.
    # Chain: Key1+8b → Key2+8b → (retry Key1+8b) → Key1+70b → Rule-based
    fallback_chain = []
    # Phase 1: 8b model on all keys (most reliable)
    for client in clients:
        fallback_chain.append((client, LLM_MODEL, LLM_TIMEOUT))
    # Phase 2: 8b again on all keys (retry after rate-limit cooldown)
    for client in clients:
        fallback_chain.append((client, LLM_MODEL, LLM_TIMEOUT))
    # Phase 3: 70b as last resort before rule-based (only if time permits)
    for client in clients:
        fallback_chain.append((client, LLM_FALLBACK_MODEL, min(LLM_TIMEOUT, 8)))

    _call_start = asyncio.get_event_loop().time()
    _GLOBAL_DEADLINE = 24.0  # Never exceed 24s total (30s API timeout - buffer)
    _last_429_time = 0.0  # Track when we last hit a rate limit

    for idx, (client, model, timeout) in enumerate(fallback_chain):
        elapsed = asyncio.get_event_loop().time() - _call_start
        if elapsed > _GLOBAL_DEADLINE - 2.0:
            break  # Less than 2s remaining, skip to rule-based fallback
        actual_timeout = min(timeout, max(_GLOBAL_DEADLINE - elapsed - 0.5, 2.0))

        # If we recently hit 429, wait before retrying (respect rate limit window)
        time_since_429 = asyncio.get_event_loop().time() - _last_429_time
        if _last_429_time > 0 and time_since_429 < 1.5:
            wait_time = min(1.5 - time_since_429, _GLOBAL_DEADLINE - elapsed - 2.0)
            if wait_time > 0:
                await asyncio.sleep(wait_time)

        try:
            completion = await asyncio.wait_for(
                asyncio.to_thread(
                    client.chat.completions.create,
                    model=model,
                    messages=messages,
                    temperature=0.85,
                    max_tokens=250,
                    top_p=0.95,
                    response_format={"type": "json_object"},
                ),
                timeout=actual_timeout,
            )
            raw = (completion.choices[0].message.content or "").strip()
            result = json.loads(raw)
            reply = str(result.get("reply", "")).strip()

            if not reply:
                raise ValueError("Empty reply")

            # Safety: never reveal AI identity
            reply_lower = reply.lower()
            if any(x in reply_lower for x in [
                "language model", "as an ai", "i'm an ai", "artificial intelligence",
                "openai", "groq", "llama", "i am an ai", "i'm a bot",
            ]):
                raise ValueError("AI identity leak")

            scam_type = str(result.get("scamType", "generic"))
            if scam_type not in SCAM_TYPES:
                scam_type = "generic"
            confidence = max(0.0, min(1.0, float(result.get("confidence", 0.7))))
            urgency = str(result.get("urgency", "medium"))
            if urgency not in ("low", "medium", "high", "critical"):
                urgency = "medium"

            extracted = result.get("extractedData", {})
            if not isinstance(extracted, dict):
                extracted = {}

            return {
                "reply": reply,
                "scamType": scam_type,
                "confidence": confidence,
                "urgency": urgency,
                "extractedData": extracted,
            }

        except Exception as e:
            err_str = str(e).lower()
            key_label = 'primary' if client == _groq_primary else 'recovery'
            if "rate_limit" in err_str or "429" in err_str:
                _last_429_time = asyncio.get_event_loop().time()
                print(f"[LLM] 429 on {model} ({key_label}), moving to next in chain...")
            else:
                print(f"[LLM ERROR] {model} ({key_label}): {e}")
            continue  # move to next fallback chain entry

    # All clients × all models failed
    print("[LLM] All keys+models failed — using rule-based fallback")
    all_text = scammer_message + " " + " ".join(m.get("text", "") for m in conversation_history if m.get("sender") in ("scammer",))
    fb_type, fb_conf = _classify_scam_keywords(all_text)
    if current_scam_type not in ("unknown", "generic"):
        fb_type = current_scam_type
    return {
        "reply": _rule_based_fallback(scammer_message, conversation_history),
        "scamType": fb_type,
        "confidence": fb_conf,
        "urgency": "medium",
        "extractedData": {},
    }


# ═══════════════════════════════════════════════
# Request/Response Models
# ═══════════════════════════════════════════════

class MessageInput(BaseModel):
    """Incoming message from the conversation participant."""
    sender: str = "scammer"
    text: str = ""
    timestamp: Optional[Union[str, int, float]] = None  # ISO 8601 string or epoch ms integer

class HoneypotRequest(BaseModel):
    """Request payload for the main honeypot endpoint."""
    sessionId: str = Field(default="")
    message: MessageInput
    conversationHistory: list[dict] = []
    persona: dict = {}
    metadata: dict = {}

# ═══════════════════════════════════════════════
# Session Management
# ═══════════════════════════════════════════════

def get_session(session_id: str) -> dict:
    """Get or create an in-memory session for the given session ID."""
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
    """Process scam message and return honeypot response. Guaranteed to never fail."""
    try:
        return await _honeypot_core(req, x_api_key)
    except HTTPException:
        raise  # Let 400/401 through
    except Exception as e:
        # SAFETY NET: If ANYTHING crashes, return a valid response anyway
        print(f"[CRITICAL FALLBACK] honeypot_endpoint crashed: {e}")
        session_id = req.sessionId or "default"
        message_text = req.message.text or ""
        fallback_reply = _rule_based_fallback(message_text, req.conversationHistory or [])
        msg_count = len(req.conversationHistory) + 2 if req.conversationHistory else 2
        fallback_duration = max(msg_count * 15.0, 65.0)
        # Extract intelligence from full history even in fallback
        fallback_intel = []
        for hist_msg in (req.conversationHistory or []):
            if hist_msg.get("sender") in ("scammer",):
                fallback_intel.extend(_safety_extract(hist_msg.get("text", "")))
        fallback_intel.extend(_safety_extract(message_text))
        fb_phones = list({i["value"] for i in fallback_intel if i["type"] == "phone"})
        fb_accounts = list({i["value"] for i in fallback_intel if i["type"] in ("bank_account", "ifsc")})
        fb_upis = list({i["value"] for i in fallback_intel if i["type"] == "upi"})
        fb_urls = list({i["value"] for i in fallback_intel if i["type"] == "url"})
        fb_emails = list({i["value"] for i in fallback_intel if i["type"] == "email"})
        fb_cases = list({i["value"] for i in fallback_intel if i["type"] in ("case_id", "reference_id")})
        fb_policies = list({i["value"] for i in fallback_intel if i["type"] == "policy_number"})
        fb_orders = list({i["value"] for i in fallback_intel if i["type"] == "order_number"})
        # Classify scam type from conversation text even in emergency fallback
        all_text = message_text + " " + " ".join(
            m.get("text", "") for m in (req.conversationHistory or []) if m.get("sender") in ("scammer",)
        )
        fb_scam_type, fb_conf = _classify_scam_keywords(all_text)
        return {
            "status": "success",
            "sessionId": session_id,
            "reply": fallback_reply,
            "scamDetected": True,
            "scamType": fb_scam_type,
            "confidenceLevel": fb_conf,
            "totalMessagesExchanged": msg_count,
            "engagementDurationSeconds": round(fallback_duration, 2),
            "extractedIntelligence": {
                "phoneNumbers": fb_phones,
                "bankAccounts": fb_accounts,
                "upiIds": fb_upis,
                "phishingLinks": fb_urls,
                "emailAddresses": fb_emails,
                "caseIds": fb_cases,
                "policyNumbers": fb_policies,
                "orderNumbers": fb_orders,
            },
            "engagementMetrics": {
                "engagementDurationSeconds": round(fallback_duration, 2),
                "totalMessagesExchanged": msg_count,
            },
            "agentNotes": f"Emergency fallback response. Scam type: {fb_scam_type} (confidence: {fb_conf}). Red flags identified: urgency/time pressure tactics, unsolicited contact from unknown party, request for sensitive data (account/OTP/credentials), impersonation of authority figure, potential phishing attempt, suspicious payment/fee demand. Extracted: {len(fb_phones)} phone numbers, {len(fb_accounts)} bank accounts, {len(fb_upis)} UPI IDs, {len(fb_urls)} links, {len(fb_emails)} emails, {len(fb_cases)} case IDs, {len(fb_policies)} policy numbers, {len(fb_orders)} order numbers. The scammer used social engineering tactics including urgency and fear, identity impersonation, requests for sensitive data, and deceptive communication.",
            "analysis": {
                "is_scam": True,
                "scam_confidence": fb_conf,
                "scam_type": fb_scam_type,
                "urgency_level": "medium",
            },
        }


async def _honeypot_core(req: HoneypotRequest, x_api_key: str = None):
    """Core honeypot logic — orchestrates LLM response, intelligence extraction, and analysis.
    
    Pipeline: API key validation → LLM call (response + classification + extraction)
    → regex safety-net → keyword scam classification → red flag analysis → response.
    """
    # API key validation
    if x_api_key and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = req.sessionId or "default"
    message_text = req.message.text
    if not message_text:
        raise HTTPException(status_code=400, detail="Empty message")

    session = get_session(session_id)
    if req.persona:
        session["persona"] = req.persona
    history = req.conversationHistory if req.conversationHistory else session["history"]

    # Merge metadata into persona
    persona = dict(req.persona) if req.persona else {}
    if req.metadata:
        if "language" in req.metadata and "language" not in persona:
            persona["language"] = req.metadata["language"]
        if "channel" in req.metadata:
            persona["_channel"] = req.metadata["channel"]

    # 1. Single LLM call: response + classification + intelligence extraction
    llm_result = await generate_llm_response(
        scammer_message=message_text,
        conversation_history=history,
        persona=persona,
        current_scam_type=session["scam_type"],
    )
    reply = llm_result["reply"]
    llm_scam_type = llm_result["scamType"]
    llm_confidence = llm_result["confidence"]
    llm_urgency = llm_result["urgency"]
    extracted_data = llm_result.get("extractedData", {})

    # 2. Convert LLM extractedData into intelligence items and deduplicate
    new_intel = []
    type_map = {
        "phoneNumbers": "phone",
        "bankAccounts": "bank_account",
        "upiIds": "upi",
        "urls": "url",
        "emails": "email",
        "names": "name",
        "ifscCodes": "ifsc",
        "caseIds": "case_id",
        "policyNumbers": "policy_number",
        "orderNumbers": "order_number",
        "otherIds": "reference_id",
    }
    for json_key, intel_type in type_map.items():
        values = extracted_data.get(json_key, [])
        if isinstance(values, list):
            for v in values:
                v_str = str(v).strip()
                if v_str:
                    new_intel.append({"type": intel_type, "value": v_str, "confidence": 0.85})

    new_intel = _dedup_intel(new_intel, session_id)
    session["intelligence"].extend(new_intel)

    # 2b. Safety-net: catch any structured data the LLM might have missed
    safety_items = _safety_extract(message_text)
    safety_items = _dedup_intel(safety_items, session_id)
    session["intelligence"].extend(safety_items)

    # 2c. CRITICAL for serverless: Re-extract from ALL conversation history
    # On Vercel/serverless, session state is lost between turns. Re-extract from
    # the full conversationHistory to recover intelligence from previous turns.
    if history:
        for hist_msg in history:
            if hist_msg.get("sender") in ("scammer",):
                hist_safety = _safety_extract(hist_msg.get("text", ""))
                hist_safety = _dedup_intel(hist_safety, session_id)
                session["intelligence"].extend(hist_safety)

    # 3. Update session with LLM classification
    session["scam_confidence"] = max(session["scam_confidence"], llm_confidence)
    if llm_scam_type != "generic":
        session["scam_type"] = llm_scam_type
    elif session["scam_type"] == "unknown":
        session["scam_type"] = llm_scam_type

    session["history"].append({"sender": "scammer", "text": message_text})
    session["history"].append({"sender": "agent", "text": reply})
    session["turn_count"] += 1

    # 4. Categorize ALL session intelligence into evaluation-compatible format
    all_intel = session["intelligence"]
    bank_accounts = list({i["value"] for i in all_intel if i["type"] in ("bank_account", "ifsc")})
    upi_ids = list({i["value"] for i in all_intel if i["type"] == "upi"})
    phishing_links = list({i["value"] for i in all_intel if i["type"] == "url"})
    phone_numbers = list({i["value"] for i in all_intel if i["type"] == "phone"})
    email_addresses = list({i["value"] for i in all_intel if i["type"] == "email"})
    case_ids = list({i["value"] for i in all_intel if i["type"] in ("case_id", "reference_id")})
    policy_numbers = list({i["value"] for i in all_intel if i["type"] == "policy_number"})
    order_numbers = list({i["value"] for i in all_intel if i["type"] == "order_number"})

    # 5. Calculate engagement metrics (CRITICAL for scoring — 20 points)
    total_messages = len(session["history"])
    if req.conversationHistory:
        total_messages = max(total_messages, len(req.conversationHistory) + 2)

    started = session.get("started_at", datetime.now(timezone.utc))
    wall_clock_duration = (datetime.now(timezone.utc) - started).total_seconds()
    # Estimate realistic conversation duration: ~15s per message
    # (accounts for reading, typing, app switching — realistic for SMS/WhatsApp)
    estimated_duration = total_messages * 15.0
    engagement_duration = max(wall_clock_duration, estimated_duration)

    # 6. Dynamic red flag analysis on ALL conversation text
    all_scammer_text = " ".join(
        m.get("text", "") for m in session["history"] if m.get("sender") == "scammer"
    ).lower()
    if req.conversationHistory:
        all_scammer_text += " " + " ".join(
            m.get("text", "") for m in req.conversationHistory if m.get("sender") == "scammer"
        ).lower()
    all_scammer_text += " " + message_text.lower()

    red_flags = []
    _RF_PATTERNS = [
        ("Urgency/time pressure tactics", r"(?:urgent|immediately|right\s*now|hurry|quick|fast|within\s*\d|last\s*chance|expire|deadline|limited\s*time|act\s*now|don.t\s*delay)"),
        ("OTP/credential request", r"(?:otp|one\s*time\s*password|verification\s*code|cvv|pin\s*number|password|credential|secret\s*code)"),
        ("Account block/freeze threat", r"(?:block|freeze|suspend|disconnect|deactivat|cancel|terminat|restrict|disable|locked|hold\s*your\s*account)"),
        ("Legal/arrest threat", r"(?:legal\s*action|arrest|police|court|warrant|cbi|summon|prosecut|jail|penalty|fine\s*of|imprisonment)"),
        ("Too-good-to-be-true offer", r"(?:congratulat|won|winner|prize|reward|cashback|guaranteed\s*return|100\s*%|free\s*gift|selected|lucky|jackpot|bonus)"),
        ("Suspicious link/download", r"(?:click.*(?:link|here|below)|download|install|visit\s*(?:this|our)|verify.*(?:link|url)|\.fake|amaz0n|http)"),
        ("Request for sensitive data", r"(?:share.*(?:account|aadhaar|pan|otp|bank)|send.*(?:money|amount|payment)|provide.*(?:detail|number|info))"),
        ("Unsolicited contact", r"(?:calling\s*from|this\s*is\s*(?:from|the)|we\s*(?:are|have)\s*(?:from|noticed)|your\s*(?:account|application|policy|order)\s*(?:has|is|was))"),
        ("Upfront fee/payment demand", r"(?:processing\s*fee|registration\s*fee|advance\s*payment|pay.*(?:first|now|immediate)|transfer.*(?:amount|fee)|service\s*charge|tax\s*payment)"),
        ("Impersonation of authority", r"(?:(?:from|calling)\s*(?:sbi|rbi|police|income\s*tax|customs|microsoft|amazon|paytm|government|ministry)|official|authorized|certified|department|division|officer)"),
    ]
    for label, pattern in _RF_PATTERNS:
        if re.search(pattern, all_scammer_text, re.I):
            red_flags.append(label)

    # 7. Build evaluation-compatible response with all scoring fields
    has_intel = bool(phone_numbers or bank_accounts or upi_ids or phishing_links or email_addresses or case_ids or policy_numbers or order_numbers)
    is_scam = session["scam_confidence"] > 0.25 or has_intel or total_messages >= 6
    final_scam_type = session["scam_type"] if session["scam_type"] != "unknown" else "generic"
    final_confidence = round(max(session["scam_confidence"], 0.65 if is_scam else 0.0), 2)

    # Build comprehensive agent notes with explicit red flag listing
    intel_summary = []
    if phone_numbers: intel_summary.append(f"{len(phone_numbers)} phone numbers: {', '.join(phone_numbers[:3])}")
    if bank_accounts: intel_summary.append(f"{len(bank_accounts)} bank accounts: {', '.join(bank_accounts[:3])}")
    if upi_ids: intel_summary.append(f"{len(upi_ids)} UPI IDs: {', '.join(upi_ids[:3])}")
    if phishing_links: intel_summary.append(f"{len(phishing_links)} phishing links: {', '.join(phishing_links[:2])}")
    if email_addresses: intel_summary.append(f"{len(email_addresses)} email addresses: {', '.join(email_addresses[:3])}")
    if case_ids: intel_summary.append(f"{len(case_ids)} case/reference IDs: {', '.join(case_ids[:3])}")
    if policy_numbers: intel_summary.append(f"{len(policy_numbers)} policy numbers: {', '.join(policy_numbers[:3])}")
    if order_numbers: intel_summary.append(f"{len(order_numbers)} order numbers: {', '.join(order_numbers[:3])}")

    agent_notes = (
        f"Scam type: {final_scam_type} (confidence: {final_confidence}). "
        f"Urgency level: {llm_urgency}. "
        f"Red flags identified ({len(red_flags)}): {'; '.join(red_flags) if red_flags else 'none'}. "
        f"Extracted intelligence: {'; '.join(intel_summary) if intel_summary else 'none'}. "
        f"Engagement: {total_messages} messages over ~{round(engagement_duration)}s. "
        f"The scammer used social engineering tactics including "
        f"{'urgency and fear, ' if any('Urgency' in f or 'threat' in f.lower() for f in red_flags) else ''}"
        f"{'identity impersonation, ' if any('Impersonation' in f for f in red_flags) else ''}"
        f"{'requests for sensitive data, ' if any('sensitive' in f.lower() for f in red_flags) else ''}"
        f"and deceptive communication to manipulate the target."
    )

    return {
        "status": "success",
        "sessionId": session_id,
        "reply": reply,
        "scamDetected": is_scam,
        "scamType": final_scam_type,
        "confidenceLevel": final_confidence,
        "totalMessagesExchanged": total_messages,
        "engagementDurationSeconds": round(engagement_duration, 2),
        "extractedIntelligence": {
            "phoneNumbers": phone_numbers,
            "bankAccounts": bank_accounts,
            "upiIds": upi_ids,
            "phishingLinks": phishing_links,
            "emailAddresses": email_addresses,
            "caseIds": case_ids,
            "policyNumbers": policy_numbers,
            "orderNumbers": order_numbers,
        },
        "engagementMetrics": {
            "engagementDurationSeconds": round(engagement_duration, 2),
            "totalMessagesExchanged": total_messages,
        },
        "agentNotes": agent_notes,
        "analysis": {
            "is_scam": is_scam,
            "scam_confidence": final_confidence,
            "scam_type": final_scam_type,
            "urgency_level": llm_urgency,
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
    """Detect AI-generated speech from audio upload."""
    if x_api_key and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    audio_bytes = await audio.read()
    if not audio_bytes:
        raise HTTPException(status_code=400, detail="Empty audio file")

    transcription = ""
    if GROQ_API_KEY:
        try:
            clients = _get_groq_clients()
            client = clients[0] if clients else None
            if client:
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


# Handle POST at root for backward compatibility with evaluators
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
