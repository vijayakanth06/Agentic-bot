"""
Agentic Honeypot — Vercel Serverless Function (Self-Contained).

Single-file FastAPI app with all logic inline for reliable Vercel deployment.
Handles: POST /api/honeypot (Problem 2) + POST /api/voice/detect (Problem 1)
"""

import os
import re
import asyncio
from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ═══════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
API_KEY = os.environ.get("API_KEY", "fae26946fc2015d9bd6f1ddbb447e2f7")
LLM_MODEL = os.environ.get("LLM_MODEL", "llama-3.3-70b-versatile")
PERSONA_NAME = os.environ.get("PERSONA_NAME", "Priya Sharma")
PERSONA_AGE = os.environ.get("PERSONA_AGE", "28")
PERSONA_OCCUPATION = os.environ.get("PERSONA_OCCUPATION", "Software Engineer at TCS")
PERSONA_LOCATION = os.environ.get("PERSONA_LOCATION", "Mumbai, Andheri West")

# ═══════════════════════════════════════════════
# FastAPI App
# ═══════════════════════════════════════════════

app = FastAPI(title="Agentic Honeypot", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory session store
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
]

MEDIUM_RISK_KEYWORDS = [
    "please help", "kindly cooperate", "do it now",
    "immediately", "urgently", "at the earliest",
    "share your", "send your", "provide your",
    "employee id", "reference number", "case number",
    "google pay", "phonepe", "paytm", "bhim",
    "bank account", "upi id", "ifsc",
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
]

_seen_intel: dict[str, set] = {}  # session_id -> set of seen dedup keys


def extract_intelligence(message: str, session_id: str = "") -> list[dict]:
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

PERSONA_PROMPT = f"""You are {PERSONA_NAME}, a {PERSONA_AGE}-year-old {PERSONA_OCCUPATION} living in {PERSONA_LOCATION}.

PERSONALITY:
- Normal Indian woman, friendly but cautious with strangers
- Mix Hindi words into English naturally (Hinglish)
- Husband named Rahul who works in banking
- Use WhatsApp, Paytm, Google Pay regularly

CRITICAL RULES:
1. NEVER reveal you know this is a scam
2. NEVER mention police, investigation, fraud, or scammer
3. NEVER say "I am an AI" or "I am a bot"
4. Keep responses SHORT (1-3 sentences) like real SMS/WhatsApp
5. Use casual texting style with occasional emojis

BEHAVIORAL STRATEGY:
- Act naive but ask innocent questions that extract information
- If they ask for money/OTP, show willingness but ask for THEIR details first
- NEVER repeat the same response. Each reply must be UNIQUE.
- Rotate through varied stalling tactics:
  * "Hold on my mom is calling"  * "Arey wait, my internet is slow"
  * "Let me check my balance"    * "My phone is about to die"
  * "One sec, Rahul is asking"   * "Which bank did you say?"
  * "What's your office address?" * "My branch manager name is different..."
- If scammer repeats, respond with a DIFFERENT excuse each time
- NEVER provide real sensitive info (make up fake details if pressed)"""

SCAM_TYPE_PROMPTS = {
    "bank_fraud": "Ask for employee ID, branch name, helpline number to 'verify'.",
    "upi_fraud": "Show willingness but ask for their UPI ID first.",
    "kyc_scam": "Act confused, ask which bank, branch, employee name.",
    "otp_fraud": "Pretend looking for OTP but keep asking questions.",
    "lottery_scam": "Act excited, ask for official docs, company registration.",
    "job_scam": "Show interest, ask for company name, office address, HR contact.",
    "threat_scam": "Act scared, ask for case number, officer name, station details.",
    "generic": "Engage naturally. Ask innocent questions to extract identity details.",
}

EXTRACTION_INSTRUCTION = """
Try to get these details NATURALLY:
1. Their full name  2. Phone number or employee ID
3. UPI ID or bank account  4. Organization they claim to be from
5. URLs or links  6. Reference numbers or case IDs"""

_groq_client = None

def _get_groq():
    global _groq_client
    if _groq_client is None:
        from groq import Groq
        _groq_client = Groq(api_key=GROQ_API_KEY)
    return _groq_client


def _detect_repetition(history: list[dict]) -> Optional[str]:
    agent_replies = [m.get("text", "").lower().strip() for m in history if m.get("sender") == "agent"]
    if len(agent_replies) < 2:
        return None
    recent = agent_replies[-3:] if len(agent_replies) >= 3 else agent_replies[-2:]
    for i in range(len(recent) - 1):
        words_a, words_b = set(recent[i].split()), set(recent[i + 1].split())
        if words_a and words_b and len(words_a & words_b) / max(len(words_a | words_b), 1) > 0.6:
            return (
                "WARNING: Your recent replies are TOO SIMILAR. Use a completely different approach. "
                "Try: phone dying, husband wants to verify, visit the branch, app error, ask supervisor name. "
                "DO NOT repeat anything you said before."
            )
    return None


FALLBACK_RESPONSES = [
    "Hello? Who is this?", "Haan batao, what happened?",
    "Sorry network issue, can you repeat?", "One sec, my mom is calling...",
]
_fallback_idx = 0


async def generate_llm_response(
    scammer_message: str,
    conversation_history: list[dict],
    scam_type: str = "generic",
) -> str:
    global _fallback_idx
    if not GROQ_API_KEY:
        resp = FALLBACK_RESPONSES[_fallback_idx % len(FALLBACK_RESPONSES)]
        _fallback_idx += 1
        return resp

    try:
        client = _get_groq()
        scam_inst = SCAM_TYPE_PROMPTS.get(scam_type, SCAM_TYPE_PROMPTS["generic"])
        messages = [
            {"role": "system", "content": PERSONA_PROMPT},
            {"role": "system", "content": f"SITUATION: {scam_inst}\n{EXTRACTION_INSTRUCTION}"},
        ]

        dedup = _detect_repetition(conversation_history)
        if dedup:
            messages.append({"role": "system", "content": dedup})

        for msg in conversation_history[-10:]:
            role = "assistant" if msg.get("sender") == "agent" else "user"
            messages.append({"role": role, "content": msg.get("text", "")})
        messages.append({"role": "user", "content": scammer_message})

        completion = await asyncio.to_thread(
            client.chat.completions.create,
            model=LLM_MODEL, messages=messages,
            temperature=0.8, max_tokens=512, top_p=1,
        )
        text = completion.choices[0].message.content or ""

        # Safety filter
        for bad in ["honeypot", "scam detection", "I am an AI", "artificial intelligence", "language model"]:
            if bad.lower() in text.lower():
                text = "Haan, tell me more? What should I do exactly?"
                break
        return text.strip()

    except Exception as e:
        print(f"[LLM ERROR] {e}")
        resp = FALLBACK_RESPONSES[_fallback_idx % len(FALLBACK_RESPONSES)]
        _fallback_idx += 1
        return resp

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
        }
    return sessions[session_id]

# ═══════════════════════════════════════════════
# API Endpoints
# ═══════════════════════════════════════════════

@app.get("/")
async def root():
    return HTMLResponse("<h1>Agentic Honeypot</h1><p>POST /api/honeypot or /api/voice/detect</p>")


@app.get("/health")
async def health():
    return {"status": "ok", "groq": bool(GROQ_API_KEY)}


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

    # Use conversation history from request OR session
    history = req.conversationHistory if req.conversationHistory else session["history"]

    # 1. Detect scam (with session history for cumulative boosting)
    detection = detect_scam(message_text, session_history=history)
    if detection.is_scam:
        session["scam_confidence"] = max(session["scam_confidence"], detection.confidence)
        session["scam_type"] = detection.scam_type

    # 2. Extract intelligence
    new_intel = extract_intelligence(message_text, session_id)
    session["intelligence"].extend(new_intel)

    # 3. Generate LLM response
    reply = await generate_llm_response(
        scammer_message=message_text,
        conversation_history=history,
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


# Also handle POST at root (in case GUVI tester sends to base URL)
@app.post("/")
async def root_post(req: HoneypotRequest, x_api_key: str = Header(None)):
    return await honeypot_endpoint(req, x_api_key)


# Backward compat
@app.post("/api/conversation")
async def conversation_compat(req: HoneypotRequest, x_api_key: str = Header(None)):
    return await honeypot_endpoint(req, x_api_key)
