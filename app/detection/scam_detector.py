"""
Scam Detection Engine — Python port + LLM enhancement.

Hybrid detection: Rule-based patterns (70%) + Keyword matching (20%) + Behavioral (10%).
Optimized for Indian market scams: UPI, KYC, OTP, bank, lottery, job.
"""

import re
from dataclasses import dataclass, field


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
    has_financial_context: bool = False
    has_direct_request: bool = False


# === SCAM PATTERNS (70+ patterns) ===

SCAM_PATTERNS = [
    # --- Urgency ---
    ScamIndicator(re.compile(r"urgent|immediately|within \d+ (hours?|minutes?)|right now", re.I), 0.18, "urgency", True),
    ScamIndicator(re.compile(r"act now|don'?t delay|time (is|was) running|last chance|final warning", re.I), 0.15, "urgency", True),
    ScamIndicator(re.compile(r"expir(e|ing|ed)|deadline|limited time|hurry|asap", re.I), 0.12, "urgency", True),

    # --- Authority Impersonation ---
    ScamIndicator(re.compile(r"(bank|rbi|sebi|income tax|police|court|government)\s*(manager|official|officer|department)", re.I), 0.20, "authority"),
    ScamIndicator(re.compile(r"(sbi|hdfc|icici|axis|kotak|pnb|bob|canara|union)\s*(bank)?", re.I), 0.12, "authority"),
    ScamIndicator(re.compile(r"your (account|number|card|kyc|pan|aadhaar) (is|has been|will be)", re.I), 0.15, "authority", True),
    ScamIndicator(re.compile(r"dear (customer|user|sir|madam|valued)", re.I), 0.10, "authority"),

    # --- Financial Requests ---
    ScamIndicator(re.compile(r"send (money|amount|payment|fund|rs\.?|₹)", re.I), 0.20, "financial", True),
    ScamIndicator(re.compile(r"transfer (to|into|amount)|wire|remittance", re.I), 0.18, "financial"),
    ScamIndicator(re.compile(r"(processing|activation|registration|delivery|customs) fee", re.I), 0.18, "financial", True),
    ScamIndicator(re.compile(r"pay (rs\.?|₹|inr)?\s*\d+", re.I), 0.20, "financial", True),
    ScamIndicator(re.compile(r"upi.{0,5}(id|transfer|pay|send)|@(upi|ybl|paytm|okaxis|oksbi|apl|ibl)", re.I), 0.18, "financial"),

    # --- Verification / KYC ---
    ScamIndicator(re.compile(r"verify your (account|identity|details|kyc|pan|aadhaar)", re.I), 0.16, "verification", True),
    ScamIndicator(re.compile(r"kyc.{0,10}(update|expir|pending|incomplete|mandatory)", re.I), 0.18, "verification", True),
    ScamIndicator(re.compile(r"(update|confirm|share|send) your (details|otp|pin|password|cvv)", re.I), 0.20, "verification", True),

    # --- OTP / Credential Theft ---
    ScamIndicator(re.compile(r"(share|send|tell|provide|enter).{0,15}(otp|pin|cvv|password|mpin)", re.I), 0.22, "otp_fraud", True),
    ScamIndicator(re.compile(r"otp.{0,10}(sent|received|generated|code)", re.I), 0.15, "otp_fraud"),

    # --- Prize / Lottery ---
    ScamIndicator(re.compile(r"(won|winner|selected|chosen).{0,20}(prize|lottery|reward|cashback|gift)", re.I), 0.18, "lottery", True),
    ScamIndicator(re.compile(r"congratulat|lucky (winner|number|draw)|jackpot", re.I), 0.16, "lottery", True),
    ScamIndicator(re.compile(r"claim (your|now|prize|reward)|redeem", re.I), 0.14, "lottery", True),
    ScamIndicator(re.compile(r"(rs\.?|₹|inr)\s*\d+\s*(lakh|crore|lakhs|crores)", re.I), 0.12, "lottery"),

    # --- Job / Income Scam ---
    ScamIndicator(re.compile(r"work from home|earn.{0,15}(daily|weekly|monthly)|part.?time.{0,10}(job|income|earning)", re.I), 0.14, "job_scam", True),
    ScamIndicator(re.compile(r"(easy|quick|guaranteed|assured) (money|income|returns|profit)", re.I), 0.16, "job_scam", True),
    ScamIndicator(re.compile(r"registration fee|joining fee|training fee", re.I), 0.16, "job_scam", True),

    # --- Investment Scam ---
    ScamIndicator(re.compile(r"(invest|trading|forex|crypto|bitcoin|mutual fund).{0,15}(guaranteed|assured|fixed|daily) returns", re.I), 0.18, "investment", True),
    ScamIndicator(re.compile(r"\d+%\s*(daily|weekly|monthly|annual)\s*(return|profit|income|interest)", re.I), 0.18, "investment", True),

    # --- Threat / Intimidation ---
    ScamIndicator(re.compile(r"(account|number|card|sim).{0,10}(block|suspend|deactivat|freez|cancel)", re.I), 0.16, "threat", True),
    ScamIndicator(re.compile(r"legal (action|notice|proceedings)|arrest warrant|fir|complaint", re.I), 0.18, "threat", True),
    ScamIndicator(re.compile(r"if you (don'?t|do not|fail to)", re.I), 0.12, "threat", True),

    # --- Phishing ---
    ScamIndicator(re.compile(r"click (here|this|below|the link)|tap (here|this|below)", re.I), 0.14, "phishing"),
    ScamIndicator(re.compile(r"(verify|update|confirm|login).{0,10}(link|url|website|page|portal)", re.I), 0.15, "phishing"),
    ScamIndicator(re.compile(r"https?://[^\s]*\.(tk|ml|ga|cf|gq|xyz|top|buzz|club|info|win)", re.I), 0.18, "phishing"),
    ScamIndicator(re.compile(r"bit\.ly|tinyurl|short\.io|rebrand\.ly|is\.gd", re.I), 0.12, "phishing"),
]

HIGH_RISK_KEYWORDS = [
    "bitcoin", "ethereum", "crypto", "wallet", "private key",
    "gift card", "steam card", "amazon gift", "google play card",
    "western union", "moneygram", "wire transfer", "bank transfer",
    "account suspended", "verify identity", "confirm details",
    "processing fee", "activation fee", "delivery fee",
    "customs duty", "import tax", "clearance fee",
    "inheritance", "lottery winner", "beneficiary", "next of kin",
    "blocked account", "frozen account", "suspicious activity",
]

MEDIUM_RISK_KEYWORDS = [
    "investment", "returns", "profit", "passive income",
    "opportunity", "business proposal", "partnership",
    "job offer", "work from home", "freelance", "weekly income",
    "prize", "winner", "selected", "lucky",
    "refund", "cashback", "bonus", "reward",
    "insurance claim", "policy", "maturity",
]


class ScamDetector:
    """Detect scam intent in incoming messages."""

    def __init__(self, threshold: float = 0.35):
        self.threshold = threshold

    def analyze(
        self,
        message: str,
        conversation_history: list[str] | None = None,
    ) -> DetectionResult:
        """Analyze a message for scam indicators.

        Returns DetectionResult with confidence, type, and indicators.
        """
        result = DetectionResult()

        # --- 1. Rule-based pattern matching (50% weight) ---
        pattern_score = 0.0
        matched_categories: dict[str, float] = {}
        has_urgency = False

        for indicator in SCAM_PATTERNS:
            if indicator.pattern.search(message):
                pattern_score += indicator.weight
                if indicator.urgency_boost:
                    has_urgency = True
                cat = indicator.category
                matched_categories[cat] = matched_categories.get(cat, 0) + indicator.weight
                result.indicators.append({
                    "category": cat,
                    "weight": indicator.weight,
                    "matched": indicator.pattern.pattern[:50],
                })

        # --- 2. Keyword matching (25% weight) ---
        keyword_score = 0.0
        lower_msg = message.lower()

        for kw in HIGH_RISK_KEYWORDS:
            if kw in lower_msg:
                keyword_score += 0.12

        for kw in MEDIUM_RISK_KEYWORDS:
            if kw in lower_msg:
                keyword_score += 0.06

        keyword_score = min(keyword_score, 1.0)

        # --- 3. Behavioral signals (15% weight) ---
        behavioral_score = 0.0
        if len(message) > 200:
            behavioral_score += 0.1  # Long messages often scam scripts
        if message.isupper() or message.count("!") > 2:
            behavioral_score += 0.1  # Shouting / exclamation
        if re.search(r"₹|rs\.?\s*\d|inr\s*\d|\d+\s*(lakh|crore)", message, re.I):
            behavioral_score += 0.1
            result.has_financial_context = True
        if re.search(r"(send|share|tell|provide|give|transfer)", message, re.I):
            result.has_direct_request = True
            behavioral_score += 0.05

        # --- 4. History analysis (10% weight) ---
        history_score = 0.0
        if conversation_history:
            for prev_msg in conversation_history[-5:]:
                for indicator in SCAM_PATTERNS:
                    if indicator.pattern.search(prev_msg):
                        history_score += indicator.weight * 0.4
            history_score = min(history_score, 1.0)

        # --- Combine scores ---
        raw_confidence = (
            pattern_score * 0.50
            + keyword_score * 0.25
            + behavioral_score * 0.15
            + history_score * 0.10
        )

        # Urgency boost
        if has_urgency and raw_confidence > 0.15:
            raw_confidence *= 1.3

        result.confidence = min(round(raw_confidence, 4), 1.0)
        result.is_scam = result.confidence >= self.threshold

        # --- Determine scam type ---
        if matched_categories:
            dominant = max(matched_categories, key=matched_categories.get)
            TYPE_MAP = {
                "urgency": "generic",
                "authority": "bank_fraud",
                "financial": "upi_fraud",
                "verification": "kyc_scam",
                "otp_fraud": "otp_fraud",
                "lottery": "lottery_scam",
                "job_scam": "job_scam",
                "investment": "investment_scam",
                "threat": "threat_scam",
                "phishing": "phishing",
            }
            result.scam_type = TYPE_MAP.get(dominant, "generic")

        # --- Urgency level ---
        urgency_count = sum(1 for i in result.indicators if i["category"] == "urgency")
        if urgency_count >= 3:
            result.urgency_level = "critical"
        elif urgency_count >= 2:
            result.urgency_level = "high"
        elif urgency_count >= 1:
            result.urgency_level = "medium"

        return result
