"""
Intelligence Extraction Engine — Extracts actionable intelligence from messages.

Targets: UPI IDs, phone numbers, bank accounts, URLs, IFSC codes,
         PAN, Aadhaar, names, organizations, crypto addresses.
"""

import re
from dataclasses import dataclass, field


@dataclass
class ExtractedItem:
    type: str
    value: str
    confidence: float
    context: str = ""


@dataclass
class ExtractionResult:
    items: list[ExtractedItem] = field(default_factory=list)
    total_score: float = 0.0

    @property
    def upi_ids(self) -> list[str]:
        return [i.value for i in self.items if i.type == "upi"]

    @property
    def phone_numbers(self) -> list[str]:
        return [i.value for i in self.items if i.type == "phone"]

    @property
    def urls(self) -> list[str]:
        return [i.value for i in self.items if i.type == "url"]

    @property
    def bank_accounts(self) -> list[str]:
        return [i.value for i in self.items if i.type == "bank_account"]


# === EXTRACTION PATTERNS ===

EXTRACTION_PATTERNS = [
    # --- UPI IDs ---
    {
        "type": "upi",
        "pattern": re.compile(
            r"[a-zA-Z0-9._-]+@(upi|ybl|paytm|okaxis|oksbi|okhdfcbank|axl|ibl|apl|"
            r"waicici|wahdfcbank|waaxis|waupi|abfspay|barodampay|cboi|csbpay|"
            r"dbs|federal|finobank|hdfcbank|hsbc|idfcbank|indus|kbl|kotak|"
            r"mahb|pnb|rbl|sbi|scb|uco|unionbank|utbi|yesbank|ikwik|"
            r"jupiteraxis|fam|slice|gpay|phonepe|amazonpay)",
            re.I,
        ),
        "confidence": 0.95,
    },
    # --- Phone Numbers ---
    {
        "type": "phone",
        "pattern": re.compile(
            r"(?:\+91[\s-]?)?(?:[6-9]\d{9})"
            r"|(?:\+91[\s-]?\d{5}[\s-]?\d{5})",
            re.I,
        ),
        "confidence": 0.85,
    },
    # --- Bank Account Numbers ---
    {
        "type": "bank_account",
        "pattern": re.compile(
            r"(?:account|a/c|ac)[\s#:.-]*(\d{9,18})"
            r"|(?:(?:savings?|current)\s*(?:account|a/c)[\s#:.-]*(\d{9,18}))",
            re.I,
        ),
        "confidence": 0.80,
    },
    # --- IFSC Codes ---
    {
        "type": "ifsc",
        "pattern": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        "confidence": 0.90,
    },
    # --- URLs ---
    {
        "type": "url",
        "pattern": re.compile(
            r"https?://[^\s<>\"']+|"
            r"(?:bit\.ly|tinyurl\.com|short\.io|is\.gd|rebrand\.ly|t\.co)/[^\s<>\"']+",
            re.I,
        ),
        "confidence": 0.85,
    },
    # --- PAN Card ---
    {
        "type": "pan",
        "pattern": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        "confidence": 0.80,
    },
    # --- Aadhaar ---
    {
        "type": "aadhaar",
        "pattern": re.compile(
            r"(?:aadhaar|aadhar|uid)[\s#:.-]*(\d{4}[\s-]?\d{4}[\s-]?\d{4})",
            re.I,
        ),
        "confidence": 0.75,
    },
    # --- Email ---
    {
        "type": "email",
        "pattern": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.I),
        "confidence": 0.85,
    },
    # --- Names ---
    {
        "type": "name",
        "pattern": re.compile(
            r"(?:(?:my name is|i am|this is|i'?m|call me)\s+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)"
            r"|(?:(?:mr|mrs|ms|dr|shri|smt)\.?\s+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",
            re.I,
        ),
        "confidence": 0.70,
    },
    # --- Organization ---
    {
        "type": "organization",
        "pattern": re.compile(
            r"(?:from|with|at|of)\s+((?:[A-Z][a-z]+\s*){1,3}(?:bank|ltd|pvt|limited|private|"
            r"finance|insurance|securities|telecom|services))",
            re.I,
        ),
        "confidence": 0.65,
    },
    # --- Crypto Addresses ---
    {
        "type": "crypto_btc",
        "pattern": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-zA-HJ-NP-Z0-9]{39,59}\b"),
        "confidence": 0.85,
    },
    {
        "type": "crypto_eth",
        "pattern": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
        "confidence": 0.85,
    },
]


class IntelligenceExtractor:
    """Extract actionable intelligence from scammer messages."""

    def __init__(self):
        self._seen: set[str] = set()

    def extract(self, message: str) -> ExtractionResult:
        """Extract all intelligence items from a message."""
        result = ExtractionResult()

        for spec in EXTRACTION_PATTERNS:
            for match in spec["pattern"].finditer(message):
                value = match.group(0).strip()

                # For named groups, try to get the captured group
                if spec["type"] in ("bank_account", "aadhaar"):
                    for g in match.groups():
                        if g:
                            value = g.strip()
                            break
                elif spec["type"] in ("name", "organization"):
                    for g in match.groups():
                        if g:
                            value = g.strip()
                            break

                # Deduplicate
                dedup_key = f"{spec['type']}:{value.lower()}"
                if dedup_key in self._seen:
                    continue
                self._seen.add(dedup_key)

                # Filter out UPI-like patterns from email matches
                if spec["type"] == "email" and any(
                    value.lower().endswith(f"@{suf}")
                    for suf in ["upi", "ybl", "paytm", "okaxis", "oksbi"]
                ):
                    continue

                # Get surrounding context
                start = max(0, match.start() - 30)
                end = min(len(message), match.end() + 30)
                context = message[start:end].strip()

                result.items.append(
                    ExtractedItem(
                        type=spec["type"],
                        value=value,
                        confidence=spec["confidence"],
                        context=context,
                    )
                )

        # Calculate total extraction score
        if result.items:
            weights = {"upi": 3, "phone": 2, "bank_account": 3, "url": 2, "ifsc": 2,
                        "name": 1, "organization": 1, "pan": 2, "aadhaar": 2,
                        "email": 1, "crypto_btc": 2, "crypto_eth": 2}
            total = sum(weights.get(i.type, 1) * i.confidence for i in result.items)
            result.total_score = min(round(total / 10, 4), 1.0)

        return result

    def extract_from_history(self, messages: list[str]) -> ExtractionResult:
        """Extract intelligence from all messages in history."""
        combined = ExtractionResult()
        for msg in messages:
            partial = self.extract(msg)
            combined.items.extend(partial.items)
        if combined.items:
            weights = {"upi": 3, "phone": 2, "bank_account": 3, "url": 2, "ifsc": 2,
                        "name": 1, "organization": 1, "pan": 2, "aadhaar": 2,
                        "email": 1, "crypto_btc": 2, "crypto_eth": 2}
            total = sum(weights.get(i.type, 1) * i.confidence for i in combined.items)
            combined.total_score = min(round(total / 10, 4), 1.0)
        return combined

    def reset(self):
        """Reset dedup state for new session."""
        self._seen.clear()
