"""
AI-Generated Voice Detection — Problem Statement 1.

Analyzes audio to detect whether speech is AI-generated or human.
Uses GROQ Whisper for transcription + heuristic analysis of speech patterns.
"""

import io
import re
import asyncio
from dataclasses import dataclass

from app.config import settings


@dataclass
class VoiceDetectionResult:
    is_ai_generated: bool
    confidence: float
    analysis: dict
    transcription: str


# ─── Heuristic Indicators of AI-Generated Speech ───

AI_SPEECH_INDICATORS = {
    # Unnaturally perfect grammar and structure
    "perfect_grammar": {
        "patterns": [
            r"\b(hereby|furthermore|additionally|consequently|therefore|henceforth)\b",
            r"\b(I would like to inform you|Please be advised|Kindly note)\b",
            r"\b(for your convenience|at your earliest convenience)\b",
        ],
        "weight": 0.15,
    },
    # Absence of natural speech disfluencies
    "no_fillers": {
        "patterns": [
            r"\b(um+|uh+|hmm+|er+|ah+|like,|you know,|I mean,)\b",
        ],
        "weight": -0.20,  # Negative = presence makes it LESS likely AI
    },
    # Robotic/corporate script patterns
    "scripted_language": {
        "patterns": [
            r"\b(this is a (recorded|automated) (message|call))\b",
            r"\b(press \d|press one|press two|press star)\b",
            r"\b(your call is important to us)\b",
            r"\b(for quality (assurance|purposes))\b",
            r"\b(this call (may|will) be (recorded|monitored))\b",
        ],
        "weight": 0.25,
    },
    # TTS artifact patterns in transcription
    "tts_artifacts": {
        "patterns": [
            r"(\w)\1{3,}",  # Repeated characters (TTS glitch)
            r"\b(dot|at the rate|slash slash|colon)\b",  # Spelled-out punctuation
            r"(?<!\d)(\d)\s+(\d)\s+(\d)\s+(\d)(?!\d)",  # Digit-by-digit reading
        ],
        "weight": 0.15,
    },
    # Unnatural prosody indicators in transcription
    "unnatural_flow": {
        "patterns": [
            r"[.!?]\s*[A-Z]",  # Overly precise sentence boundaries
        ],
        "weight": 0.05,
    },
    # Scam script patterns (common in AI robocalls)
    "scam_script": {
        "patterns": [
            r"\b(your (account|card|loan) (has been|will be) (blocked|suspended|compromised))\b",
            r"\b(verify your (identity|account|details))\b",
            r"\b(legal action will be taken)\b",
            r"\b(warrant (has been|will be) issued)\b",
            r"\b(contact us immediately|respond immediately)\b",
        ],
        "weight": 0.20,
    },
}


def analyze_transcription(text: str) -> dict:
    """Analyze transcription text for AI-generated speech indicators."""
    if not text:
        return {"score": 0.5, "indicators": [], "details": {}}

    score = 0.3  # Base score (slight lean toward human)
    indicators = []
    details = {}

    text_lower = text.lower()
    word_count = len(text.split())

    for indicator_name, config in AI_SPEECH_INDICATORS.items():
        matches = []
        for pattern in config["patterns"]:
            found = re.findall(pattern, text_lower, re.IGNORECASE)
            matches.extend(found)

        if matches:
            weight = config["weight"]
            if weight > 0:
                score += weight
                indicators.append(f"{indicator_name}: {len(matches)} matches")
            else:
                # Negative weight = human indicator
                score += weight  # Subtracts from score
                indicators.append(f"human_{indicator_name}: {len(matches)} matches")

        details[indicator_name] = len(matches)

    # ── Additional heuristics ──

    # 1. Sentence length consistency (AI tends to be uniform)
    sentences = re.split(r"[.!?]+", text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 5]
    if len(sentences) >= 3:
        lengths = [len(s.split()) for s in sentences]
        avg_len = sum(lengths) / len(lengths)
        variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
        if variance < 4:  # Very uniform sentence lengths
            score += 0.10
            indicators.append(f"uniform_sentences: variance={variance:.1f}")
        details["sentence_variance"] = round(variance, 2)

    # 2. Punctuation density (AI tends to be well-punctuated)
    punct_count = len(re.findall(r"[,;:!?.]", text))
    punct_ratio = punct_count / max(word_count, 1)
    if punct_ratio > 0.15:
        score += 0.05
        indicators.append(f"high_punctuation: ratio={punct_ratio:.2f}")
    details["punctuation_ratio"] = round(punct_ratio, 3)

    # 3. Repetition check (AI scripts often repeat key phrases)
    words = text_lower.split()
    if word_count > 20:
        bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words) - 1)]
        unique_bigrams = len(set(bigrams))
        repetition_ratio = 1 - (unique_bigrams / max(len(bigrams), 1))
        if repetition_ratio > 0.3:
            score += 0.10
            indicators.append(f"high_repetition: ratio={repetition_ratio:.2f}")
        details["repetition_ratio"] = round(repetition_ratio, 3)

    # Clamp score
    score = max(0.0, min(1.0, score))

    return {
        "score": round(score, 4),
        "indicators": indicators,
        "details": details,
    }


async def detect_ai_voice(audio_bytes: bytes, filename: str = "audio.wav") -> VoiceDetectionResult:
    """Detect whether audio contains AI-generated speech.

    Uses GROQ Whisper for transcription + heuristic analysis.
    """
    transcription = ""

    # Step 1: Transcribe with GROQ Whisper
    if settings.GROQ_API_KEY:
        try:
            from app.voice.stt import transcribe_audio
            result = await transcribe_audio(audio_bytes, filename=filename)
            transcription = result.get("text", "")
        except Exception as e:
            print(f"[VOICE DETECT] Transcription error: {e}")

    # Step 2: Analyze transcription for AI patterns
    analysis = analyze_transcription(transcription)

    # Step 3: Determine result
    is_ai = analysis["score"] >= 0.55

    return VoiceDetectionResult(
        is_ai_generated=is_ai,
        confidence=analysis["score"],
        analysis=analysis,
        transcription=transcription,
    )
