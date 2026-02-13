"""
Speech-to-Text — GROQ Whisper Large V3 integration.

Transcribes audio from scam calls into text for the LLM pipeline.
"""

import io
from groq import Groq
from app.config import settings

_client = None


def _get_client() -> Groq:
    global _client
    if _client is None:
        _client = Groq(api_key=settings.GROQ_API_KEY)
    return _client


async def transcribe_audio(
    audio_data: bytes,
    filename: str = "audio.wav",
    language: str | None = None,
) -> dict:
    """Transcribe audio bytes using GROQ Whisper.

    Args:
        audio_data: Raw audio bytes (WAV, MP3, M4A, WebM, etc.)
        filename: Filename hint for format detection
        language: Optional language code (e.g., "en", "hi")

    Returns:
        Dict with keys: text, language, duration, segments
    """
    if not settings.GROQ_API_KEY:
        return {"text": "", "language": "unknown", "duration": 0, "segments": []}

    try:
        client = _get_client()

        kwargs = {
            "file": (filename, audio_data),
            "model": settings.STT_MODEL,
            "temperature": 0,
            "response_format": "verbose_json",
        }
        if language:
            kwargs["language"] = language

        transcription = client.audio.transcriptions.create(**kwargs)

        return {
            "text": transcription.text or "",
            "language": getattr(transcription, "language", "unknown"),
            "duration": getattr(transcription, "duration", 0),
            "segments": [
                {
                    "text": seg.get("text", "") if isinstance(seg, dict) else getattr(seg, "text", ""),
                    "start": seg.get("start", 0) if isinstance(seg, dict) else getattr(seg, "start", 0),
                    "end": seg.get("end", 0) if isinstance(seg, dict) else getattr(seg, "end", 0),
                }
                for seg in (getattr(transcription, "segments", []) or [])
            ],
        }

    except Exception as e:
        print(f"[STT ERROR] {e}")
        return {"text": "", "language": "unknown", "duration": 0, "segments": [], "error": str(e)}


async def transcribe_file(file_path: str, language: str | None = None) -> dict:
    """Transcribe an audio file from disk."""
    with open(file_path, "rb") as f:
        audio_data = f.read()
    filename = file_path.split("/")[-1].split("\\")[-1]
    return await transcribe_audio(audio_data, filename, language)
