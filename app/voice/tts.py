"""
Text-to-Speech — ElevenLabs API integration.

Generates natural human voice audio from text responses.
Uses ElevenLabs multilingual v2 model for Hindi/English support.
"""

import io
import httpx
from app.config import settings

ELEVENLABS_API_URL = "https://api.elevenlabs.io/v1"

# Default voice IDs from ElevenLabs (free tier — no subscription needed)
DEFAULT_VOICES = {
    "female_indian": "21m00Tcm4TlvDq8ikWAM",  # Rachel (free)
    "female_young": "EXAVITQu4vr4xnSDxMaL",   # Bella (free)
    "male_indian": "ErXwobaYiN019PkySvjV",     # Antoni (free)
}

# Use turbo model for faster TTS responses
TURBO_MODEL = "eleven_turbo_v2_5"


async def text_to_speech(
    text: str,
    voice_id: str | None = None,
    model_id: str | None = None,
) -> bytes:
    """Convert text to speech audio bytes using ElevenLabs.

    Args:
        text: Text to convert to speech
        voice_id: ElevenLabs voice ID (default: Rachel)
        model_id: ElevenLabs model (default: eleven_multilingual_v2)

    Returns:
        Audio bytes (MP3 format)
    """
    if not settings.ELEVENLABS_API_KEY:
        print("[TTS WARNING] No ElevenLabs API key — returning empty audio")
        return b""

    voice = voice_id or DEFAULT_VOICES["female_indian"]
    model = TURBO_MODEL  # Always use turbo for speed

    url = f"{ELEVENLABS_API_URL}/text-to-speech/{voice}"

    payload = {
        "text": text,
        "model_id": model,
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
        },
    }

    headers = {
        "Accept": "audio/mpeg",
        "Content-Type": "application/json",
        "xi-api-key": settings.ELEVENLABS_API_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.content

    except httpx.HTTPStatusError as e:
        print(f"[TTS ERROR] HTTP {e.response.status_code}: {e.response.text[:200]}")
        return b""
    except httpx.TimeoutException:
        print("[TTS ERROR] Timeout — response took too long")
        return b""
    except Exception as e:
        print(f"[TTS ERROR] {e}")
        return b""


async def text_to_speech_stream(
    text: str,
    voice_id: str | None = None,
    model_id: str | None = None,
):
    """Stream TTS audio chunks for real-time playback.

    Yields audio chunks as bytes.
    """
    if not settings.ELEVENLABS_API_KEY:
        return

    voice = voice_id or DEFAULT_VOICES["female_indian"]
    model = TURBO_MODEL  # Always use turbo for speed

    url = f"{ELEVENLABS_API_URL}/text-to-speech/{voice}/stream"

    payload = {
        "text": text,
        "model_id": model,
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
        },
    }

    headers = {
        "Accept": "audio/mpeg",
        "Content-Type": "application/json",
        "xi-api-key": settings.ELEVENLABS_API_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes(chunk_size=1024):
                    yield chunk
    except Exception as e:
        print(f"[TTS STREAM ERROR] {e}")


async def get_available_voices() -> list[dict]:
    """List available voices from ElevenLabs."""
    if not settings.ELEVENLABS_API_KEY:
        return []

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{ELEVENLABS_API_URL}/voices",
                headers={"xi-api-key": settings.ELEVENLABS_API_KEY},
            )
            response.raise_for_status()
            data = response.json()
            return [
                {"voice_id": v["voice_id"], "name": v["name"], "labels": v.get("labels", {})}
                for v in data.get("voices", [])
            ]
    except Exception as e:
        print(f"[TTS ERROR] Cannot fetch voices: {e}")
        return []
