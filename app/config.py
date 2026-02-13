"""
Configuration — Centralized settings from environment variables.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from .env file."""

    # --- API Keys ---
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    ELEVENLABS_API_KEY: str = os.getenv("ELEVENLABS_API_KEY", "")
    TWILIO_ACCOUNT_SID: str = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN: str = os.getenv("TWILIO_AUTH_TOKEN", "")
    TWILIO_PHONE_NUMBER: str = os.getenv("TWILIO_PHONE_NUMBER", "")
    API_KEY: str = os.getenv("API_KEY", "honeypot-secret-key")

    # --- Server ---
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # --- LLM ---
    LLM_MODEL: str = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.8"))
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "512"))

    # --- Voice ---
    STT_MODEL: str = os.getenv("STT_MODEL", "whisper-large-v3")
    ELEVENLABS_VOICE_ID: str = os.getenv("ELEVENLABS_VOICE_ID", "")
    ELEVENLABS_MODEL: str = os.getenv("ELEVENLABS_MODEL", "eleven_multilingual_v2")

    # --- Database ---
    DB_PATH: str = os.getenv("DB_PATH", "honeypot.db")

    # --- GUVI Callback ---
    GUVI_CALLBACK_URL: str = os.getenv(
        "GUVI_CALLBACK_URL",
        "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
    )

    # --- Persona ---
    PERSONA_NAME: str = os.getenv("PERSONA_NAME", "Priya Sharma")
    PERSONA_AGE: int = int(os.getenv("PERSONA_AGE", "28"))
    PERSONA_LOCATION: str = os.getenv("PERSONA_LOCATION", "Mumbai, Andheri West")
    PERSONA_OCCUPATION: str = os.getenv("PERSONA_OCCUPATION", "Software Engineer at TCS")


settings = Settings()
