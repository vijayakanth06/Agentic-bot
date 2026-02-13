"""
Twilio Call Handler — Manages inbound voice calls via Twilio.

Flow: Inbound Call → Twilio WebSocket → Audio chunks → Whisper STT
     → GROQ LLM → ElevenLabs TTS → Audio back to caller
"""

from twilio.rest import Client as TwilioClient
from twilio.twiml.voice_response import VoiceResponse, Gather, Stream
from app.config import settings

_twilio_client = None


def _get_twilio_client() -> TwilioClient | None:
    global _twilio_client
    if _twilio_client is None and settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN:
        _twilio_client = TwilioClient(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    return _twilio_client


def generate_answer_twiml(session_id: str, websocket_url: str) -> str:
    """Generate TwiML to answer an incoming call and stream audio.

    Args:
        session_id: Unique session identifier for this call
        websocket_url: WebSocket URL for real-time audio streaming

    Returns:
        TwiML XML string
    """
    response = VoiceResponse()

    # Initial greeting while the system initializes
    response.say(
        "Hello, this is Priya speaking. How can I help you?",
        voice="Polly.Aditi",  # Indian English voice
        language="en-IN",
    )

    response.pause(length=1)

    # Start bi-directional audio stream
    stream = Stream(url=websocket_url)
    stream.parameter(name="session_id", value=session_id)
    response.append(stream)

    return str(response)


def generate_gather_twiml(session_id: str, action_url: str) -> str:
    """Generate TwiML with speech recognition (fallback mode without WebSocket).

    This uses Twilio's built-in STT instead of GROQ Whisper.
    Useful for simpler setups without WebSocket streaming.
    """
    response = VoiceResponse()

    response.say(
        "Hello, this is Priya speaking.",
        voice="Polly.Aditi",
        language="en-IN",
    )

    gather = Gather(
        input="speech",
        action=action_url,
        method="POST",
        timeout=5,
        speech_timeout="auto",
        language="en-IN",
    )
    gather.say(
        "Please tell me what this is regarding.",
        voice="Polly.Aditi",
        language="en-IN",
    )
    response.append(gather)

    # If no speech detected
    response.say(
        "I didn't catch that. Please call back.",
        voice="Polly.Aditi",
        language="en-IN",
    )

    return str(response)


def generate_response_twiml(
    response_text: str,
    audio_url: str | None = None,
    continue_url: str | None = None,
    session_id: str = "",
) -> str:
    """Generate TwiML to play a response and optionally gather more input.

    Args:
        response_text: Text to speak (used with Polly if no audio_url)
        audio_url: URL to pre-generated ElevenLabs audio file
        continue_url: URL to POST next speech input to
        session_id: Session ID for tracking
    """
    response = VoiceResponse()

    if audio_url:
        # Play pre-generated ElevenLabs audio (human-like voice)
        response.play(audio_url)
    else:
        # Fallback to Polly TTS
        response.say(response_text, voice="Polly.Aditi", language="en-IN")

    if continue_url:
        # Gather next input
        gather = Gather(
            input="speech",
            action=continue_url,
            method="POST",
            timeout=8,
            speech_timeout="auto",
            language="en-IN",
        )
        gather.pause(length=1)
        response.append(gather)

        # Timeout handling
        response.say(
            "Are you still there?",
            voice="Polly.Aditi",
            language="en-IN",
        )
        gather2 = Gather(
            input="speech",
            action=continue_url,
            method="POST",
            timeout=5,
            speech_timeout="auto",
            language="en-IN",
        )
        response.append(gather2)

    return str(response)


def get_call_info(call_sid: str) -> dict | None:
    """Get information about a call from Twilio API."""
    client = _get_twilio_client()
    if not client:
        return None
    try:
        call = client.calls(call_sid).fetch()
        return {
            "call_sid": call.sid,
            "from_number": call.from_formatted,
            "to_number": call.to_formatted,
            "status": call.status,
            "duration": call.duration,
            "direction": call.direction,
        }
    except Exception as e:
        print(f"[TWILIO ERROR] {e}")
        return None
