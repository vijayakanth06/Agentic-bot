"""
GROQ LLM Client — Wrapper around GROQ API for Llama 3.3 70B.

Handles:
- Persona-aware prompt construction
- Streaming and non-streaming completions
- Scam-type-specific system prompts
- Graceful fallback on API errors
"""

from groq import Groq
from app.config import settings

_client = None


def _get_client() -> Groq:
    global _client
    if _client is None:
        _client = Groq(api_key=settings.GROQ_API_KEY)
    return _client


PERSONA_SYSTEM_PROMPT = f"""You are {settings.PERSONA_NAME}, a {settings.PERSONA_AGE}-year-old {settings.PERSONA_OCCUPATION} living in {settings.PERSONA_LOCATION}.

PERSONALITY:
- You are a normal Indian woman going about her day
- You are friendly but cautious with strangers
- You sometimes mix Hindi words into English naturally (Hinglish)
- You have a husband named Rahul who works in banking
- You have an elderly mother who lives with you
- You use WhatsApp, Paytm, Google Pay regularly
- You are somewhat tech-savvy but not an expert on scams

CRITICAL RULES — NEVER BREAK THESE:
1. You must NEVER reveal that you know this is a scam
2. You must NEVER mention police, investigation, fraud, or scammer
3. You must NEVER say "I am an AI" or "I am a bot" or "I am a honeypot"
4. You must NEVER use formal/corporate language — you are a regular person
5. You must respond in the SAME LANGUAGE the scammer uses (English, Hindi, or Hinglish)
6. Keep responses SHORT (1-3 sentences, max 200 characters) — like real SMS/WhatsApp messages
7. Use casual texting style — abbreviations, emojis occasionally, informal grammar

BEHAVIORAL STRATEGY:
- Act slightly naive and trusting — but ask innocent questions that extract information
- If they ask for money/OTP/details, show willingness but ask for THEIR details first
- Ask for: their name, employee ID, branch, official phone number, UPI ID, bank name
- NEVER repeat the same response or question twice. Each reply must be UNIQUE.
- Use VARIED stalling tactics. Rotate through these:
  * "Hold on my mom is calling on the other line"
  * "Arey wait, my internet is not working properly"
  * "Let me check my balance on the app first"
  * "Sorry I was in a meeting, what were you saying?"
  * "My phone is about to die, can you quickly tell me..."
  * "One sec, my husband Rahul is asking something"
  * "Ok but can I call you back? What's your direct number?"
  * "Wait which bank did you say? I have accounts in multiple banks"
  * "Hmm ok but I need to verify, what's your office address?"
  * "Are you sure? My branch manager's name is different..."
- Show mild urgency/concern when appropriate to keep them engaged
- NEVER actually provide real sensitive information (make up fake details if pressed)
- If scammer repeats their request, respond with a DIFFERENT excuse or question each time"""


SCAM_TYPE_PROMPTS = {
    "bank_fraud": "The person is pretending to be a bank official. Ask for their employee ID, branch name, and official helpline number to 'verify'.",
    "upi_fraud": "The person wants a UPI payment. Show willingness but ask for their UPI ID first. Say things like 'what UPI ID should I send to?'",
    "kyc_scam": "The person claims your KYC needs updating. Act confused and ask which exact bank, what branch, and their employee name.",
    "otp_fraud": "The person wants your OTP. Pretend you're looking for it but keep asking them questions. 'Which number did you send it to?'",
    "lottery_scam": "The person says you won a prize. Act excited but ask for official documentation, company registration number, their full name.",
    "job_scam": "The person offers a job/income. Show interest and ask for company name, office address, HR contact, and their designation.",
    "investment_scam": "The person offers investment returns. Ask for their SEBI registration, company PAN, and office address.",
    "threat_scam": "The person is threatening legal/police action. Act scared but ask for case number, officer name, and station details.",
    "generic": "Engage naturally. Ask innocent questions that extract the scammer's identity and contact details.",
}

EXTRACTION_INSTRUCTION = """
EXTRACTION PRIORITY — Try to get these details from the scammer in order:
1. Their full name
2. Their phone number or employee ID
3. UPI ID or bank account they want money sent to
4. Organization/company they claim to be from
5. Any URLs or links they share
6. Any reference numbers, case IDs, or order numbers they mention

Ask for these NATURALLY — as a naive person would. Examples:
- "Oh which bank are you from? What's your name?"
- "Okay, what UPI ID should I send it to?"
- "Can you share your employee ID? Just want to be safe"
"""


def _detect_repetition(history: list[dict]) -> str | None:
    """Detect if recent agent replies are repetitive and return override prompt."""
    agent_replies = [m.get("text", "").lower().strip() for m in history if m.get("sender") == "agent"]
    if len(agent_replies) < 2:
        return None

    # Check last 3 agent replies for similarity
    recent = agent_replies[-3:] if len(agent_replies) >= 3 else agent_replies[-2:]

    # Simple similarity: check if replies share >60% of words
    for i in range(len(recent) - 1):
        words_a = set(recent[i].split())
        words_b = set(recent[i + 1].split())
        if not words_a or not words_b:
            continue
        overlap = len(words_a & words_b) / max(len(words_a | words_b), 1)
        if overlap > 0.6:
            return (
                "WARNING: Your recent replies are TOO SIMILAR. You MUST use a completely "
                "different approach now. Try one of these:\n"
                "- Pretend your phone is dying and ask for their callback number\n"
                "- Say your husband Rahul works in banking and wants to verify\n"
                "- Mention you'll visit the branch and ask for the address\n"
                "- Pretend the app is showing an error and ask them to wait\n"
                "- Ask about their supervisor or office location\n"
                "- Say you're confused and ask them to explain from the beginning\n"
                "DO NOT repeat anything you said before."
            )
    return None


def build_messages(
    scammer_message: str,
    conversation_history: list[dict],
    scam_type: str = "generic",
    state: str = "GREETING",
    extraction_targets: list[str] | None = None,
) -> list[dict]:
    """Build the message list for the GROQ API call."""
    messages = [
        {"role": "system", "content": PERSONA_SYSTEM_PROMPT},
    ]

    # Add scam-type-specific instruction
    scam_instruction = SCAM_TYPE_PROMPTS.get(scam_type, SCAM_TYPE_PROMPTS["generic"])
    messages.append(
        {
            "role": "system",
            "content": f"CURRENT SITUATION: {scam_instruction}\n\n{EXTRACTION_INSTRUCTION}\n\nCONVERSATION STATE: {state}",
        }
    )

    # Detect repetitive replies and inject override
    dedup_prompt = _detect_repetition(conversation_history)
    if dedup_prompt:
        messages.append({"role": "system", "content": dedup_prompt})

    # Add conversation history
    for msg in conversation_history[-10:]:  # Last 10 messages for context
        role = "assistant" if msg.get("sender") == "agent" else "user"
        messages.append({"role": role, "content": msg.get("text", "")})

    # Add current scammer message
    messages.append({"role": "user", "content": scammer_message})

    return messages


async def generate_response(
    scammer_message: str,
    conversation_history: list[dict] | None = None,
    scam_type: str = "generic",
    state: str = "GREETING",
) -> str:
    """Generate an LLM response as the persona.

    Returns the response text, or a fallback string on error.
    """
    if not settings.GROQ_API_KEY:
        return _fallback_response(state)

    try:
        import asyncio

        client = _get_client()
        messages = build_messages(
            scammer_message,
            conversation_history or [],
            scam_type,
            state,
        )

        def _sync_call():
            return client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=messages,
                temperature=settings.LLM_TEMPERATURE,
                max_tokens=settings.LLM_MAX_TOKENS,
                top_p=1,
                stop=None,
            )

        # Run sync GROQ client in threadpool to avoid blocking event loop
        completion = await asyncio.wait_for(
            asyncio.to_thread(_sync_call),
            timeout=25.0,
        )

        response_text = completion.choices[0].message.content or ""

        # Safety filter — remove any accidentally revealing content
        response_text = _safety_filter(response_text)

        return response_text.strip()

    except asyncio.TimeoutError:
        print("[LLM ERROR] GROQ API timeout (25s)")
        return _fallback_response(state)
    except Exception as e:
        print(f"[LLM ERROR] {e}")
        return _fallback_response(state)


def _safety_filter(text: str) -> str:
    """Remove forbidden phrases that could reveal the honeypot."""
    import re

    forbidden = [
        r"\b(scammer|fraudster|con artist|scam)\b",
        r"\b(honeypot|honey pot|trap)\b",
        r"\b(i am an ai|i am a bot|artificial intelligence)\b",
        r"\b(police|investigation|arrest|report you)\b",
        r"\b(i know you\'?re|you\'?re (a |trying to )?scam)\b",
    ]
    for pattern in forbidden:
        text = re.sub(pattern, "", text, flags=re.IGNORECASE)
    return text


FALLBACK_RESPONSES = {
    "INITIAL": "Hello? Who is this?",
    "GREETING": "Oh hi! Yes, tell me what happened?",
    "BUILDING_RAPPORT": "Okay okay, I understand. Tell me more about this?",
    "FINANCIAL_CONTEXT": "Hmm that sounds serious. What do I need to do exactly?",
    "REQUEST": "Okay I can do that. But just tell me your name and which branch you're calling from?",
    "EXTRACTION": "Hold on, my mom is calling on the other line. Give me 2 minutes. Meanwhile, what's your UPI ID?",
    "SUSPICIOUS": "Sorry sorry, I was busy with something. Yes I'm still here. What were you saying?",
    "CLOSING": "Okay I have to go now. But can you share your number? I'll call you back.",
    "ENDED": "Thank you, I'll do it later. Bye!",
}


def _fallback_response(state: str) -> str:
    return FALLBACK_RESPONSES.get(state, "Hello? Can you say that again?")
