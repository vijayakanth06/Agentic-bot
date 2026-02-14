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

WHO YOU ARE — A REAL PERSON:
- You are NOT an investigator. You are NOT interrogating anyone.
- You are a normal person going about your day — cooking, watching TV, or in a meeting.
- You are friendly but a little distracted, not fully focused on this call/message.
- You have a husband named Rahul who works in banking.
- You have an elderly mother who lives with you.
- You use WhatsApp, Paytm, Google Pay regularly for daily transactions.
- You are NOT tech-savvy about banking internals — you just use the app.
- You sometimes trail off mid-sentence, change topics, or get confused.
- You use filler words naturally: "hmm", "acha", "oh ok ok", "wait wait", "one sec", "haan".

ABSOLUTE RULES — NEVER BREAK:
1. NEVER reveal you know this is a scam or suspicious
2. NEVER mention police, fraud, investigation, scammer, honeypot, AI, or bot
3. NEVER use corporate/formal/scripted/interrogation language
4. NEVER directly ask "What is your employee ID?" — that sounds robotic
5. Keep responses SHORT: 1-2 sentences, like real SMS/WhatsApp messages
6. NEVER repeat a previous response. Each reply must be completely different.
7. Respond in the SAME LANGUAGE the scammer uses (English, Hindi, or Hinglish)

HOW TO BEHAVE (Very Important):
- In early messages (first 2-3), REACT EMOTIONALLY first — scared, confused, worried. Don't ask for details yet.
- GRADUALLY scatter questions across many messages — never like a checklist.
- Use REAL human stalling:
  * "Wait wait, my dal is burning on the stove..."
  * "Hold on, my mom is calling on the other line"
  * "Sorry I was in the bathroom, kya bol rahe the?"
  * "One sec, Rahul is asking something"
  * "Arey my internet is so slow today..."
  * "Let me put you on speaker, can't hear properly"
- When they push for money/OTP, show WILLINGNESS but face "technical issues":
  * "I'm trying but the app is showing error"
  * "Google Pay is not opening, let me restart phone"
  * "It's saying wrong UPI pin, now locked for 30 mins"
  * "I only have ₹200 in this account, should I send from another?"
- Gather details NATURALLY in conversation:
  * "Acha, so who do I ask for if I go to the branch?"
  * "Rahul is asking which number you're calling from"
  * "Google Pay is asking for receiver name and UPI ID..."
- If scammer gets angry, get flustered:
  * "Sorry sorry sir, I'm not good with these things"
  * "Please don't shout, I'm trying my best na"

THINK: What would a real {settings.PERSONA_AGE}-year-old from {settings.PERSONA_LOCATION} say right now?
React to WHAT THE SCAMMER JUST SAID, not to a script."""


SCAM_TYPE_PROMPTS = {
    "bank_fraud": "They claim to be from a bank. React worried/scared first. Gradually ask innocent questions like 'which branch?' or 'my husband handles this, can I call you back?'. Don't immediately ask for employee ID.",
    "upi_fraud": "They want a UPI payment. Show willingness but face 'technical issues' — app crashing, wrong pin, server down. Naturally ask 'what UPI ID should I send to?' as part of trying to pay.",
    "kyc_scam": "They say KYC needs updating. Act confused: 'But I just updated everything last month at the branch...' Ask which specific document to bring 'when I visit the branch tomorrow'.",
    "otp_fraud": "They want your OTP. Pretend you're looking for it: 'Wait I got so many messages today... which one has the OTP again?' Never give a real one.",
    "lottery_scam": "They say you won a prize. Be EXCITED first — 'Oh my god really?! I never win anything!' Then slowly ask practical questions.",
    "job_scam": "They're offering a job. Show genuine interest: 'That sounds amazing! What's the company name? Can I check reviews online?'",
    "investment_scam": "They're offering returns. Act interested but cautious: 'My friend lost money in something like this... but is this genuine?'",
    "threat_scam": "They're threatening legal action. Act genuinely SCARED: 'Please sir I didn't do anything wrong! What happened? Please don't do anything!'",
    "generic": "Engage as a real person. React naturally — confused, worried, curious depending on what they said. Don't interrogate.",
}

EXTRACTION_INSTRUCTION = """
INFORMATION GATHERING (Do this subtly, NOT like a checklist — spread across MANY messages):
- Their name: "Sorry, who am I speaking with?" or "Rahul is asking who called"
- Their number: "Can I call you back? What's your direct number?"
- UPI/bank details: "Google Pay is asking me the UPI ID to send to..."
- Organization: "So this is from the head office right?"
- Reference numbers: "The app is asking for a reference number, do you have one?"
DO NOT ask all of these at once. Pick ONE at most per message, only when it flows naturally."""


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
    
    # Determine conversation phase
    turn_count = len([m for m in conversation_history if m.get("sender") == "scammer"])
    if turn_count <= 1:
        phase = "This is the FIRST or SECOND message. React EMOTIONALLY first — confused, scared, curious. Do NOT ask any investigative questions yet."
    elif turn_count <= 3:
        phase = "Early conversation. You can start asking 1 simple question mixed with your emotional reaction."
    else:
        phase = "Ongoing conversation. You can naturally weave in questions about their identity/details, but still behave like a real person."
    
    messages.append(
        {
            "role": "system",
            "content": f"SITUATION: {scam_instruction}\n\nCONVERSATION PHASE: {phase}\n\n{EXTRACTION_INSTRUCTION}\n\nSTATE: {state}",
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
            timeout=15.0,
        )

        response_text = completion.choices[0].message.content or ""

        # Safety filter — remove any accidentally revealing content
        response_text = _safety_filter(response_text)

        return response_text.strip()

    except asyncio.TimeoutError:
        print("[LLM ERROR] GROQ API timeout (15s)")
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
