"""
Agentic Honeypot â€” Main FastAPI Application.

Product-grade system handling both messages and voice calls.
Endpoints:
  POST /api/honeypot        â€” Process scam message (GUVI compatible)
  POST /api/voice/detect    â€” AI-generated voice detection (Problem 1)
  POST /api/handoff         â€” User triggers AI hand-off
  POST /api/voice/incoming  â€” Twilio inbound call webhook
  POST /api/voice/respond   â€” Twilio speech recognition callback
  GET  /api/sessions        â€” List all sessions
  GET  /api/sessions/{id}   â€” Get session detail + intel
  GET  /api/reports/{id}    â€” Generate & download PDF report
  GET  /api/dashboard       â€” Dashboard statistics
  GET  /health              â€” Health check
  WS   /ws/dashboard        â€” Real-time dashboard WebSocket
"""

import os
import sys
import json
import uuid
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

# Ensure project root is importable (for Vercel + direct run)
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from fastapi import FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect, Header, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.config import settings
from app.llm.groq_client import generate_response
from app.detection.scam_detector import ScamDetector, DetectionResult
from app.extraction.extractor import IntelligenceExtractor
from app.state.machine import StateMachine, State
from app.handoff.handler import HandoffHandler, HandoffMode
from app.database.db import (
    init_db, create_session as db_create_session,
    update_session as db_update_session, save_message, save_intelligence,
    save_handoff_event, get_session as db_get_session,
    get_messages, get_intelligence, get_all_sessions, get_dashboard_stats,
)
from app.reports.generator import generate_report
from app.voice.stt import transcribe_audio
from app.voice.tts import text_to_speech
from app.voice.call_handler import generate_answer_twiml, generate_gather_twiml, generate_response_twiml
from app.voice.voice_detector import detect_ai_voice

# â”€â”€â”€ Session Store (in-memory, synced to DB) â”€â”€â”€

sessions: dict[str, dict] = {}
detector = ScamDetector()
handoff_handler = HandoffHandler()
dashboard_websockets: list[WebSocket] = []


# â”€â”€â”€ Lifespan â”€â”€â”€

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await init_db()
    except Exception as e:
        print(f"âš ï¸  Database init skipped: {e}")
    print(f"ðŸ¯ Agentic Honeypot started on port {settings.PORT}")
    print(f"   GROQ API: {'âœ… Configured' if settings.GROQ_API_KEY else 'âŒ Missing'}")
    print(f"   ElevenLabs: {'âœ… Configured' if settings.ELEVENLABS_API_KEY else 'âŒ Missing'}")
    print(f"   Twilio: {'âœ… Configured' if settings.TWILIO_ACCOUNT_SID else 'âŒ Missing'}")
    yield
    print("ðŸ›‘ Honeypot shutting down")


# â”€â”€â”€ App â”€â”€â”€

app = FastAPI(
    title="Agentic Honeypot",
    description="AI-powered scam detection & engagement system",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


# â”€â”€â”€ API Key Authentication â”€â”€â”€

async def verify_api_key(x_api_key: str = Header(None)):
    """Verify the x-api-key header for protected endpoints."""
    if not x_api_key or x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key


# â”€â”€â”€ Request/Response Models â”€â”€â”€

class MessageInput(BaseModel):
    sender: str = "scammer"
    text: str
    timestamp: int | None = None


class HoneypotRequest(BaseModel):
    sessionId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    message: MessageInput
    conversationHistory: list[dict] = []
    metadata: dict = {}


class HandoffRequest(BaseModel):
    sessionId: str
    action: str = "activate"  # activate | deactivate | monitor


# â”€â”€â”€ Helper: Get or create session â”€â”€â”€

def get_session(session_id: str) -> dict:
    if session_id not in sessions:
        sessions[session_id] = {
            "id": session_id,
            "state_machine": StateMachine(),
            "extractor": IntelligenceExtractor(),
            "history": [],
            "intelligence": [],
            "scam_type": "unknown",
            "scam_confidence": 0.0,
            "created_at": datetime.now().isoformat(),
            "channel": "message",
        }
    return sessions[session_id]


async def broadcast_dashboard(event: dict):
    """Broadcast event to all connected dashboard WebSockets."""
    dead = []
    for ws in dashboard_websockets:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        dashboard_websockets.remove(ws)


# â”€â”€â”€ API Endpoints â”€â”€â”€

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "agentic-honeypot",
        "version": "2.0.0",
        "uptime": datetime.now().isoformat(),
        "components": {
            "groq": bool(settings.GROQ_API_KEY),
            "elevenlabs": bool(settings.ELEVENLABS_API_KEY),
            "twilio": bool(settings.TWILIO_ACCOUNT_SID),
        },
    }


@app.post("/api/honeypot")
async def honeypot_endpoint(req: HoneypotRequest, x_api_key: str = Header(None)):
    """Main honeypot endpoint â€” processes scam messages.

    Compatible with GUVI evaluation format.
    """
    # API key validation (allow requests without key for local dev)
    if x_api_key and x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    session = get_session(req.sessionId)
    sm: StateMachine = session["state_machine"]
    extractor: IntelligenceExtractor = session["extractor"]
    message_text = req.message.text

    # 1. Detect scam
    history_texts = [m.get("text", "") for m in session["history"] if m.get("sender") == "scammer"]
    detection: DetectionResult = detector.analyze(message_text, history_texts)

    session["scam_confidence"] = max(session["scam_confidence"], detection.confidence)
    if detection.is_scam and session["scam_type"] == "unknown":
        session["scam_type"] = detection.scam_type

    # 2. Extract intelligence
    extraction = extractor.extract(message_text)
    new_intel = [{"type": i.type, "value": i.value, "confidence": i.confidence, "context": i.context} for i in extraction.items]
    session["intelligence"].extend(new_intel)

    # 3. Auto hand-off if scam detected
    handoff_handler.auto_handoff(
        req.sessionId,
        session["scam_confidence"],
        threshold=0.35,
        message_count=len(session["history"]),
    )

    # 4. State transition
    transition = sm.transition(
        scam_confidence=session["scam_confidence"],
        has_financial_context=detection.has_financial_context,
        has_direct_request=detection.has_direct_request,
        extraction_progress=extraction.total_score,
    )

    # 5. Generate LLM response
    reply = await generate_response(
        scammer_message=message_text,
        conversation_history=session["history"],
        scam_type=session["scam_type"],
        state=sm.get_state(),
    )

    # 6. Store in history
    session["history"].append({"sender": "scammer", "text": message_text})
    session["history"].append({"sender": "agent", "text": reply})

    # 7. Persist to DB (best-effort, don't block response)
    try:
        await db_create_session(req.sessionId, channel="message")
        await save_message(req.sessionId, "scammer", message_text, sm.get_state())
        await save_message(req.sessionId, "agent", reply, sm.get_state())
        if new_intel:
            await save_intelligence(req.sessionId, new_intel)
        await db_update_session(
            req.sessionId,
            scam_type=session["scam_type"],
            scam_confidence=session["scam_confidence"],
            state=sm.get_state(),
            turn_count=sm.turn_count,
            total_extracted=len(session["intelligence"]),
        )
    except Exception as e:
        print(f"[DB] Persist skipped: {e}")

    # 8. Broadcast to dashboard
    await broadcast_dashboard({
        "type": "message",
        "session_id": req.sessionId,
        "scam_type": session["scam_type"],
        "confidence": session["scam_confidence"],
        "state": sm.get_state(),
        "turn": sm.turn_count,
        "intel_count": len(session["intelligence"]),
    })

    # 9. Categorize extracted intelligence for GUVI format
    all_intel = session["intelligence"]
    bank_accounts = list({i["value"] for i in all_intel if i["type"] in ("bank_account", "ifsc")})
    upi_ids = list({i["value"] for i in all_intel if i["type"] == "upi"})
    phishing_links = list({i["value"] for i in all_intel if i["type"] == "url"})
    phone_numbers = list({i["value"] for i in all_intel if i["type"] == "phone"})
    suspicious_kw = list({ind.get("category", "suspicious") if isinstance(ind, dict) else str(ind) for ind in detection.indicators})

    # 10. Response (GUVI compatible)
    return {
        "status": "success",
        "reply": reply,
        # â”€â”€â”€ GUVI evaluation fields â”€â”€â”€
        "scamDetected": detection.is_scam or session["scam_confidence"] > 0.3,
        "totalMessagesExchanged": sm.turn_count,
        "extractedIntelligence": {
            "bankAccounts": bank_accounts,
            "upiIds": upi_ids,
            "phishingLinks": phishing_links,
            "phoneNumbers": phone_numbers,
            "suspiciousKeywords": suspicious_kw[:10],
        },
        "agentNotes": f"Scam type: {session['scam_type']}. Tactics used: {', '.join(suspicious_kw[:5])}. Phone numbers collected: {len(phone_numbers)}. Total engagement: {sm.turn_count} messages",
        # â”€â”€â”€ Extended fields â”€â”€â”€
        "analysis": {
            "is_scam": detection.is_scam,
            "scam_confidence": session["scam_confidence"],
            "scam_type": session["scam_type"],
            "urgency_level": detection.urgency_level,
        },
        "intelligence": {
            "extracted": new_intel,
            "total_items": len(all_intel),
            "extraction_score": extraction.total_score,
        },
        "state": {
            "current": sm.get_state(),
            "turn_count": sm.turn_count,
            "should_end": transition.should_end,
        },
        "handoff": handoff_handler.get_state(req.sessionId),
    }


@app.post("/api/handoff")
async def handoff_endpoint(req: HandoffRequest):
    """User hand-off control endpoint."""
    session = get_session(req.sessionId)

    if req.action == "activate":
        state = handoff_handler.initiate_handoff(
            req.sessionId,
            reason="user_triggered",
            scam_confidence=session["scam_confidence"],
            message_count=len(session["history"]),
        )
        try:
            await save_handoff_event(req.sessionId, "user", "ai_agent", "user_triggered", session["scam_confidence"])
            await db_update_session(req.sessionId, handoff_mode="ai_agent")
        except Exception:
            pass
    elif req.action == "deactivate":
        state = handoff_handler.revoke_handoff(req.sessionId)
        try:
            await save_handoff_event(req.sessionId, "ai_agent", "user", "user_revoked", 0)
            await db_update_session(req.sessionId, handoff_mode="user")
        except Exception:
            pass
    elif req.action == "monitor":
        state = handoff_handler.set_monitoring(req.sessionId)
        try:
            await save_handoff_event(req.sessionId, "user", "monitoring", "user_set_monitoring", 0)
            await db_update_session(req.sessionId, handoff_mode="monitoring")
        except Exception:
            pass
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use: activate, deactivate, monitor")

    await broadcast_dashboard({"type": "handoff", "session_id": req.sessionId, "mode": state.mode.value})
    return {"status": "success", "handoff": handoff_handler.get_state(req.sessionId)}


# â”€â”€â”€ Voice Call Endpoints â”€â”€â”€

@app.post("/api/voice/incoming")
async def voice_incoming(request: Request):
    """Twilio webhook â€” called when an inbound call arrives."""
    form = await request.form()
    call_sid = form.get("CallSid", str(uuid.uuid4()))
    from_number = form.get("From", "unknown")

    session_id = f"call-{call_sid}"
    session = get_session(session_id)
    session["channel"] = "voice"
    session["caller"] = from_number

    try:
        await db_create_session(session_id, channel="voice")
    except Exception:
        pass

    # Auto-activate AI for all incoming calls
    handoff_handler.initiate_handoff(session_id, reason="auto_voice", scam_confidence=0)

    # Generate TwiML â€” use Gather mode with speech recognition
    base_url = str(request.base_url).rstrip("/")
    action_url = f"{base_url}/api/voice/respond?session_id={session_id}"
    twiml = generate_gather_twiml(session_id, action_url)

    await broadcast_dashboard({
        "type": "call_incoming",
        "session_id": session_id,
        "from": from_number,
    })

    return Response(content=twiml, media_type="application/xml")


@app.post("/api/voice/respond")
async def voice_respond(request: Request, session_id: str = ""):
    """Twilio callback â€” processes speech input from the caller."""
    form = await request.form()
    speech_text = form.get("SpeechResult", "")

    if not speech_text:
        twiml = generate_response_twiml(
            "I'm sorry, I didn't catch that. Can you say that again?",
            continue_url=f"{str(request.base_url).rstrip('/')}/api/voice/respond?session_id={session_id}",
        )
        return Response(content=twiml, media_type="application/xml")

    session = get_session(session_id)
    sm: StateMachine = session["state_machine"]
    extractor: IntelligenceExtractor = session["extractor"]

    # 1. Detect scam from speech
    history_texts = [m.get("text", "") for m in session["history"] if m.get("sender") == "scammer"]
    detection = detector.analyze(speech_text, history_texts)
    session["scam_confidence"] = max(session["scam_confidence"], detection.confidence)
    if detection.is_scam and session["scam_type"] == "unknown":
        session["scam_type"] = detection.scam_type

    # 2. Extract intelligence
    extraction = extractor.extract(speech_text)
    new_intel = [{"type": i.type, "value": i.value, "confidence": i.confidence, "context": i.context} for i in extraction.items]
    session["intelligence"].extend(new_intel)

    # 3. State transition
    sm.transition(
        scam_confidence=session["scam_confidence"],
        has_financial_context=detection.has_financial_context,
        has_direct_request=detection.has_direct_request,
        extraction_progress=extraction.total_score,
    )

    # 4. Generate LLM response
    reply = await generate_response(
        scammer_message=speech_text,
        conversation_history=session["history"],
        scam_type=session["scam_type"],
        state=sm.get_state(),
    )

    # 5. Store in history & DB
    session["history"].append({"sender": "scammer", "text": speech_text})
    session["history"].append({"sender": "agent", "text": reply})
    try:
        await save_message(session_id, "scammer", speech_text, sm.get_state(), "voice")
        await save_message(session_id, "agent", reply, sm.get_state(), "voice")
        if new_intel:
            await save_intelligence(session_id, new_intel)
        await db_update_session(
            session_id,
            scam_type=session["scam_type"],
            scam_confidence=session["scam_confidence"],
            state=sm.get_state(),
            turn_count=sm.turn_count,
            total_extracted=len(session["intelligence"]),
        )
    except Exception as e:
        print(f"[DB] Voice persist skipped: {e}")

    # 6. Try ElevenLabs TTS for human-like voice
    audio_url = None
    try:
        if settings.ELEVENLABS_API_KEY:
            audio_bytes = await text_to_speech(reply)
            if audio_bytes:
                # Save audio temporarily and serve it
                os.makedirs("temp_audio", exist_ok=True)
                audio_filename = f"resp_{session_id}_{sm.turn_count}.mp3"
                audio_path = os.path.join("temp_audio", audio_filename)
                with open(audio_path, "wb") as f:
                    f.write(audio_bytes)
                base_url = str(request.base_url).rstrip("/")
                audio_url = f"{base_url}/audio/{audio_filename}"
    except Exception as e:
        print(f"[TTS ERROR] Falling back to Polly: {e}")

    # 7. Generate TwiML response
    base_url = str(request.base_url).rstrip("/")
    continue_url = f"{base_url}/api/voice/respond?session_id={session_id}"

    if sm.current_state == State.ENDED:
        twiml = generate_response_twiml(reply, audio_url=audio_url)
    else:
        twiml = generate_response_twiml(reply, audio_url=audio_url, continue_url=continue_url)

    await broadcast_dashboard({
        "type": "voice_turn",
        "session_id": session_id,
        "scammer_said": speech_text,
        "agent_said": reply,
        "state": sm.get_state(),
        "confidence": session["scam_confidence"],
    })

    return Response(content=twiml, media_type="application/xml")


# â”€â”€â”€ Data Endpoints â”€â”€â”€

@app.get("/api/sessions")
async def list_sessions():
    try:
        sessions_list = await get_all_sessions()
    except Exception:
        sessions_list = []
    return {"status": "success", "sessions": sessions_list}


@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: str):
    try:
        session_data = await db_get_session(session_id)
        if not session_data:
            raise HTTPException(status_code=404, detail="Session not found")
        messages = await get_messages(session_id)
        intelligence = await get_intelligence(session_id)
    except HTTPException:
        raise
    except Exception:
        return {"status": "error", "detail": "Database unavailable"}
    return {
        "status": "success",
        "session": session_data,
        "messages": messages,
        "intelligence": intelligence,
        "handoff": handoff_handler.get_state(session_id),
    }


@app.get("/api/reports/{session_id}")
async def download_report(session_id: str):
    """Generate and download a PDF law enforcement report."""
    try:
        session_data = await db_get_session(session_id)
        if not session_data:
            raise HTTPException(status_code=404, detail="Session not found")
        messages = await get_messages(session_id)
        intelligence = await get_intelligence(session_id)
        filepath = await generate_report(session_id, session_data, messages, intelligence)
        return FileResponse(filepath, filename=os.path.basename(filepath), media_type="application/pdf")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")


@app.get("/api/dashboard")
async def dashboard_stats():
    try:
        stats = await get_dashboard_stats()
    except Exception:
        stats = {"total_sessions": 0, "active_sessions": 0, "scams_detected": 0, "intelligence_items": 0, "total_messages": 0}
    return {"status": "success", **stats}


# â”€â”€â”€ WebSocket for Live Dashboard â”€â”€â”€

@app.websocket("/ws/dashboard")
async def websocket_dashboard(ws: WebSocket):
    await ws.accept()
    dashboard_websockets.append(ws)
    try:
        while True:
            await ws.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        dashboard_websockets.remove(ws)


# â”€â”€â”€ Serve TTS Audio Files â”€â”€â”€

audio_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "temp_audio")
os.makedirs(audio_dir, exist_ok=True)
app.mount("/audio", StaticFiles(directory=audio_dir), name="audio")


# â”€â”€â”€ Serve Frontend â”€â”€â”€

@app.get("/")
async def serve_frontend():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return HTMLResponse(open(index_path, encoding="utf-8").read())
    return HTMLResponse("<h1>Agentic Honeypot</h1><p>Frontend not found. Place index.html in /frontend/</p>")


# â”€â”€â”€ Problem 1: AI Voice Detection â”€â”€â”€

@app.post("/api/voice/detect")
async def voice_detect_endpoint(
    audio: UploadFile = File(...),
    x_api_key: str = Header(None),
):
    """Problem 1 â€” Detect whether audio contains AI-generated speech."""
    if x_api_key and x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    audio_bytes = await audio.read()
    if not audio_bytes:
        raise HTTPException(status_code=400, detail="Empty audio file")

    result = await detect_ai_voice(audio_bytes, filename=audio.filename or "audio.wav")

    return {
        "status": "success",
        "isAIGenerated": result.is_ai_generated,
        "confidence": result.confidence,
        "transcription": result.transcription,
        "analysis": result.analysis,
    }


# â”€â”€â”€ Backward Compat (GUVI) â”€â”€â”€

@app.post("/api/conversation")
async def conversation_compat(req: HoneypotRequest, x_api_key: str = Header(None)):
    """Legacy endpoint for backward compatibility."""
    return await honeypot_endpoint(req, x_api_key)


# â”€â”€â”€ Run â”€â”€â”€

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)

