"""
User Hand-Off Handler — Manages the transition from user to AI agent.

Problem statement requirement #1: "User can hand-off the interaction to, once the scam is detected"
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class HandoffMode(str, Enum):
    USER = "user"           # User is chatting manually
    AI_AGENT = "ai_agent"   # AI honeypot has taken over
    MONITORING = "monitoring"  # AI watches but user responds


@dataclass
class HandoffState:
    session_id: str
    mode: HandoffMode = HandoffMode.USER
    handoff_at: datetime | None = None
    trigger_reason: str = ""
    scam_confidence_at_handoff: float = 0.0
    messages_before_handoff: int = 0


class HandoffHandler:
    """Manage user ↔ AI agent hand-off per session."""

    def __init__(self):
        self._sessions: dict[str, HandoffState] = {}

    def get_or_create(self, session_id: str) -> HandoffState:
        if session_id not in self._sessions:
            self._sessions[session_id] = HandoffState(session_id=session_id)
        return self._sessions[session_id]

    def initiate_handoff(
        self,
        session_id: str,
        reason: str = "scam_detected",
        scam_confidence: float = 0.0,
        message_count: int = 0,
    ) -> HandoffState:
        """User triggers AI takeover."""
        state = self.get_or_create(session_id)
        state.mode = HandoffMode.AI_AGENT
        state.handoff_at = datetime.now()
        state.trigger_reason = reason
        state.scam_confidence_at_handoff = scam_confidence
        state.messages_before_handoff = message_count
        return state

    def auto_handoff(
        self,
        session_id: str,
        scam_confidence: float,
        threshold: float = 0.6,
        message_count: int = 0,
    ) -> HandoffState | None:
        """Automatically hand off if scam confidence exceeds threshold."""
        state = self.get_or_create(session_id)
        if state.mode == HandoffMode.USER and scam_confidence >= threshold:
            return self.initiate_handoff(
                session_id,
                reason=f"auto_detected (confidence={scam_confidence:.2f})",
                scam_confidence=scam_confidence,
                message_count=message_count,
            )
        return None

    def revoke_handoff(self, session_id: str) -> HandoffState:
        """User takes back control."""
        state = self.get_or_create(session_id)
        state.mode = HandoffMode.USER
        return state

    def set_monitoring(self, session_id: str) -> HandoffState:
        """AI watches but user responds."""
        state = self.get_or_create(session_id)
        state.mode = HandoffMode.MONITORING
        return state

    def is_ai_active(self, session_id: str) -> bool:
        state = self.get_or_create(session_id)
        return state.mode == HandoffMode.AI_AGENT

    def get_state(self, session_id: str) -> dict:
        state = self.get_or_create(session_id)
        return {
            "session_id": state.session_id,
            "mode": state.mode.value,
            "handoff_at": state.handoff_at.isoformat() if state.handoff_at else None,
            "trigger_reason": state.trigger_reason,
            "scam_confidence_at_handoff": state.scam_confidence_at_handoff,
        }
