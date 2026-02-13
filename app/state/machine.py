"""
Conversation State Machine — Manages conversation lifecycle.

9 states: INITIAL → GREETING → BUILDING_RAPPORT → FINANCIAL_CONTEXT
          → REQUEST → EXTRACTION → SUSPICIOUS → CLOSING → ENDED
"""

from dataclasses import dataclass
from enum import Enum


class State(str, Enum):
    INITIAL = "INITIAL"
    GREETING = "GREETING"
    BUILDING_RAPPORT = "BUILDING_RAPPORT"
    FINANCIAL_CONTEXT = "FINANCIAL_CONTEXT"
    REQUEST = "REQUEST"
    EXTRACTION = "EXTRACTION"
    SUSPICIOUS = "SUSPICIOUS"
    CLOSING = "CLOSING"
    ENDED = "ENDED"


@dataclass
class TransitionResult:
    next_state: State
    should_end: bool = False
    reason: str = ""


STATE_CONFIGS = {
    State.INITIAL: {"max_turns": 1, "next": [State.GREETING]},
    State.GREETING: {"max_turns": 3, "next": [State.BUILDING_RAPPORT, State.FINANCIAL_CONTEXT]},
    State.BUILDING_RAPPORT: {"max_turns": 5, "next": [State.FINANCIAL_CONTEXT, State.REQUEST]},
    State.FINANCIAL_CONTEXT: {"max_turns": 5, "next": [State.REQUEST, State.EXTRACTION]},
    State.REQUEST: {"max_turns": 3, "next": [State.EXTRACTION, State.SUSPICIOUS]},
    State.EXTRACTION: {"max_turns": 15, "next": [State.CLOSING, State.SUSPICIOUS]},
    State.SUSPICIOUS: {"max_turns": 3, "next": [State.EXTRACTION, State.CLOSING, State.ENDED]},
    State.CLOSING: {"max_turns": 2, "next": [State.ENDED]},
    State.ENDED: {"max_turns": 0, "next": []},
}


class StateMachine:
    """Manage conversation state transitions."""

    def __init__(self):
        self.current_state = State.INITIAL
        self.turn_count = 0
        self.state_turn_count = 0
        self.history: list[dict] = []

    def transition(
        self,
        scam_confidence: float = 0.0,
        has_financial_context: bool = False,
        has_direct_request: bool = False,
        extraction_progress: float = 0.0,
        scammer_terminated: bool = False,
    ) -> TransitionResult:
        """Determine the next state based on context."""
        self.turn_count += 1
        self.state_turn_count += 1
        current = self.current_state
        config = STATE_CONFIGS[current]

        # Terminal state
        if current == State.ENDED:
            return TransitionResult(State.ENDED, should_end=True, reason="Conversation ended")

        # Scammer terminated
        if scammer_terminated:
            result = TransitionResult(State.ENDED, should_end=True, reason="Scammer terminated")
            self._do_transition(result.next_state, result.reason)
            return result

        next_state = current
        reason = "No transition needed"

        if current == State.INITIAL:
            next_state = State.GREETING
            reason = "Initial classification done"

        elif current == State.GREETING:
            if has_financial_context or has_direct_request:
                next_state = State.FINANCIAL_CONTEXT
                reason = "Financial context detected early"
            elif self.state_turn_count >= config["max_turns"]:
                next_state = State.BUILDING_RAPPORT
                reason = "Max greeting turns reached"

        elif current == State.BUILDING_RAPPORT:
            if has_direct_request:
                next_state = State.REQUEST
                reason = "Direct request received"
            elif has_financial_context or self.state_turn_count >= config["max_turns"]:
                next_state = State.FINANCIAL_CONTEXT
                reason = "Financial context detected or max turns"

        elif current == State.FINANCIAL_CONTEXT:
            if has_direct_request:
                next_state = State.REQUEST
                reason = "Direct request received"
            elif self.state_turn_count >= config["max_turns"]:
                next_state = State.REQUEST
                reason = "Max turns, moving to request"

        elif current == State.REQUEST:
            if self.state_turn_count >= config["max_turns"]:
                next_state = State.EXTRACTION
                reason = "Moving to extraction phase"

        elif current == State.EXTRACTION:
            if extraction_progress >= 0.9 and self.turn_count >= 12:
                next_state = State.CLOSING
                reason = "Extraction targets met"
            elif self.state_turn_count >= config["max_turns"]:
                next_state = State.CLOSING
                reason = "Max extraction turns reached"

        elif current == State.SUSPICIOUS:
            if self.state_turn_count >= config["max_turns"]:
                next_state = State.CLOSING
                reason = "Could not recover from suspicion"
            else:
                next_state = State.EXTRACTION
                reason = "Recovery attempt"

        elif current == State.CLOSING:
            if self.state_turn_count >= config["max_turns"]:
                next_state = State.ENDED
                reason = "Closing complete"

        if next_state != current:
            self._do_transition(next_state, reason)

        return TransitionResult(
            next_state=self.current_state,
            should_end=self.current_state == State.ENDED,
            reason=reason,
        )

    def _do_transition(self, new_state: State, reason: str):
        self.history.append({
            "from": self.current_state.value,
            "to": new_state.value,
            "turn": self.turn_count,
            "reason": reason,
        })
        self.current_state = new_state
        self.state_turn_count = 0

    def get_state(self) -> str:
        return self.current_state.value

    def to_dict(self) -> dict:
        return {
            "current_state": self.current_state.value,
            "turn_count": self.turn_count,
            "state_turn_count": self.state_turn_count,
            "history": self.history,
        }
