/**
 * Conversation State Machine
 * 
 * Manages conversation states and transitions.
 * Ensures deterministic flow through engagement phases.
 */

const STATES = {
  INITIAL: 'INITIAL',
  GREETING: 'GREETING',
  BUILDING_RAPPORT: 'BUILDING_RAPPORT',
  FINANCIAL_CONTEXT: 'FINANCIAL_CONTEXT',
  REQUEST: 'REQUEST',
  EXTRACTION: 'EXTRACTION',
  SUSPICIOUS: 'SUSPICIOUS',
  CLOSING: 'CLOSING',
  ENDED: 'ENDED'
};

const STATE_CONFIGS = {
  INITIAL: {
    next: ['GREETING'],
    maxTurns: 2,
    canEnd: false
  },
  GREETING: {
    next: ['BUILDING_RAPPORT'],
    maxTurns: 4,
    canEnd: false
  },
  BUILDING_RAPPORT: {
    next: ['FINANCIAL_CONTEXT', 'REQUEST'],
    maxTurns: 6,
    canEnd: false
  },
  FINANCIAL_CONTEXT: {
    next: ['REQUEST', 'EXTRACTION'],
    maxTurns: 8,
    canEnd: false
  },
  REQUEST: {
    next: ['EXTRACTION', 'FINANCIAL_CONTEXT', 'SUSPICIOUS'],
    maxTurns: 6,
    canEnd: false
  },
  EXTRACTION: {
    next: ['CLOSING', 'SUSPICIOUS'],
    maxTurns: 15,
    canEnd: false
  },
  SUSPICIOUS: {
    next: ['EXTRACTION', 'CLOSING', 'ENDED'],
    maxTurns: 5,
    canEnd: true
  },
  CLOSING: {
    next: ['ENDED'],
    maxTurns: 3,
    canEnd: true
  },
  ENDED: {
    next: [],
    maxTurns: 0,
    canEnd: true
  }
};

class StateMachine {
  constructor(config = {}) {
    this.states = STATES;
    this.configs = STATE_CONFIGS;
    this.maxTurns = config.maxTurns || 25;
    this.maxDuration = config.maxDuration || 30 * 60 * 1000; // 30 minutes
  }

  /**
   * Transition to next state based on context
   * @param {string} currentState - Current state
   * @param {Object} context - Transition context
   * @returns {Object} Transition result
   */
  transition(currentState, context) {
    const config = this.configs[currentState];
    
    // Check if already in terminal state
    if (currentState === STATES.ENDED) {
      return {
        current_state: STATES.ENDED,
        next_state: STATES.ENDED,
        reason: 'Already in terminal state',
        confidence: 1.0,
        should_end: true,
        termination_strategy: 'auto_close'
      };
    }

    // Check for forced transitions
    const forcedTransition = this.checkForcedTransitions(currentState, context);
    if (forcedTransition) {
      return forcedTransition;
    }

    // Check turn limits
    if (context.turnCount >= config.maxTurns) {
      return {
        current_state: currentState,
        next_state: STATES.CLOSING,
        reason: `Max turns (${config.maxTurns}) reached`,
        confidence: 0.9,
        should_end: false,
        termination_strategy: 'time_excuse'
      };
    }

    // State-specific transition logic
    switch (currentState) {
      case STATES.INITIAL:
        return this.transitionFromInitial(context);
      
      case STATES.GREETING:
        return this.transitionFromGreeting(context);
      
      case STATES.BUILDING_RAPPORT:
        return this.transitionFromBuildingRapport(context);
      
      case STATES.FINANCIAL_CONTEXT:
        return this.transitionFromFinancialContext(context);
      
      case STATES.REQUEST:
        return this.transitionFromRequest(context);
      
      case STATES.EXTRACTION:
        return this.transitionFromExtraction(context);
      
      case STATES.SUSPICIOUS:
        return this.transitionFromSuspicious(context);
      
      case STATES.CLOSING:
        return this.transitionFromClosing(context);
      
      default:
        return {
          current_state: currentState,
          next_state: currentState,
          reason: 'Unknown state, maintaining',
          confidence: 0.5,
          should_end: false
        };
    }
  }

  transitionFromInitial(context) {
    if (context.scamConfidence >= 0.75) {
      return {
        current_state: STATES.INITIAL,
        next_state: STATES.GREETING,
        reason: 'Scam confirmed (confidence >= 0.75)',
        confidence: 0.95,
        should_end: false
      };
    }
    
    return {
      current_state: STATES.INITIAL,
      next_state: STATES.GREETING,
      reason: 'Proceeding with caution',
      confidence: 0.6,
      should_end: false
    };
  }

  transitionFromGreeting(context) {
    if (context.turnCount >= 3 || context.hasFinancialContext) {
      return {
        current_state: STATES.GREETING,
        next_state: STATES.BUILDING_RAPPORT,
        reason: 'Greeting complete, building rapport',
        confidence: 0.85,
        should_end: false
      };
    }

    return {
      current_state: STATES.GREETING,
      next_state: STATES.GREETING,
      reason: 'Continuing greeting',
      confidence: 0.7,
      should_end: false
    };
  }

  transitionFromBuildingRapport(context) {
    if (context.turnCount >= 5 || context.hasDirectRequest) {
      return {
        current_state: STATES.BUILDING_RAPPORT,
        next_state: STATES.FINANCIAL_CONTEXT,
        reason: 'Rapport established, moving to financial context',
        confidence: 0.8,
        should_end: false
      };
    }

    if (context.hasFinancialContext) {
      return {
        current_state: STATES.BUILDING_RAPPORT,
        next_state: STATES.FINANCIAL_CONTEXT,
        reason: 'Financial context detected',
        confidence: 0.9,
        should_end: false
      };
    }

    return {
      current_state: STATES.BUILDING_RAPPORT,
      next_state: STATES.BUILDING_RAPPORT,
      reason: 'Continuing to build rapport',
      confidence: 0.6,
      should_end: false
    };
  }

  transitionFromFinancialContext(context) {
    if (context.turnCount >= 5 || context.hasDirectRequest) {
      return {
        current_state: STATES.FINANCIAL_CONTEXT,
        next_state: STATES.REQUEST,
        reason: 'Financial context understood, request received',
        confidence: 0.85,
        should_end: false
      };
    }

    return {
      current_state: STATES.FINANCIAL_CONTEXT,
      next_state: STATES.FINANCIAL_CONTEXT,
      reason: 'Clarifying financial details',
      confidence: 0.7,
      should_end: false
    };
  }

  transitionFromRequest(context) {
    if (context.turnCount >= 2) {
      return {
        current_state: STATES.REQUEST,
        next_state: STATES.EXTRACTION,
        reason: 'Request acknowledged, moving to extraction',
        confidence: 0.8,
        should_end: false
      };
    }

    return {
      current_state: STATES.REQUEST,
      next_state: STATES.REQUEST,
      reason: 'Clarifying request details',
      confidence: 0.6,
      should_end: false
    };
  }

  transitionFromExtraction(context) {
    // Only close if we have really good extraction OR very high turn count
    const extractionComplete = context.extractionProgress >= 0.9;
    
    // Much higher threshold before going to CLOSING
    if (extractionComplete && context.turnCount >= 12) {
      return {
        current_state: STATES.EXTRACTION,
        next_state: STATES.CLOSING,
        reason: 'Extraction complete with good data',
        confidence: 0.9,
        should_end: false,
        termination_strategy: 'graceful_closing'
      };
    }

    // Only timeout at very high turn count
    if (context.turnCount >= 15) {
      return {
        current_state: STATES.EXTRACTION,
        next_state: STATES.CLOSING,
        reason: 'Max extraction turns reached',
        confidence: 0.9,
        should_end: false,
        termination_strategy: 'graceful_closing'
      };
    }

    // Check for suspicion indicators
    if (context.consecutiveDelays >= 4) {
      return {
        current_state: STATES.EXTRACTION,
        next_state: STATES.SUSPICIOUS,
        reason: 'Too many delays, scammer may be suspicious',
        confidence: 0.7,
        should_end: false
      };
    }

    // Stay in EXTRACTION to keep engaging
    return {
      current_state: STATES.EXTRACTION,
      next_state: STATES.EXTRACTION,
      reason: 'Continuing extraction - more data needed',
      confidence: 0.7,
      should_end: false
    };
  }

  transitionFromSuspicious(context) {
    if (context.consecutiveDelays >= 3) {
      return {
        current_state: STATES.SUSPICIOUS,
        next_state: STATES.CLOSING,
        reason: 'Recovery failed, exiting gracefully',
        confidence: 0.8,
        should_end: false,
        termination_strategy: 'safe_exit'
      };
    }

    return {
      current_state: STATES.SUSPICIOUS,
      next_state: STATES.EXTRACTION,
      reason: 'Recovering from suspicion',
      confidence: 0.5,
      should_end: false
    };
  }

  transitionFromClosing(context) {
    return {
      current_state: STATES.CLOSING,
      next_state: STATES.ENDED,
      reason: 'Conversation complete',
      confidence: 1.0,
      should_end: true,
      termination_strategy: 'graceful_closing'
    };
  }

  checkForcedTransitions(currentState, context) {
    // Check for early termination conditions
    if (context.scammerTerminated) {
      return {
        current_state: currentState,
        next_state: STATES.ENDED,
        reason: 'Scammer terminated conversation',
        confidence: 1.0,
        should_end: true,
        termination_strategy: 'auto_close'
      };
    }

    return null;
  }

  /**
   * Get available transitions from current state
   * @param {string} state - Current state
   * @returns {string[]} Available next states
   */
  getAvailableTransitions(state) {
    return this.configs[state]?.next || [];
  }

  /**
   * Get state configuration
   * @param {string} state - State name
   * @returns {Object} State configuration
   */
  getStateConfig(state) {
    return this.configs[state] || null;
  }

  /**
   * Get all states
   * @returns {Object} All states
   */
  getAllStates() {
    return { ...this.states };
  }
}

module.exports = { StateMachine, STATES };
