/**
 * Agent Orchestrator - ENHANCED VERSION
 * HCL GUVI Buildathon - Competition Ready
 * 
 * Generates dynamic, contextual responses based on:
 * 1. What the scammer actually says
 * 2. Keywords and intent in the message
 * 3. Conversation history and state
 * 4. Natural human-like engagement
 */

class AgentOrchestrator {
  constructor(config = {}) {
    this.conversationContext = new Map();
    this.lastResponseType = null;
    this.usedResponses = new Set();
  }

  /**
   * Get the default persona configuration
   */
  getDefaultPersona() {
    return {
      name: 'Priya Sharma',
      age: 28,
      occupation: 'Software Engineer',
      location: 'Mumbai, Andheri',
      personality: {
        warmth: 0.75,
        skepticism: 0.55,
        curiosity: 0.85,
        patience: 0.65,
        busyness: 0.70
      }
    };
  }

  /**
   * Get the prompt for a specific state
   */
  getStatePrompt(state, context = {}) {
    return `State: ${state}, ScamType: ${context.scamType || 'unknown'}`;
  }

  /**
   * Main response generation - COMPLETELY DYNAMIC
   */
  async generateResponse(prompt, context) {
    const state = context.state || 'GREETING';
    const lastMessage = (context.lastScammerMessage || '').toLowerCase();
    const turnCount = context.turnCount || 1;
    const conversationHistory = context.conversationHistory || [];
    
    // Analyze the scammer's message for keywords and intent
    const analysis = this.analyzeMessage(lastMessage);
    
    // Generate response based on what the scammer is asking for
    let response = this.generateContextualResponse(analysis, state, turnCount, lastMessage, conversationHistory);
    
    // Ensure we don't repeat the exact same response
    response = this.ensureUnique(response, analysis, state, turnCount, lastMessage);
    
    return response;
  }

  /**
   * Analyze the scammer's message for keywords and intent
   */
  analyzeMessage(message) {
    return {
      // What is the scammer asking for?
      wantsOTP: /otp|one.?time|verification code|code.?(we|you)|receive/i.test(message),
      wantsAccountNumber: /account.?number|account.?no|bank.?account/i.test(message),
      wantsCardDetails: /card.?number|cvv|expiry|debit.?card|credit.?card/i.test(message),
      wantsUPI: /upi|gpay|phonepe|paytm|@ybl|@oksbi|@okaxis/i.test(message),
      wantsPayment: /pay|send|transfer|fee|charge|amount|rs\.?|rupees|\₹/i.test(message),
      wantsLink: /click|link|website|url|verify|update/i.test(message),
      wantsPhone: /call.?(back|me|us)|phone|mobile|contact|whatsapp/i.test(message),
      
      // What urgency tactics are they using?
      hasUrgency: /urgent|immediate|now|minute|second|hour|asap/i.test(message),
      hasThreat: /block|suspend|close|freeze|lock|legal|police|court|arrest/i.test(message),
      hasDeadline: /\d+\s*(minute|second|hour)|today|time.?limit|expires?/i.test(message),
      
      // What authority are they claiming?
      claimsBank: /sbi|hdfc|icici|axis|bank|rbi|reserve/i.test(message),
      claimsGovernment: /government|income.?tax|police|court|cbi|ed/i.test(message),
      
      // What benefits are they promising?
      promisesReward: /won|prize|lottery|reward|cashback|bonus|offer|free/i.test(message),
      promisesRefund: /refund|return|money.?back|compensation/i.test(message),
      
      // Specific mentions
      mentionsKYC: /kyc|know.?your.?customer|verification|update/i.test(message),
      mentionsAadhaar: /aadhaar|aadhar|uid/i.test(message),
      mentionsPAN: /pan.?card|pan.?number/i.test(message),
      
      // Phone numbers mentioned
      hasPhoneNumber: /\+91[\s\-]?\d{10}|\b\d{10}\b/i.test(message),
      extractedPhone: (message.match(/\+91[\s\-]?(\d{10})|(\b\d{10}\b)/i) || [])[0],
      
      // Specific numeric values
      hasAmount: /rs\.?\s*\d+|\₹\s*\d+|\d+\s*rupees/i.test(message),
      hasTime: /\d+\s*(minute|second|hour)/i.test(message)
    };
  }

  /**
   * Generate a contextual response based on message analysis
   */
  generateContextualResponse(analysis, state, turnCount, originalMessage, conversationHistory) {
    // Priority 1: Handle OTP requests (most common scam tactic)
    if (analysis.wantsOTP) {
      return this.respondToOTPRequest(analysis, turnCount, originalMessage);
    }
    
    // Priority 2: Handle payment/money requests
    if (analysis.wantsUPI || analysis.wantsPayment) {
      return this.respondToPaymentRequest(analysis, turnCount, originalMessage);
    }
    
    // Priority 3: Handle account/card requests
    if (analysis.wantsAccountNumber || analysis.wantsCardDetails) {
      return this.respondToAccountRequest(analysis, turnCount);
    }
    
    // Priority 4: Handle urgency and threats
    if (analysis.hasDeadline || (analysis.hasUrgency && analysis.hasThreat)) {
      return this.respondToUrgency(analysis, turnCount, originalMessage);
    }
    
    // Priority 5: Handle link requests
    if (analysis.wantsLink) {
      return this.respondToLinkRequest(analysis, turnCount);
    }
    
    // Priority 6: Handle KYC/verification scams
    if (analysis.mentionsKYC || analysis.mentionsAadhaar || analysis.mentionsPAN) {
      return this.respondToVerificationRequest(analysis, turnCount);
    }
    
    // Priority 7: Handle reward/prize scams
    if (analysis.promisesReward || analysis.promisesRefund) {
      return this.respondToPromises(analysis, turnCount);
    }
    
    // Priority 8: Handle authority claims
    if (analysis.claimsBank || analysis.claimsGovernment) {
      return this.respondToAuthorityClaims(analysis, turnCount);
    }
    
    // Priority 9: Phone number extraction
    if (analysis.hasPhoneNumber) {
      return this.respondToPhoneNumber(analysis, turnCount);
    }
    
    // Default: Generate an engaging response based on state
    return this.generateEngagingResponse(state, turnCount, originalMessage);
  }

  /**
   * Respond to OTP requests - show hesitation but engagement
   */
  respondToOTPRequest(analysis, turnCount, message) {
    // Check if they mentioned a specific phone number to send to
    if (analysis.hasPhoneNumber) {
      const phone = analysis.extractedPhone;
      const responses = [
        `Wait, you want me to send OTP to ${phone}? But the SMS says not to share with anyone!`,
        `Send to ${phone}? But isn't OTP supposed to be confidential? My bank always says never share.`,
        `Hmm I got the OTP but sending to ${phone} feels wrong. Can I speak to your manager first?`,
        `The code came but before I share... why ${phone}? Is that the official bank number?`,
        `I'm hesitating to send to ${phone}. Can you explain why you need MY OTP? This seems odd.`
      ];
      return this.pickRandom(responses);
    }
    
    // General OTP responses
    const earlyResponses = [
      "Wait, OTP? But my bank SMS always says never share OTP with anyone. Is this really official?",
      "I got a code but it clearly says DO NOT SHARE. Why exactly do you need this?",
      "Hmm the OTP came... but can you explain why the BANK needs MY verification code?",
      "I see the OTP message. But something feels off - banks don't usually ask for this right?",
      "Code received. But wait - if this is the real bank, shouldn't you have access already?",
      "The OTP is here but I want to verify first. What's your employee ID and department?",
      "I got it but let me confirm - which branch are you calling from? I want to verify."
    ];
    
    const laterResponses = [
      "Look, I've thought about it and I really can't share OTP. My husband will be very upset.",
      "I asked my brother who works in a bank - he says NEVER share OTP on call. Sorry.",
      "Actually, let me just visit the bank branch tomorrow. It's safer that way.",
      "No sorry, I'm not comfortable. Can you email me officially from the bank domain?",
      "I'll go to the branch directly. Which location should I visit? And what documents to bring?"
    ];
    
    return this.pickRandom(turnCount > 4 ? laterResponses : earlyResponses);
  }

  /**
   * Respond to payment/UPI requests - extract scammer's payment details
   */
  respondToPaymentRequest(analysis, turnCount, message) {
    // If they mentioned specific amount
    if (analysis.hasAmount) {
      const amountMatch = message.match(/rs\.?\s*(\d+(?:,\d+)?)|(\d+(?:,\d+)?)\s*rupees|\₹\s*(\d+(?:,\d+)?)/i);
      const amount = amountMatch ? amountMatch[0] : 'that amount';
      
      const responses = [
        `${amount} is quite a lot for me. But okay, let me check my balance. What's the UPI ID?`,
        `Okay ${amount}. Before I transfer, tell me the exact UPI ID or account number?`,
        `${amount} I can manage. Just confirm - what's the beneficiary name and UPI ID?`,
        `I'll arrange ${amount}. Give me the complete bank details - account number, IFSC, name.`,
        `That's ${amount} right? Okay. Let me get the details - UPI ID and your name for the transfer?`
      ];
      return this.pickRandom(responses);
    }
    
    // Extract UPI/account details
    const responses = [
      "Okay I'll make the payment. What's the exact UPI ID? Please spell it clearly.",
      "I'm opening my PhonePe now. Tell me the UPI ID slowly so I can type it correctly.",
      "Ready to transfer. What's the account number, IFSC code, and beneficiary name?",
      "I'll pay right away. Just need the payment details - UPI or bank account?",
      "My GPay is open. What's the UPI ID? And what name will appear when I search?",
      "Alright, let me send. Give me the exact details - I don't want to send to wrong account!",
      "Payment karna hai toh details chahiye na? UPI ID ya bank account kya hai?"
    ];
    
    return this.pickRandom(responses);
  }

  /**
   * Respond to account/card requests - extract scammer's details
   */
  respondToAccountRequest(analysis, turnCount) {
    const responses = [
      "I can share my account number. But first, what's your name and employee ID for my records?",
      "Okay, but before I give bank details - tell me your full name and which department?",
      "I'll share, but I want to note down who I'm talking to. Your name and designation?",
      "Account number... let me find my passbook. Meanwhile, what's your official phone number?",
      "I have multiple bank accounts. Which bank is this regarding? And your employee code?",
      "Okay wait, I'm getting my diary to note your details first. Name and office location?",
      "I'll tell you but I always keep records. What's your name, employee ID, and branch?"
    ];
    
    return this.pickRandom(responses);
  }

  /**
   * Respond to urgency/threats - show concern but extract info
   */
  respondToUrgency(analysis, turnCount, originalMessage) {
    // Check for specific time mentions
    const timeMatch = originalMessage.match(/(\d+)\s*(minute|second|hour)/i);
    
    if (timeMatch) {
      const time = timeMatch[0];
      const responses = [
        `${time}? That's very less time! But I can't do this properly in a rush. What's your direct number?`,
        `Only ${time}?! Okay okay, I'm panicking now. But wait - give me a callback number first.`,
        `${time} is too fast! I need to think. What's your supervisor's number? I want to speak to them.`,
        `Arrey ${time} mein kaise! At least tell me your name and branch so I can verify quickly?`,
        `${time}?? I can't think clearly with this pressure. What's the helpdesk number I can call?`
      ];
      return this.pickRandom(responses);
    }
    
    const responses = [
      "Oh god, you're scaring me! But I can't make decisions in panic. Explain calmly please?",
      "Why so urgent?? If this is official, there should be some proper process right?",
      "Wait wait, I'm getting nervous. Let me call back on the official bank number to verify.",
      "This seems too rushed. Can you give me a reference number so I can check with the bank?",
      "I understand it's urgent but I need to verify. What's your employee ID and branch?",
      "Okay I'm worried now. But even in emergency I should be careful. Your full name and designation?",
      "So stressful! Before I do anything wrong, let me confirm - which bank and which branch are you from?"
    ];
    
    return this.pickRandom(responses);
  }

  /**
   * Respond to link requests
   */
  respondToLinkRequest(analysis, turnCount) {
    const responses = [
      "Can you send the link properly? I'll open it on my laptop - phone browser is slow.",
      "Share the website address please. I want to make sure it's the official site.",
      "Send me the link again. What's the exact URL? I want to verify it's genuine.",
      "My phone internet is not working well. Tell me the website name and I'll search it.",
      "Okay share the link. But tell me - what should I look for to confirm it's real?",
      "I'll check the link. But first, what's the official website supposed to look like?"
    ];
    
    return this.pickRandom(responses);
  }

  /**
   * Respond to KYC/verification requests
   */
  respondToVerificationRequest(analysis, turnCount) {
    const responses = [
      "KYC pending? But I definitely submitted all documents. When was this issue raised?",
      "I thought my verification was complete. Can you tell me what exactly is missing?",
      "Which document is the problem? I have Aadhaar, PAN, everything properly linked.",
      "Verification issue? Can I come to the branch to sort this out? Which location?",
      "I don't remember any pending KYC. Can you send an official SMS or email about this?",
      "My Aadhaar and PAN are linked since 2020. What's the specific problem you're seeing?",
      "If there's KYC issue, I'll visit the branch. What's the address and what documents to bring?"
    ];
    
    return this.pickRandom(responses);
  }

  /**
   * Respond to reward/prize promises
   */
  respondToPromises(analysis, turnCount) {
    const responses = [
      "Really?? I won something? But I don't remember participating. Which contest was this?",
      "Prize for me?! That's amazing but sounds too good. What's the company name and how do I verify?",
      "Wait wait, I never enter contests. How was I selected? Can you explain the process?",
      "Haha, this sounds like those scam messages! But okay, tell me - how do I claim this prize?",
      "I'm suspicious but also curious. If I really won, send me an official email with proof!",
      "Okay assuming this is real - what are the next steps? And what's your organization name?",
      "A lottery I didn't enter? That's odd. But okay, what documents do you need from me?"
    ];
    
    return this.pickRandom(responses);
  }

  /**
   * Respond to authority claims
   */
  respondToAuthorityClaims(analysis, turnCount) {
    const responses = [
      "You're from the bank? Which branch? I usually deal with Andheri West branch.",
      "Okay sir, but can I get your employee ID? I want to verify before proceeding.",
      "Which department exactly? And what's your designation? I like to keep records.",
      "I believe you, but can I call the main helpline to confirm this call is genuine?",
      "Before we continue, give me your name and a reference number for this conversation.",
      "What's your direct landline number? I'll call back to make sure this is legitimate.",
      "If you're really from the bank, you can access my details right? What's my registered address?"
    ];
    
    return this.pickRandom(responses);
  }

  /**
   * Respond when phone number is mentioned
   */
  respondToPhoneNumber(analysis, turnCount) {
    const phone = analysis.extractedPhone;
    const responses = [
      `Is ${phone} your direct number? I'll save it and call you back to verify.`,
      `Okay I noted ${phone}. Is this the official helpline or your personal number?`,
      `${phone} - got it. But before I call, what's your name and department again?`,
      `Let me save ${phone}. Can I reach you on WhatsApp also? Easier to share documents.`,
      `I'll try calling ${phone} from my husband's phone to verify. What's your name?`
    ];
    
    return this.pickRandom(responses);
  }

  /**
   * Generate engaging response for general messages
   */
  generateEngagingResponse(state, turnCount, message) {
    const responses = {
      'INITIAL': [
        "Hello? Who is this? I don't have this number saved.",
        "Hi, sorry - who's calling? I didn't catch the name.",
        "Yes hello? How did you get my number?",
        "Hey, this number isn't saved. Who am I speaking with?"
      ],
      'GREETING': [
        "Oh I see. Tell me more - what exactly is this about?",
        "Okay okay, I'm listening. Please explain the full situation.",
        "Right, continue please. What should I know?",
        "Interesting! Go on, I want to understand properly."
      ],
      'BUILDING_RAPPORT': [
        "That's helpful to know. So how long have you been working there?",
        "I see. And where exactly is your office located?",
        "Understood. Tell me about yourself - which department are you from?",
        "Okay, and if I need to visit, which address should I come to?"
      ],
      'FINANCIAL_CONTEXT': [
        "Alright, I'm following. So what's the next step I should take?",
        "Okay, now walk me through the exact process please.",
        "Got it. So tell me clearly - what action do I need to take?",
        "Understood so far. What documents or details do you need from me?"
      ],
      'REQUEST': [
        "I want to help but need to understand fully first. Can you clarify?",
        "Before I do anything, explain all the details one more time.",
        "Okay I'm ready. What exactly do you need from me to proceed?",
        "I'll do it, but first answer my questions - what's your full name and employee ID?"
      ],
      'EXTRACTION': [
        "Let me note everything down. Your name, department, and contact number please?",
        "I'll do it. But first give me all official details for my records.",
        "Okay proceeding. Tell me the exact payment/account details one more time?",
        "Ready to help. What's your name, designation, and which location are you calling from?"
      ],
      'SUSPICIOUS': [
        "Sorry I got distracted by work. What were you saying about?",
        "Oops, my internet lagged! Can you repeat the important part?",
        "Wait, I missed that. Too many notifications. What should I do again?",
        "One second, someone was at the door. Okay I'm back - continue please."
      ],
      'CLOSING': [
        "Let me think about this. Can I call you back at this number in an hour?",
        "I need to discuss with my husband first. Will you be available later?",
        "Give me some time to verify. What's your direct number for callback?",
        "I'll definitely follow up. Send me your contact details on WhatsApp?"
      ]
    };
    
    const stateResponses = responses[state] || responses['GREETING'];
    return this.pickRandom(stateResponses);
  }

  /**
   * Pick a random item from array
   */
  pickRandom(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  /**
   * Ensure we don't repeat the exact same response
   */
  ensureUnique(response, analysis, state, turnCount, message) {
    // If we've used this exact response before, modify it
    if (this.usedResponses.has(response)) {
      // Try to get a different response
      const alternateResponse = this.generateAlternateResponse(analysis, state, turnCount, message);
      if (alternateResponse && !this.usedResponses.has(alternateResponse)) {
        this.usedResponses.add(alternateResponse);
        return alternateResponse;
      }
      // If still duplicate, add variation
      response = this.addVariation(response);
    }
    
    this.usedResponses.add(response);
    
    // Clear old responses to prevent memory buildup (keep last 20)
    if (this.usedResponses.size > 20) {
      const arr = Array.from(this.usedResponses);
      this.usedResponses = new Set(arr.slice(-15));
    }
    
    return response;
  }

  /**
   * Generate an alternate response
   */
  generateAlternateResponse(analysis, state, turnCount, message) {
    // Generic alternates that work in most situations
    const alternates = [
      "Sorry, can you explain that again? I want to make sure I understand correctly.",
      "Hmm okay. But before we continue, what's your full name and employee ID?",
      "I'm a bit confused. Can you walk me through this step by step?",
      "Okay, one moment. Let me just verify - which organization are you from exactly?",
      "Right right. But tell me clearly - what exactly do I need to do?",
      "I want to proceed but carefully. What's the official helpline number I can call?",
      "Understood. But first, can you share your official email ID for my records?"
    ];
    
    return this.pickRandom(alternates);
  }

  /**
   * Add variation to prevent exact duplicates
   */
  addVariation(response) {
    const prefixes = [
      "Actually, ",
      "Wait, ",
      "One thing - ",
      "Hmm, ",
      "See, ",
      "Listen, ",
      "Before that, "
    ];
    
    const suffixes = [
      " Please clarify.",
      " I need to understand.",
      " Tell me clearly.",
      " Just checking.",
      " Help me understand.",
      " One more time please."
    ];
    
    // Add prefix or suffix randomly
    if (Math.random() > 0.5) {
      const prefix = this.pickRandom(prefixes);
      return prefix + response.charAt(0).toLowerCase() + response.slice(1);
    } else {
      const suffix = this.pickRandom(suffixes);
      return response.replace(/[.!?]$/, '') + '.' + suffix;
    }
  }

  /**
   * Get responses for a specific state (for backwards compatibility)
   */
  getResponsesForState(state) {
    return [this.generateEngagingResponse(state, 1, '')];
  }

  /**
   * Get a fallback response
   */
  getFallbackResponse(state, consecutiveFallbacks) {
    const fallbacks = [
      "Sorry, I got distracted. Work email just came. What were you saying?",
      "Oops, my phone lagged! Can you repeat the important part?",
      "One second, someone at the door. Okay I'm back - continue please.",
      "Sorry sorry, network issue. Please say that again?"
    ];
    
    if (consecutiveFallbacks >= 3) {
      return "Look, I really need to go now. Can you WhatsApp me the details? I'll check later.";
    }
    
    return fallbacks[consecutiveFallbacks % fallbacks.length];
  }
}

module.exports = { AgentOrchestrator };
