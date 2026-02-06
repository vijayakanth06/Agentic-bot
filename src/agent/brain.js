/**
 * INTELLIGENT CONVERSATION BRAIN
 * HCL GUVI Buildathon - Competition Winning Module
 * 
 * This is the "advanced brain" that differentiates REAL vs SCAM,
 * handles ANY conversation, and responds like a genuine human.
 * 
 * Key Capabilities:
 * 1. Real-time scam vs legitimate classification
 * 2. Natural human personality with quirks
 * 3. Memory and context awareness
 * 4. Emotional intelligence
 * 5. Handles unexpected/out-of-blue messages
 * 6. LANGUAGE MATCHING - responds in same language as scammer
 */

class ConversationBrain {
  constructor() {
    this.persona = this.createRichPersona();
    this.conversationMemory = new Map();
    this.emotionalState = 'neutral';
    this.trustLevel = 0.5;
    this.detectedLanguage = 'english'; // Track language: 'english', 'hindi', 'hinglish'
  }

  /**
   * DETECT LANGUAGE of the message
   * Returns: 'english', 'hindi', or 'hinglish'
   */
  detectLanguage(message) {
    // ONLY pure Hindi/Hinglish words - NOT common English words used in India
    const pureHindiWords = /\b(kya|hai|kaise|ho|aap|mein|hum|yeh|woh|karo|karna|karenge|bolo|batao|abhi|jaldi|paise|paisa|bhejo|dedo|lo|lena|dena|nahi|haan|ji|sahab|beta|bhai|didi|bahen|rupaye|lakh|crore|tum|tumhara|mera|apka|unka|iska|uska|accha|theek|sahi|galat|khata|samjho|samjhao|suniye|dekhiye|turant|foran|tab|phir|baad|pehle|aage|piche|upar|niche|andar|bahar|yahan|wahan|kyun|kab|kahan|kaun|kitna|kaise|hoga|hogi|raha|rahi|karunga|karungi|jayega|jayegi|milega|milegi|bata|de|le|kar|bol|sun|dekh|ruk|chal|aa|ja|mat|na|toh|par|lekin|aur|bhi|sirf|bas|abhi|kal|aaj|subah|shaam|raat|din)\b/gi;
    const hindiMatches = (message.match(pureHindiWords) || []).length;
    
    // Check for Devanagari script - definite Hindi
    const hasDevanagari = /[\u0900-\u097F]/.test(message);
    
    // Calculate word count for ratio
    const wordCount = message.split(/\s+/).length;
    const hindiRatio = hindiMatches / wordCount;
    
    if (hasDevanagari) {
      return 'hindi';
    } else if (hindiRatio > 0.3 || hindiMatches >= 4) {
      return 'hindi';
    } else if (hindiMatches >= 2 || (hindiMatches >= 1 && hindiRatio > 0.1)) {
      return 'hinglish';
    }
    return 'english';
  }

  /**
   * Create a rich, believable persona with backstory
   */
  createRichPersona() {
    return {
      name: 'Priya',
      fullName: 'Priya Sharma',
      age: 28,
      occupation: 'Software Engineer at TCS',
      location: 'Mumbai, Andheri West',
      
      // Personal details (for authenticity)
      husband: 'Rahul',
      familySize: 'joint family with in-laws',
      pet: 'no pets, but wants a dog',
      
      // Daily life context
      workTiming: '9 AM to 6 PM',
      commute: 'WFH mostly, sometimes goes to office in BKC',
      hobbies: ['watching Netflix', 'cooking', 'yoga'],
      recentEvents: ['attended cousin wedding last month', 'planning vacation to Goa'],
      
      // Banking details (believable fake)
      banks: ['HDFC savings account', 'SBI salary account', 'ICICI credit card'],
      preferredUPI: 'PhonePe and GPay',
      
      // Personality traits
      traits: {
        cautious: 0.7,
        friendly: 0.8,
        talkative: 0.65,
        curious: 0.9,
        trusting: 0.4,
        impatient: 0.3
      }
    };
  }

  /**
   * CORE FUNCTION: Determine if message is SCAM or LEGITIMATE
   * Returns: { isScam: boolean, confidence: number, type: string, reasoning: string }
   */
  classifyMessage(message, conversationHistory = [], detectionResult = {}) {
    // First detect and store language
    this.detectedLanguage = this.detectLanguage(message);
    
    const lowerMsg = message.toLowerCase();
    
    // Strong scam indicators (high confidence scam)
    const strongScamIndicators = [
      { pattern: /otp|one.?time.?password|verification code/i, weight: 0.9, type: 'otp_fraud' },
      { pattern: /won|lottery|prize|jackpot|lucky winner/i, weight: 0.85, type: 'lottery_scam' },
      { pattern: /kyc.*(expired?|pending|update|block)/i, weight: 0.9, type: 'kyc_scam' },
      { pattern: /account.*(block|suspend|freeze|close)/i, weight: 0.85, type: 'threat_scam' },
      { pattern: /send.*(money|payment|rs|rupees|fee)/i, weight: 0.8, type: 'advance_fee' },
      { pattern: /transfer.*urgent|urgent.*transfer/i, weight: 0.85, type: 'urgency_scam' },
      { pattern: /(cvv|card number|expiry date|pin)/i, weight: 0.9, type: 'card_fraud' },
      { pattern: /processing fee|activation fee|clearance/i, weight: 0.85, type: 'advance_fee' },
      { pattern: /income tax.*refund|refund.*income tax/i, weight: 0.8, type: 'tax_scam' },
      { pattern: /arrest warrant|legal action|court case/i, weight: 0.85, type: 'legal_threat' },
      { pattern: /crypto|bitcoin|investment.*guarantee/i, weight: 0.8, type: 'investment_scam' },
      { pattern: /work from home.*earn|earn.*daily.*rs/i, weight: 0.75, type: 'job_scam' }
    ];

    // Legitimate conversation indicators
    const legitimateIndicators = [
      { pattern: /^(hi|hello|hey|good morning|good evening)[\s!?.]*$/i, weight: 0.7 },
      { pattern: /^how are you|what's up|kaise ho/i, weight: 0.6 },
      { pattern: /thanks|thank you|dhanyavaad/i, weight: 0.5 },
      { pattern: /^(ok|okay|alright|sure|yes|no|haan|nahi)[\s!?.]*$/i, weight: 0.6 },
      { pattern: /how.*(help|assist)|can i help/i, weight: 0.4 },
      { pattern: /^bye|goodbye|talk later|see you/i, weight: 0.7 },
      // Casual topics - NOT scam related
      { pattern: /weather|rain|sunny|hot|cold|monsoon|humid/i, weight: 0.6 },
      { pattern: /cricket|match|ipl|kohli|rohit|dhoni|india.*(vs|match)/i, weight: 0.6 },
      { pattern: /food|biryani|pizza|lunch|dinner|breakfast|eat|restaurant/i, weight: 0.6 },
      { pattern: /movie|film|bollywood|netflix|watch/i, weight: 0.5 },
      { pattern: /family|husband|wife|kids|children|parents/i, weight: 0.5 },
      { pattern: /weekend|vacation|holiday|travel|trip/i, weight: 0.5 },
      { pattern: /genuine.*(inquiry|question)|real.*customer/i, weight: 0.6 },
      // Polite small talk
      { pattern: /nice to (meet|talk)|pleasure/i, weight: 0.5 },
      { pattern: /take care|have a (good|nice) day/i, weight: 0.6 }
    ];

    // Neutral/ambiguous indicators (need more context)
    const ambiguousIndicators = [
      { pattern: /bank|account|transaction/i, weight: 0 }, // Could be either
      { pattern: /call.*regarding|calling about/i, weight: 0 },
      { pattern: /update|verify|confirm/i, weight: 0 }
    ];

    let scamScore = 0;
    let legitScore = 0;
    let detectedType = 'unknown';
    let matchedPatterns = [];

    // Check scam indicators
    for (const indicator of strongScamIndicators) {
      if (indicator.pattern.test(lowerMsg)) {
        scamScore += indicator.weight;
        detectedType = indicator.type;
        matchedPatterns.push(indicator.type);
      }
    }

    // Check legitimate indicators
    for (const indicator of legitimateIndicators) {
      if (indicator.pattern.test(lowerMsg)) {
        legitScore += indicator.weight;
      }
    }

    // Use detection result if available
    if (detectionResult.is_scam && detectionResult.confidence > 0.6) {
      scamScore += detectionResult.confidence * 0.5;
    }

    // Analyze conversation history for escalation pattern (scammers escalate quickly)
    if (conversationHistory.length >= 2) {
      const recentMessages = conversationHistory.slice(-5);
      let financialMentions = 0;
      let urgencyMentions = 0;
      
      for (const msg of recentMessages) {
        const text = (msg.text || '').toLowerCase();
        if (/money|payment|transfer|upi|bank|fee|charge/i.test(text)) financialMentions++;
        if (/urgent|immediate|now|hurry|quick/i.test(text)) urgencyMentions++;
      }
      
      // Rapid escalation is a strong scam indicator
      if (financialMentions >= 2 && conversationHistory.length <= 5) {
        scamScore += 0.3;
      }
      if (urgencyMentions >= 2) {
        scamScore += 0.2;
      }
    }

    // Normalize scores
    const totalScore = scamScore + legitScore;
    const scamConfidence = totalScore > 0 ? scamScore / Math.max(totalScore, 1) : 0.5;
    
    // Classification decision
    let isScam = false;
    let reasoning = '';

    if (scamScore >= 0.7) {
      isScam = true;
      reasoning = `High scam indicators detected: ${matchedPatterns.join(', ')}`;
    } else if (scamScore >= 0.4 && legitScore < 0.3) {
      isScam = true;
      reasoning = `Moderate scam indicators with low legitimate signals`;
    } else if (legitScore >= 0.5 && scamScore < 0.3) {
      isScam = false;
      reasoning = `Appears to be legitimate conversation`;
    } else {
      // Ambiguous - lean towards caution (treat as potential scam but respond normally)
      isScam = scamScore > legitScore;
      reasoning = `Ambiguous - monitoring closely`;
    }

    return {
      isScam,
      confidence: Math.min(scamConfidence, 1.0),
      type: detectedType,
      reasoning,
      scamScore,
      legitScore,
      matchedPatterns
    };
  }

  /**
   * Analyze emotional content and intent of message
   */
  analyzeEmotionalContext(message) {
    const lowerMsg = message.toLowerCase();
    
    return {
      // Sender's apparent emotion
      senderTone: this.detectSenderTone(lowerMsg),
      
      // Manipulation tactics
      usesUrgency: /urgent|immediate|now|quick|fast|hurry|asap/i.test(lowerMsg),
      usesFear: /block|suspend|arrest|legal|police|court|freeze|close/i.test(lowerMsg),
      usesGreed: /won|prize|lottery|reward|free|bonus|cashback|crore|lakh/i.test(lowerMsg),
      usesAuthority: /officer|manager|department|government|rbi|bank official/i.test(lowerMsg),
      usesRapport: /dear|valued|respected|sir|madam|friend/i.test(lowerMsg),
      
      // Question types
      isQuestion: /\?|kya|kaun|kaise|kab|kyun|where|what|when|why|how|who/i.test(lowerMsg),
      isGreeting: /^(hi|hello|hey|namaste|good\s*(morning|afternoon|evening))[\s!?,.]*/i.test(lowerMsg),
      isGoodbye: /bye|goodbye|talk later|see you|alvida|phir milenge/i.test(lowerMsg),
      
      // Pressure level (0-1)
      pressureLevel: this.calculatePressureLevel(lowerMsg)
    };
  }

  detectSenderTone(message) {
    if (/please|kindly|request|help|sorry/i.test(message)) return 'polite';
    if (/urgent|important|critical|serious/i.test(message)) return 'urgent';
    if (/angry|upset|disappointed|complaint/i.test(message)) return 'upset';
    if (/!{2,}|URGENT|WARNING|ALERT/i.test(message)) return 'aggressive';
    if (/thank|grateful|appreciate/i.test(message)) return 'grateful';
    return 'neutral';
  }

  calculatePressureLevel(message) {
    let pressure = 0;
    
    if (/urgent|immediate/i.test(message)) pressure += 0.2;
    if (/\d+\s*(minute|hour|second)/i.test(message)) pressure += 0.3;
    if (/block|suspend|freeze/i.test(message)) pressure += 0.25;
    if (/!{2,}/i.test(message)) pressure += 0.1;
    if (/last chance|final warning/i.test(message)) pressure += 0.2;
    if (/must|have to|need to.*now/i.test(message)) pressure += 0.15;
    
    return Math.min(pressure, 1.0);
  }

  /**
   * Update brain's emotional state based on conversation
   */
  updateEmotionalState(classification, emotionalContext) {
    if (classification.isScam && classification.confidence > 0.7) {
      // Getting suspicious
      if (emotionalContext.usesFear) {
        this.emotionalState = 'worried';
      } else if (emotionalContext.usesUrgency) {
        this.emotionalState = 'confused';
      } else {
        this.emotionalState = 'suspicious';
      }
      this.trustLevel = Math.max(0, this.trustLevel - 0.1);
    } else if (!classification.isScam) {
      // Normal conversation
      if (emotionalContext.isGreeting) {
        this.emotionalState = 'happy';
        this.trustLevel = Math.min(1, this.trustLevel + 0.05);
      } else {
        this.emotionalState = 'neutral';
      }
    }
  }

  /**
   * Generate a NATURAL, HUMAN-LIKE response
   * This is the core intelligence - responds appropriately to ANY message
   */
  generateHumanResponse(message, classification, emotionalContext, turnCount, sessionMemory = {}) {
    const { isScam, type, confidence, legitScore, scamScore } = classification;
    
    // Store context for this turn
    this.storeMemory(message, sessionMemory);
    
    // Handle special cases first
    if (emotionalContext.isGreeting && turnCount <= 1) {
      return this.respondToGreeting(message, isScam);
    }
    
    if (emotionalContext.isGoodbye) {
      return this.respondToGoodbye(message, isScam);
    }
    
    // If clearly NOT a scam (high legit score or very low scam score), respond naturally
    if (!isScam || (legitScore > 0.4 && scamScore < 0.3)) {
      return this.respondToLegitimateMessage(message, emotionalContext, turnCount);
    }
    
    // If SCAM detected with reasonable confidence, engage strategically
    if (isScam && confidence > 0.4) {
      return this.respondToScamMessage(message, type, emotionalContext, turnCount, sessionMemory);
    }
    
    // Ambiguous (low confidence either way) - respond cautiously but naturally
    return this.respondToAmbiguousMessage(message, emotionalContext, turnCount);
  }

  /**
   * Respond to greeting messages - LANGUAGE AWARE
   */
  respondToGreeting(message, isPotentialScam) {
    const isEnglish = this.detectedLanguage === 'english';
    
    const greetings = isEnglish ? [
      "Hello! Who's this? I don't have this number saved.",
      "Hi! Yes, who am I speaking with?",
      "Hello? Sorry, didn't catch your name. Who's calling?",
      "Hey! Yes tell me, who is this?",
      "Hi, this number's not saved. May I know who's calling?"
    ] : [
      "Hello! Kaun hai? Yeh number saved nahi hai mere paas.",
      "Hi hi! Haan, aap kaun bol rahe ho?",
      "Hello? Sorry, naam nahi suna. Kaun bol raha hai?",
      "Hey! Haan batao, kaun hai?",
      "Hello ji! Haan bolo, kaun hai?"
    ];
    
    return this.addPersonalityFlair(this.pickRandom(greetings));
  }

  /**
   * Respond to goodbye messages - LANGUAGE AWARE
   */
  respondToGoodbye(message, wasScam) {
    const isEnglish = this.detectedLanguage === 'english';
    
    if (wasScam) {
      // Try to extract one last piece of info
      const responses = isEnglish ? [
        "Wait, before you go - can you share your WhatsApp number? I'll message you.",
        "Okay but send me your contact details please. I want to follow up.",
        "Alright, but what's your email? I'll confirm everything in writing.",
        "Sure, but let me save your number. What was your name again?"
      ] : [
        "Ruko, jaane se pehle - WhatsApp number de do? Message karti hun.",
        "Okay par contact details bhej do na. Follow up karna hai mujhe.",
        "Theek hai, par email kya hai? Writing mein confirm karna hai mujhe.",
        "Theek hai, par number save karne do. Naam kya tha aapka?"
      ];
      return this.pickRandom(responses);
    } else {
      const responses = isEnglish ? [
        "Okay, bye bye! Take care!",
        "Alright, talk later. Bye!",
        "Sure, no problem. Bye!",
        "Okay bye! Nice talking to you."
      ] : [
        "Okay, bye bye! Dhyan rakhna!",
        "Theek hai, baad mein baat karte hain. Bye!",
        "Haan haan, koi baat nahi. Bye!",
        "Bye bye! Achha laga baat karke."
      ];
      return this.pickRandom(responses);
    }
  }

  /**
   * Respond to clearly legitimate messages - LANGUAGE AWARE
   */
  respondToLegitimateMessage(message, emotionalContext, turnCount) {
    const lowerMsg = message.toLowerCase();
    const isEnglish = this.detectedLanguage === 'english';
    
    // Handle common legitimate conversations
    if (/how are you|kaise ho|how's it going/i.test(lowerMsg)) {
      const responses = isEnglish ? [
        "I'm good, thanks for asking! Just busy with work. How about you?",
        "Doing well! A bit tired from work but managing. What about you?",
        "All good here! Planning for the weekend. And you?",
        "Pretty good, life is going on! How are you doing?"
      ] : [
        "Theek hun, thanks for asking! Bas kaam mein busy. Aap batao?",
        "Achhi hun! Thoda thaki hui but manage kar rahi. Aap sunao?",
        "Sab badhiya! Weekend ki planning chal rahi hai. Aur aap?",
        "Theek hai, life chal rahi hai! Aap kaise ho?"
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
    
    if (/thank|thanks|dhanyavaad/i.test(lowerMsg)) {
      const responses = isEnglish ? [
        "You're welcome! Happy to help.",
        "No problem at all!",
        "Anytime! Let me know if you need anything else.",
        "Most welcome! Take care."
      ] : [
        "Arey koi baat nahi! Khushi hui help karke.",
        "Koi problem nahi!",
        "Kabhi bhi! Bolo agar aur kuch chahiye.",
        "Welcome welcome! Dhyan rakhna."
      ];
      return this.pickRandom(responses);
    }
    
    if (/sorry|apologize|maafi/i.test(lowerMsg)) {
      const responses = isEnglish ? [
        "No worries at all! It's okay.",
        "It's absolutely fine! Don't worry about it.",
        "It's totally fine, no need to apologize!",
        "All good, don't stress about it!"
      ] : [
        "Arey koi baat nahi! Hota hai.",
        "Bilkul theek hai! Tension mat lo.",
        "Koi problem nahi, sorry bolne ki zaroorat nahi!",
        "Sab theek hai, stress mat lo!"
      ];
      return this.pickRandom(responses);
    }
    
    // Weather talk
    if (/weather|rain|hot|cold|sunny|monsoon/i.test(lowerMsg)) {
      const responses = isEnglish ? [
        "Yes, the weather is crazy these days! But tell me, what's up?",
        "I know right! The weather is so unpredictable. Anyway, what can I do for you?",
        "Yes! I stepped out today and it was so humid. But anyway, you were saying?"
      ] : [
        "Haan yaar, weather pagal hai aajkal! Par batao, kya hua?",
        "Haan na! Weather kitna unpredictable hai. Anyway, kya help kar sakti hun?",
        "Haan! Aaj bahar gayi toh itni humidity thi. Par batao, kya keh rahe the?"
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
    
    // Cricket/Sports
    if (/cricket|match|india|ipl|worldcup|kohli|rohit/i.test(lowerMsg)) {
      const responses = isEnglish ? [
        "Oh don't get me started on cricket! My husband watches every match. But anyway, what were you calling about?",
        "Haha yes! Did you see that catch? Amazing! But wait, what did you need from me?",
        "Cricket! My whole family was glued to the TV. But tell me, what's the purpose of your call?"
      ] : [
        "Arrey cricket pe mat chalo! Mere husband har match dekhte hain. Par batao, call kyun kiya?",
        "Haha haan! Woh catch dekha? Kamaal tha! Par ruko, aapko kya chahiye tha mujhse?",
        "Cricket! Poora ghar TV ke saamne chipka tha. Par batao, call ka purpose kya hai?"
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
    
    // Food
    if (/food|eat|lunch|dinner|breakfast|biryani|pizza|chai/i.test(lowerMsg)) {
      const responses = isEnglish ? [
        "Oh nice! I'm actually getting hungry now haha. But anyway, what were we discussing?",
        "Oh don't talk about food, I'm on a diet! But tell me, what did you call for?",
        "Mmm that sounds delicious! I just had tea. Anyway, how can I help you?"
      ] : [
        "Oh nice! Mujhe bhi bhook lag rahi hai haha. Par batao, kya discuss kar rahe the?",
        "Yaar food ki baat mat karo, diet pe hun! Par batao, call kyun kiya?",
        "Mmm yummy! Abhi chai pi maine. Anyway, kya help kar sakti hun?"
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
    
    // Family
    if (/family|husband|wife|kids|children|parents|mother|father/i.test(lowerMsg)) {
      const responses = isEnglish ? [
        "Family is everything! My husband always says the same. But tell me, what's the matter?",
        "So nice! Family time is the best. Anyway, what can I do for you?",
        "Yes, family first always! But coming back to the topic, what were you saying?"
      ] : [
        "Family hi sab kuch hai na! Mere husband bhi yehi bolte hain. Par batao, kya baat hai?",
        "Kitna accha! Family time best hota hai. Anyway, kya kar sakti hun aapke liye?",
        "Haan, family first hamesha! Par topic pe aate hain, kya keh rahe the?"
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
    
    // General friendly response
    const responses = isEnglish ? [
      "Hmm interesting! Tell me more about that?",
      "Oh I see. And then what happened?",
      "Okay, I'm listening. Go on...",
      "That's nice! What else?",
      "Okay, understood. Anything else?",
      "Haha nice! But anyway, what brings you to call me today?"
    ] : [
      "Hmm interesting! Aur batao iske baare mein?",
      "Achha achha. Phir kya hua?",
      "Okay, sun rahi hun. Aage batao...",
      "Achha hai! Aur kya?",
      "Theek hai, samajh gayi. Aur kuch?",
      "Haha nice! Par anyway, aaj call kyun kiya?"
    ];
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  /**
   * Respond to scam messages - CORE HONEYPOT LOGIC
   */
  respondToScamMessage(message, scamType, emotionalContext, turnCount, sessionMemory) {
    const lowerMsg = message.toLowerCase();
    
    // Different strategies based on scam type
    switch(scamType) {
      case 'otp_fraud':
        return this.handleOTPScam(message, emotionalContext, turnCount);
      
      case 'kyc_scam':
        return this.handleKYCScam(message, emotionalContext, turnCount);
      
      case 'lottery_scam':
      case 'advance_fee':
        return this.handlePrizeScam(message, emotionalContext, turnCount);
      
      case 'threat_scam':
      case 'legal_threat':
        return this.handleThreatScam(message, emotionalContext, turnCount);
      
      case 'card_fraud':
        return this.handleCardScam(message, emotionalContext, turnCount);
      
      case 'investment_scam':
        return this.handleInvestmentScam(message, emotionalContext, turnCount);
      
      case 'job_scam':
        return this.handleJobScam(message, emotionalContext, turnCount);
      
      default:
        return this.handleGenericScam(message, emotionalContext, turnCount);
    }
  }

  // Specific scam type handlers - ALL NOW LANGUAGE AWARE
  handleOTPScam(message, emotionalContext, turnCount) {
    const phoneMatch = message.match(/\+91[\s-]?(\d{10})|(\d{10})/);
    const phone = phoneMatch ? phoneMatch[0] : null;
    const isEnglish = this.detectedLanguage === 'english';
    
    if (turnCount <= 2) {
      let responses;
      if (phone) {
        responses = isEnglish ? [
          `Send OTP to ${phone}? But the SMS says never share it with anyone. Are you really from the bank?`,
          `Wait, send to ${phone}? But my bank says OTP is confidential. Why exactly do you need it?`,
          `${phone}? I got the OTP but it clearly says never share. Can you explain why you need it?`,
          `To ${phone}... but this feels off. OTP is supposed to be secret right? My husband always says never share.`
        ] : [
          `OTP ${phone} pe bhejun? But SMS mein likha hai share mat karo... Aap sach mein bank se ho?`,
          `Wait, ${phone} pe send karu? Par mera bank says OTP confidential hai. Kyun chahiye aapko?`,
          `${phone}? Hmm, OTP aaya but it says never share. Aap samjhao kyun chahiye?`,
          `${phone} pe... par kuch gadbad lag rahi hai. OTP secret hota hai na?`
        ];
      } else {
        responses = isEnglish ? [
          "OTP? But my bank always says never share OTP with anyone on call. Is this really official?",
          "Wait, you need the OTP? But the message says it's confidential. Why do you need it?",
          "I got the OTP but... banks don't usually ask for this over the phone right? I'm confused.",
          "OTP came but before I share - which bank and which branch are you calling from exactly?"
        ] : [
          "OTP? Par mera bank hamesha bolta hai ki OTP kabhi share mat karo. Yeh official hai?",
          "Ruko ruko, OTP share karna hai? But SMS mein likha hai confidential. Kyun chahiye?",
          "OTP aaya but... banks usually phone pe nahi maangti na? Confuse ho gayi mein.",
          "OTP aaya par pehle batao - kaun sa bank aur kaun si branch se bol rahe ho?"
        ];
      }
      return this.addPersonalityFlair(this.pickRandom(responses));
    } else {
      const responses = isEnglish ? [
        "Look, I talked to my husband. He said NEVER share OTP on call. Can we do this at the branch instead?",
        "Sorry but I'm not comfortable doing this. I'll visit the bank tomorrow. Which branch should I go to?",
        "I thought about it but I can't do this. Let me verify at the bank. What documents should I bring?",
        "My brother works at SBI and he said this sounds suspicious. Let me call the official helpline first."
      ] : [
        "Dekho, maine apne husband se baat ki. Unhone kaha KABHI OTP call pe share mat karo. Branch pe mil sakte hain?",
        "Sorry par mujhe comfortable nahi lag raha. Kal bank jaaungi. Kaun si branch?",
        "Maine socha par nahi ho payega. Bank jaake verify karti hun. Kya documents laun?",
        "Mere bhai SBI mein kaam karte hain, unhone kaha suspicious hai. Pehle official helpline call karti hun."
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
  }

  handleKYCScam(message, emotionalContext, turnCount) {
    const isEnglish = this.detectedLanguage === 'english';
    
    const responses = turnCount <= 3 ? (isEnglish ? [
      "KYC pending? But I remember submitting everything already. When did this issue come up?",
      "Oh, I thought my KYC was complete! Which specific document is missing?",
      "My Aadhaar and PAN are both linked since 2020. What exactly is the problem?",
      "I don't understand - I completed KYC at the branch itself. Can you please check again?",
      "KYC expired? But I didn't get any SMS or email about this. When was it supposed to be done?"
    ] : [
      "KYC pending? Par maine toh sab submit kar diya tha. Yeh issue kab aaya?",
      "Arrey, mujhe laga KYC complete hai! Kaun sa document missing hai exactly?",
      "Mera Aadhaar aur PAN dono 2020 se linked hain. Problem kya hai specifically?",
      "Samajh nahi aa raha - maine branch pe hi KYC kiya tha. Phir se check karoge?",
      "KYC expire? Par mujhe koi SMS ya email nahi aaya iske baare mein. Kab karna tha?"
    ]) : (isEnglish ? [
      "Now I'm worried. Let me visit the branch directly. Which location should I come to?",
      "I'll come to the bank tomorrow with all documents. What's the branch address please?",
      "Can you send me an official email about this? I want everything properly documented.",
      "Let me call the customer care number printed on my card to verify this first."
    ] : [
      "Ab tension ho rahi hai. Branch pe aa jaati hun. Kaun si location pe aaun?",
      "Kal bank aa jaaungi sab documents leke. Branch ka address kya hai?",
      "Iske baare mein official email bhej sakte ho? Mujhe sab documented chahiye.",
      "Card pe jo customer care number hai, pehle woh call karke verify karti hun."
    ]);
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  handlePrizeScam(message, emotionalContext, turnCount) {
    const upiMatch = message.match(/([a-zA-Z0-9._-]+@[a-zA-Z]+)/i);
    const upi = upiMatch ? upiMatch[0] : null;
    const amountMatch = message.match(/rs\.?\s*(\d+(?:,\d+)?)|(\d+(?:,\d+)?)\s*(rupees|rs)/i);
    const amount = amountMatch ? amountMatch[0] : null;
    const isEnglish = this.detectedLanguage === 'english';
    
    if (upi) {
      const responses = isEnglish ? [
        `Send to ${upi}? Okay wait, let me open GPay. What name should I see when I search?`,
        `Sending to ${upi}... but first confirm - is this your personal account or the company's?`,
        `${upi} right? Okay. Before I pay, what's your full name as registered on UPI?`,
        `Got it - ${upi}. But tell me, what organization is this from? I want to note it down.`
      ] : [
        `${upi} pe bhejun? Okay ruko, GPay khol rahi hun. Search karne pe kya naam aana chahiye?`,
        `${upi} pe bhej rahi hun... par pehle confirm karo - yeh personal account hai ya company ka?`,
        `${upi} sahi hai? Okay. Pay karne se pehle, UPI pe registered full name batao?`,
        `Theek hai - ${upi}. Par batao, yeh kaun si organization se hai? Note karna hai mujhe.`
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
    
    if (amount) {
      const responses = isEnglish ? [
        `${amount}? That's quite a bit. But okay for a lottery I can manage. What's the UPI ID?`,
        `Hmm ${amount}... let me check my balance first. Tell me the exact payment details?`,
        `${amount} I can arrange. Give me the account number, IFSC code, and beneficiary name.`,
        `Okay ${amount}. Before I transfer - what's the company name and your employee ID?`
      ] : [
        `${amount}? Kaafi hai. Par lottery ke liye manage kar lungi. UPI ID kya hai?`,
        `Hmm ${amount}... pehle balance check karti hun. Exact payment details batao?`,
        `${amount} arrange kar lungi. Account number, IFSC, aur beneficiary name do.`,
        `Okay ${amount}. Transfer se pehle - company name aur aapka employee ID batao?`
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
    
    const responses = isEnglish ? [
      "Wait, I won something?! But I don't remember entering any contest. Which one was this?",
      "Oh wow! A prize for me? But this sounds too good to be true. How can I verify this is real?",
      "Lottery?? But I never buy lottery tickets though. Can you explain how I was selected?",
      "This sounds amazing but also suspicious. Please send me an official email with all the details."
    ] : [
      "Ruko, maine kuch jeeta?! Par mujhe yaad nahi ki maine koi contest enter kiya. Kaun sa tha yeh?",
      "Arrey wah! Mere liye prize? Par yeh toh too good to be true lag raha hai. Verify kaise karun?",
      "Lottery?? Par main toh kabhi lottery tickets khareedti hi nahi. Mujhe kaise select kiya?",
      "Amazing toh hai par suspicious bhi. Official email bhejo please sab details ke saath."
    ];
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  handleThreatScam(message, emotionalContext, turnCount) {
    const timeMatch = message.match(/(\d+)\s*(minute|hour|second)/i);
    const time = timeMatch ? timeMatch[0] : null;
    const isEnglish = this.detectedLanguage === 'english';
    
    if (time) {
      const responses = isEnglish ? [
        `Only ${time}?? You're really scaring me! But wait - let me confirm first, what's your official number?`,
        `${time}?! That's way too fast, I can't think properly. What's your supervisor's number please?`,
        `${time} is too little time! At least tell me your name and branch so I can verify!`,
        `Only ${time}?! I'm panicking now. Give me the helpdesk number I can call back on.`
      ] : [
        `Sirf ${time}?? Aap mujhe dara rahe ho! Par ruko - pehle confirm karo, official number kya hai?`,
        `${time}?! Bahut jaldi hai, soch bhi nahi pa rahi. Supervisor ka number do please?`,
        `${time} mein kaise! Kam se kam apna naam aur branch toh batao taaki verify kar sakun!`,
        `Sirf ${time}?! Panic ho rahi hun. Helpdesk number do jispe call back kar sakun.`
      ];
      return this.addPersonalityFlair(this.pickRandom(responses));
    }
    
    const responses = isEnglish ? [
      "Oh my god! You're really scaring me. But even in emergency I should be careful. What's your employee ID?",
      "This is so stressful! But before I panic - which bank and which branch are you calling from exactly?",
      "Wait, let me calm down first. Can you give me a reference number for this issue?",
      "I'm really worried now. But tell me your name and designation - I need to verify first.",
      "If my account is blocked, I'll go to the branch directly. Which address should I come to?"
    ] : [
      "Oh god! Aap mujhe bahut dara rahe ho. Par emergency mein bhi careful rehna chahiye. Employee ID kya hai?",
      "Bahut stress ho raha hai! Par panic hone se pehle - kaun sa bank aur branch se bol rahe ho exactly?",
      "Ruko, pehle calm hone do. Is issue ka reference number de sakte ho?",
      "Ab tension ho rahi hai. Par pehle naam aur designation batao - verify karna hai mujhe.",
      "Agar account block hai toh branch pe aa jaati hun. Kaun sa address pe aaun?"
    ];
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  handleCardScam(message, emotionalContext, turnCount) {
    const isEnglish = this.detectedLanguage === 'english';
    
    const responses = isEnglish ? [
      "Card details? Okay, but first tell me - what's your name and employee ID for my records?",
      "Before I share my card number, I need to verify you. What's the official customer care number?",
      "I can share but I always note down who I'm talking to. Your name, department, and branch please?",
      "Let me find my card first. Meanwhile, what's your direct phone number and official email?",
      "Which card are you asking about? I have multiple cards. And what's your employee code?"
    ] : [
      "Card details? Theek hai, par pehle batao - aapka naam aur employee ID kya hai mere records ke liye?",
      "Card number share karne se pehle, verify karna hai. Official customer care number kya hai?",
      "Share kar sakti hun par hamesha note karti hun kisse baat kar rahi hun. Naam, department, branch batao?",
      "Pehle card dhundhne do. Tab tak, aapka direct phone number aur official email batao?",
      "Kaun sa card puch rahe ho? Mere paas multiple cards hain. Aur employee code kya hai aapka?"
    ];
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  handleInvestmentScam(message, emotionalContext, turnCount) {
    const isEnglish = this.detectedLanguage === 'english';
    
    const responses = isEnglish ? [
      "Guaranteed returns? That sounds too risky. What's your company name and SEBI registration number?",
      "Investment opportunity? Sounds interesting but I need to verify first. What's your official website?",
      "My CA handles all my investments. Can I share your details with him? What's your company name?",
      "Hmm, I'm interested but also cautious. Send me the documentation to my email. What's your company name?"
    ] : [
      "Guaranteed returns? Yeh toh risky lag raha hai. Company ka naam aur SEBI registration number kya hai?",
      "Investment opportunity? Interesting hai par verify karna padega. Official website kya hai?",
      "Mere CA sab investments handle karte hain. Aapki details unhe de dun? Company ka naam kya hai?",
      "Hmm, interested hun par cautious bhi. Email pe documentation bhejo. Company ka naam batao?"
    ];
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  handleJobScam(message, emotionalContext, turnCount) {
    const isEnglish = this.detectedLanguage === 'english';
    
    const responses = isEnglish ? [
      "Work from home job? Sounds interesting! But what company is this? I need to research first.",
      "Daily earning? That sounds good but too easy. What exactly is the work involved?",
      "Tell me more - what's the company name, website, and your designation please?",
      "I'm interested but need more details. What qualifications are required? And what's the interview process?"
    ] : [
      "Work from home job? Interesting lag raha hai! Par kaun si company hai? Pehle research karna hai.",
      "Daily earning? Accha hai par bahut easy lag raha hai. Kaam exactly kya karna hoga?",
      "Aur batao - company ka naam, website, aur aapki designation kya hai?",
      "Interested hun par details chahiye. Qualifications kya chahiye? Interview process kya hai?"
    ];
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  handleGenericScam(message, emotionalContext, turnCount) {
    const lowerMsg = message.toLowerCase();
    const isEnglish = this.detectedLanguage === 'english';
    
    // Try to extract any details mentioned
    const phoneMatch = message.match(/\+91[\s-]?(\d{10})|(\d{10})/);
    const upiMatch = message.match(/([a-zA-Z0-9._-]+@[a-zA-Z]+)/i);
    const amountMatch = message.match(/rs\.?\s*(\d+)|(\d+)\s*rupees/i);
    
    if (phoneMatch) {
      const phone = phoneMatch[0];
      const response = isEnglish 
        ? `Okay noted ${phone}. Is this your direct number? I'll call back to verify.`
        : `Okay noted ${phone}. Yeh aapka direct number hai? Call back karke verify karti hun.`;
      return this.addPersonalityFlair(response);
    }
    
    if (upiMatch) {
      const upi = upiMatch[0];
      const response = isEnglish
        ? `${upi} - got it. Before I proceed, what name will show on this UPI?`
        : `${upi} - theek hai. Aage badhne se pehle, is UPI pe kya naam dikhega?`;
      return this.addPersonalityFlair(response);
    }
    
    if (amountMatch) {
      const amount = amountMatch[0];
      const response = isEnglish
        ? `${amount}? Okay let me check my balance. What's the exact UPI ID or account number?`
        : `${amount}? Okay balance check karti hun. Exact UPI ID ya account number kya hai?`;
      return this.addPersonalityFlair(response);
    }
    
    // Default extraction responses
    const responses = isEnglish ? [
      "Okay I understand. But before we proceed - what's your name and employee ID?",
      "Alright then. Tell me clearly - which organization are you from exactly?",
      "I'm following. But I always keep records - your name, department, and contact number please?",
      "Understood. Let me note down - what's your full name and official email?",
      "Got it. But first, what's the official helpline number I can call to verify this?"
    ] : [
      "Okay samajh gayi. Par aage badhne se pehle - aapka naam aur employee ID kya hai?",
      "Hmm theek hai. Clearly batao - kaun si organization se ho exactly?",
      "Sun rahi hun. Par hamesha record rakhti hun - naam, department, contact number batao?",
      "Samajh gayi. Note karti hun - full name aur official email kya hai?",
      "Theek hai. Par pehle, verify karne ke liye official helpline number kya hai?"
    ];
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  /**
   * Respond to ambiguous messages - LANGUAGE AWARE
   */
  respondToAmbiguousMessage(message, emotionalContext, turnCount) {
    const isEnglish = this.detectedLanguage === 'english';
    
    const responses = isEnglish ? [
      "Sorry, can you explain that in more detail? I want to understand properly.",
      "Okay. Tell me more - what exactly is this regarding?",
      "I see. And what should I do about it? Please walk me through the process.",
      "Interesting. But who am I speaking with? Which company or organization?",
      "Okay, I'm listening. Please continue, what's the full situation here?"
    ] : [
      "Sorry, thoda detail mein samjha sakte ho? Theek se samajhna hai mujhe.",
      "Hmm okay. Aur batao - exactly kis baare mein hai yeh?",
      "Achha. Toh karna kya hai mujhe? Process samjhao please.",
      "Interesting. Par mai kisse baat kar rahi hun? Kaun si company ya organization?",
      "Okay, sun rahi hun. Aage batao, poori situation kya hai?"
    ];
    return this.addPersonalityFlair(this.pickRandom(responses));
  }

  /**
   * Add personality quirks to make response more human
   * RESPECTS the detected language - only adds Hindi elements if scammer used Hindi
   */
  addPersonalityFlair(response) {
    // ONLY add Hindi/Hinglish flair if scammer used Hindi
    if (this.detectedLanguage === 'english') {
      // Keep response in pure English - no Hindi additions
      const random = Math.random();
      
      // 20% chance to add English filler words only
      if (random < 0.2) {
        const fillers = ['Actually, ', 'Well, ', 'Hmm, ', 'Look, ', 'Okay so, '];
        response = this.pickRandom(fillers) + response.charAt(0).toLowerCase() + response.slice(1);
      }
      
      // 15% chance to add English ending phrase
      if (random > 0.85) {
        const endings = [' right?', '...', ' you know?', ' I think.'];
        response = response.replace(/[.?!]$/, '') + this.pickRandom(endings);
      }
      
      return response;
    }
    
    // For Hindi or Hinglish - can add Hinglish elements
    const random = Math.random();
    
    // 25% chance to add filler words
    if (random < 0.25) {
      const fillers = this.detectedLanguage === 'hindi' 
        ? ['Dekhiye, ', 'Suniye, ', 'Accha, ', 'Haan toh, ']
        : ['Actually, ', 'Basically, ', 'Hmm, '];
      response = this.pickRandom(fillers) + response.charAt(0).toLowerCase() + response.slice(1);
    }
    
    // 15% chance to add ending phrase
    if (random > 0.85) {
      const endings = this.detectedLanguage === 'hindi'
        ? [' hai na?', ' samjhe?', ' theek hai?']
        : [' na?', ' right?', '...'];
      response = response.replace(/[.?!]$/, '') + this.pickRandom(endings);
    }
    
    return response;
  }

  /**
   * Store conversation memory
   */
  storeMemory(message, sessionMemory) {
    // Extract key information to remember
    const phoneMatch = message.match(/\+91[\s-]?(\d{10})|(\d{10})/);
    const nameMatch = message.match(/(?:my name is|i am|this is)\s+([A-Za-z]+)/i);
    const orgMatch = message.match(/(?:from|with)\s+([A-Za-z]+\s*(?:bank|ltd|pvt|private|limited)?)/i);
    
    if (phoneMatch) sessionMemory.mentionedPhone = phoneMatch[0];
    if (nameMatch) sessionMemory.mentionedName = nameMatch[1];
    if (orgMatch) sessionMemory.mentionedOrg = orgMatch[1];
  }

  /**
   * Utility function
   */
  pickRandom(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }
}

module.exports = { ConversationBrain };
