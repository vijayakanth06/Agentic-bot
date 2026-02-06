/**
 * Test Runner for Agentic Honey-Pot
 * Updated for HCL GUVI Buildathon
 * 
 * Runs unit tests for all components.
 */

const { ScamDetector } = require('../src/detection/scam-detector');
const { StateMachine, STATES } = require('../src/state/machine');
const { AgentOrchestrator } = require('../src/agent/orchestrator');
const { IntelligenceExtractor } = require('../src/extraction/extractor');
const { ResponseValidator } = require('../src/validation/safety');
const { MetricsTracker } = require('../src/utils/metrics');

// Test utilities
let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✓ ${name}`);
    testsPassed++;
  } catch (error) {
    console.log(`✗ ${name}`);
    console.log(`  Error: ${error.message}`);
    testsFailed++;
  }
}

function assertEqual(actual, expected, message = '') {
  if (actual !== expected) {
    throw new Error(`${message}: Expected ${expected}, got ${actual}`);
  }
}

function assertTrue(value, message = '') {
  if (!value) {
    throw new Error(message || 'Expected true, got false');
  }
}

function assertGreaterThan(actual, minimum, message = '') {
  if (actual <= minimum) {
    throw new Error(message || `Expected ${actual} > ${minimum}`);
  }
}

function assertGreaterOrEqual(actual, minimum, message = '') {
  if (actual < minimum) {
    throw new Error(message || `Expected ${actual} >= ${minimum}`);
  }
}

// Test suites

console.log('\n=== Agentic Honey-Pot Test Suite ===\n');

console.log('--- Scam Detection Tests ---');

test('ScamDetector: Detects urgency patterns', () => {
  const detector = new ScamDetector();
  const result = detector.analyze('You must act immediately or your account will be blocked!');
  assertGreaterOrEqual(result.confidence, 0.2, 'Should detect urgency patterns');
  assertTrue(result.indicators.some(i => i.category === 'urgency' || i.category === 'threat'), 'Should categorize as urgency/threat');
});

test('ScamDetector: Detects financial requests with UPI', () => {
  const detector = new ScamDetector();
  const result = detector.analyze('Please send money to this UPI ID: scammer@upi immediately');
  assertGreaterOrEqual(result.confidence, 0.4, 'Should have high confidence for financial + urgency');
  assertTrue(result.has_financial_context, 'Should detect financial context');
});

test('ScamDetector: Detects bank authority impersonation', () => {
  const detector = new ScamDetector();
  const result = detector.analyze('This is SBI bank manager calling about your account suspension. Act immediately.');
  assertGreaterOrEqual(result.confidence, 0.2, 'Should detect authority impersonation');
  assertTrue(result.indicators.length > 0, 'Should have indicators');
});

test('ScamDetector: Detects KYC scam patterns', () => {
  const detector = new ScamDetector();
  const result = detector.analyze('Your KYC is expired. Update immediately or your account will be blocked. Call now.');
  assertGreaterOrEqual(result.confidence, 0.3, 'Should detect KYC scam');
  assertTrue(result.indicators.some(i => i.category === 'verification' || i.category === 'urgency'), 'Should identify verification/urgency');
});

test('ScamDetector: Detects OTP fraud attempts', () => {
  const detector = new ScamDetector();
  const result = detector.analyze('Share your OTP immediately to verify account. Your bank account will be suspended.');
  assertGreaterOrEqual(result.confidence, 0.3, 'Should detect OTP fraud');
  assertTrue(result.has_direct_request, 'Should detect direct request');
});

test('ScamDetector: Detects lottery scams', () => {
  const detector = new ScamDetector();
  const result = detector.analyze('Congratulations! You have won a lottery prize of Rs.50 lakhs! Pay processing fee to claim.');
  assertGreaterOrEqual(result.confidence, 0.4, 'Should detect lottery scam');
});

test('ScamDetector: Low confidence for normal messages', () => {
  const detector = new ScamDetector();
  const result = detector.analyze('Hey, how are you doing today? Want to meet for coffee?');
  assertTrue(result.confidence < 0.5, 'Should have low confidence for normal messages');
  assertTrue(!result.is_scam, 'Should not classify as scam');
});

test('ScamDetector: Accumulates evidence from history', () => {
  const detector = new ScamDetector();
  const history = [
    'This is from your bank.',
    'Your account has a problem.'
  ];
  const result = detector.analyze('Send Rs.5000 to verify your account.', history);
  assertGreaterOrEqual(result.confidence, 0.3, 'Should accumulate evidence from history');
});

console.log('\n--- State Machine Tests ---');

test('StateMachine: Initial state transitions to GREETING', () => {
  const machine = new StateMachine();
  const result = machine.transition(STATES.INITIAL, { scamConfidence: 0.8 });
  assertEqual(result.next_state, STATES.GREETING, 'Should transition to GREETING');
});

test('StateMachine: GREETING stays or transitions based on context', () => {
  const machine = new StateMachine();
  const result = machine.transition(STATES.GREETING, { turnCount: 1, hasFinancialContext: false });
  assertTrue(
    result.next_state === STATES.GREETING || result.next_state === STATES.BUILDING_RAPPORT,
    'Should stay in GREETING or move to BUILDING_RAPPORT'
  );
});

test('StateMachine: Financial context triggers transition', () => {
  const machine = new StateMachine();
  const result = machine.transition(STATES.BUILDING_RAPPORT, { turnCount: 2, hasFinancialContext: true });
  assertEqual(result.next_state, STATES.FINANCIAL_CONTEXT, 'Should transition on financial context');
});

test('StateMachine: EXTRACTION stays engaged with low progress', () => {
  const machine = new StateMachine();
  // With low extraction progress, should stay in EXTRACTION even at turn 10
  const result = machine.transition(STATES.EXTRACTION, { 
    turnCount: 10, 
    extractionProgress: 0.5,
    consecutiveDelays: 0
  });
  assertEqual(result.next_state, STATES.EXTRACTION, 'Should stay in EXTRACTION with low progress');
});

test('StateMachine: EXTRACTION transitions to CLOSING with high progress', () => {
  const machine = new StateMachine();
  // Should only close with high progress (>=0.9) and enough turns (>=12)
  const result = machine.transition(STATES.EXTRACTION, { 
    turnCount: 15, 
    extractionProgress: 0.95,
    consecutiveDelays: 0
  });
  assertEqual(result.next_state, STATES.CLOSING, 'Should transition to CLOSING with high progress');
});

test('StateMachine: SUSPICIOUS recovery', () => {
  const machine = new StateMachine();
  const result = machine.transition(STATES.SUSPICIOUS, { consecutiveDelays: 1 });
  assertEqual(result.next_state, STATES.EXTRACTION, 'Should recover to EXTRACTION');
});

test('StateMachine: ENDED is terminal', () => {
  const machine = new StateMachine();
  const result = machine.transition(STATES.ENDED, { scamConfidence: 1.0 });
  assertEqual(result.next_state, STATES.ENDED, 'Should stay in ENDED');
  assertTrue(result.should_end, 'Should indicate should end');
});

console.log('\n--- Intelligence Extraction Tests ---');

test('IntelligenceExtractor: Extracts UPI IDs', () => {
  const extractor = new IntelligenceExtractor();
  const result = extractor.extract('Send payment to scammer@ybl or fraudster@paytm');
  const upiItems = result.items.filter(i => i.type === 'upi');
  assertGreaterOrEqual(upiItems.length, 1, 'Should extract UPI IDs');
});

test('IntelligenceExtractor: Extracts phone numbers', () => {
  const extractor = new IntelligenceExtractor();
  const result = extractor.extract('Call me at +91 9876543210 or 8765432109');
  const phoneItems = result.items.filter(i => i.type === 'phone');
  assertGreaterOrEqual(phoneItems.length, 1, 'Should extract phone numbers');
});

test('IntelligenceExtractor: Extracts URLs', () => {
  const extractor = new IntelligenceExtractor();
  const result = extractor.extract('Visit https://suspicious-link.tk/pay or bit.ly/scam123');
  const urlItems = result.items.filter(i => i.type === 'url');
  assertGreaterOrEqual(urlItems.length, 1, 'Should extract URLs');
});

test('IntelligenceExtractor: Extracts IFSC codes', () => {
  const extractor = new IntelligenceExtractor();
  const result = extractor.extract('IFSC: SBIN0001234, Account: 12345678901');
  const ifscItems = result.items.filter(i => i.type === 'ifsc');
  assertEqual(ifscItems.length, 1, 'Should extract IFSC code');
});

test('IntelligenceExtractor: Deduplicates items', () => {
  const extractor = new IntelligenceExtractor();
  const result = extractor.extract('scammer@upi scammer@upi scammer@upi');
  const upiCount = result.items.filter(i => i.type === 'upi').length;
  assertEqual(upiCount, 1, 'Should deduplicate UPI IDs');
});

test('IntelligenceExtractor: Extracts names', () => {
  const extractor = new IntelligenceExtractor();
  const result = extractor.extract('My name is Rahul Sharma and I am calling from the bank.');
  const nameItems = result.items.filter(i => i.type === 'name');
  assertGreaterOrEqual(nameItems.length, 1, 'Should extract names');
});

console.log('\n--- Response Validation Tests ---');

test('ResponseValidator: Blocks scam accusations', () => {
  const validator = new ResponseValidator();
  const result = validator.validate('I know you are a scammer trying to fraud me', 'GREETING');
  assertTrue(!result.is_valid, 'Should block scam accusations');
});

test('ResponseValidator: Blocks police/legal mentions', () => {
  const validator = new ResponseValidator();
  const result = validator.validate('I am going to report this to the police', 'GREETING');
  assertTrue(!result.is_valid, 'Should block police mentions');
});

test('ResponseValidator: Allows normal responses', () => {
  const validator = new ResponseValidator();
  const result = validator.validate('That sounds interesting! Tell me more about this opportunity.', 'GREETING');
  assertTrue(result.is_valid, 'Should allow normal responses');
});

test('ResponseValidator: Provides fallback response', () => {
  const validator = new ResponseValidator();
  const fallback = validator.getFallbackResponse('EXTRACTION', 0);
  assertTrue(fallback.length > 20, 'Should provide substantial fallback');
});

console.log('\n--- Metrics Tracker Tests ---');

test('MetricsTracker: Records conversations', () => {
  const tracker = new MetricsTracker();
  tracker.recordConversation({
    conversation_id: 'test-123',
    metrics: {
      turn_count: 10,
      engagement_duration_ms: 60000,
      extraction_score: 0.7,
      persona_consistency: 0.9
    },
    intelligence: {
      extracted: [{ type: 'upi', value: 'test@upi', confidence: 0.8 }],
      is_scam: true,
      scam_confidence: 0.85
    },
    state: { current: 'EXTRACTION' }
  });
  
  const metrics = tracker.getMetrics();
  assertEqual(metrics.session.totalConversations, 1, 'Should record conversation');
});

test('MetricsTracker: Calculates engagement score', () => {
  const tracker = new MetricsTracker();
  const score = tracker.calculateEngagementScore({
    turn_count: 15,
    engagement_duration_ms: 300000,
    intelligence_items: 5,
    extraction_score: 0.8,
    persona_consistency: 0.9
  });
  
  assertGreaterThan(score, 40, 'Should calculate reasonable engagement score');
});

test('MetricsTracker: Assesses conversation quality', () => {
  const tracker = new MetricsTracker();
  const assessment = tracker.assessConversationQuality({
    turn_count: 20,
    engagement_duration_ms: 600000,
    intelligence_items: 8,
    extraction_score: 0.9,
    persona_consistency: 0.95
  });
  
  assertTrue(
    assessment.rating === 'excellent' || assessment.rating === 'good',
    'Should rate good/excellent for high engagement'
  );
});

console.log('\n--- Agent Orchestrator Tests ---');

test('AgentOrchestrator: Gets default persona', () => {
  const orchestrator = new AgentOrchestrator();
  const persona = orchestrator.getDefaultPersona();
  assertEqual(persona.name, 'Priya Sharma', 'Should have correct persona name');
  assertEqual(persona.location, 'Mumbai, Andheri', 'Should have correct location');
});

test('AgentOrchestrator: Generates state-specific prompts', () => {
  const orchestrator = new AgentOrchestrator();
  const prompt = orchestrator.getStatePrompt('EXTRACTION', { scamType: 'bank_fraud' });
  assertTrue(prompt.includes('EXTRACTION'), 'Should include state name');
  assertTrue(prompt.includes('bank_fraud'), 'Should include scam type');
});

test('AgentOrchestrator: Generates responses for different states', async () => {
  const orchestrator = new AgentOrchestrator();
  
  const initialResponse = await orchestrator.generateResponse('', { state: 'INITIAL' });
  assertTrue(initialResponse.length > 10, 'Should generate INITIAL response');
  
  const extractionResponse = await orchestrator.generateResponse('', { state: 'EXTRACTION' });
  assertTrue(extractionResponse.length > 10, 'Should generate EXTRACTION response');
});

test('AgentOrchestrator: Provides fallback responses', () => {
  const orchestrator = new AgentOrchestrator();
  const response = orchestrator.getFallbackResponse('EXTRACTION', 0);
  assertTrue(response.length > 20, 'Should provide substantial fallback');
  assertTrue(response.includes('sorry') || response.includes('Sorry'), 'Fallback should be apologetic');
});

// Summary
console.log('\n═══════════════════════════════════════════════════════════');
console.log('                    Test Results');
console.log('═══════════════════════════════════════════════════════════');
console.log(`✓ Passed: ${testsPassed}`);
console.log(`✗ Failed: ${testsFailed}`);
console.log('═══════════════════════════════════════════════════════════');

if (testsFailed > 0) {
  console.log('\n⚠️  Some tests failed! Review the errors above.');
  process.exit(1);
} else {
  console.log('\n🎉 All tests passed!');
  process.exit(0);
}
