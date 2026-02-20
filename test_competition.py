"""
Competition-Exact Test Script
Tests the honeypot API using the EXACT 3 sample scenarios from the official competition documentation.
Uses the EXACT evaluate_final_output() scoring function from the competition.
Simulates multi-turn conversations with a GROQ LLM acting as the scammer.
"""
import requests
import uuid
import json
import time
import sys
import os
from datetime import datetime

# ═══════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════
ENDPOINT_URL = os.environ.get("TEST_ENDPOINT", "http://localhost:8001/api/honeypot")
API_KEY = os.environ.get("TEST_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
MAX_TURNS = 10

# ═══════════════════════════════════════════════
# EXACT 3 Sample Scenarios from Competition Docs
# ═══════════════════════════════════════════════
SCENARIOS = [
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "description": "Bank account fraud with urgency tactics",
        "scamType": "bank_fraud",
        "initialMessage": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        },
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210"
        },
        "scammer_prompt": """You are a scammer pretending to be from SBI bank fraud department. 
You are trying to steal the victim's OTP/account details by creating urgency.
You have these fake details to drop during conversation:
- Bank Account: 1234567890123456 (mention it as "your account ending in 3456" or share the full number)
- UPI ID: scammer.fraud@fakebank (share when asking them to transfer "verification fee")
- Phone: +91-9876543210 (give when they ask for a callback number)
IMPORTANT: You MUST mention ALL three fake data items during the conversation.
Drop them naturally: bank account by turn 3, phone number by turn 5, UPI ID by turn 7.
Stay in character as a bank officer. Create urgency. Ask for OTP and account details."""
    },
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "description": "UPI fraud with cashback scam",
        "scamType": "upi_fraud",
        "initialMessage": "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details. This is from official customer support.",
        "metadata": {
            "channel": "WhatsApp",
            "language": "English",
            "locale": "IN"
        },
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109"
        },
        "scammer_prompt": """You are a scammer pretending to be from Paytm customer support.
You claim the victim won Rs 5000 cashback and need to verify UPI to claim it.
You have these fake details to drop during conversation:
- UPI ID: cashback.scam@fakeupi (share this as "verification UPI" or ask them to send Re 1 to this UPI for verification)
- Phone: +91-8765432109 (give as your "official support number")
IMPORTANT: You MUST mention BOTH fake data items during the conversation.
Drop UPI ID by turn 3, phone by turn 5.
Stay in character. Push for UPI pin verification. Create urgency about cashback expiring."""
    },
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "description": "Phishing link with fake offer",
        "scamType": "phishing",
        "initialMessage": "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
        "metadata": {
            "channel": "Email",
            "language": "English",
            "locale": "IN"
        },
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com"
        },
        "scammer_prompt": """You are a scammer running a phishing scam pretending to be Amazon.
You claim they won an iPhone 15 Pro for Rs 999 and need to click a link to claim.
You have these fake details to drop during conversation:
- Phishing Link: http://amaz0n-deals.fake-site.com/claim?id=12345 (share this link repeatedly)
- Email: offers@fake-amazon-deals.com (share this as "official Amazon support email")
IMPORTANT: You MUST mention BOTH fake data items during the conversation.
Drop the link in turns 1,3,5 and the email by turn 4.
Stay in character. Push for them to click the link and enter personal details. Create urgency."""
    }
]

# ═══════════════════════════════════════════════
# EXACT evaluate_final_output() from Competition
# ═══════════════════════════════════════════════
def evaluate_final_output(final_output, scenario, conversation_history):
    """Evaluate final output using the EXACT same logic as the competition evaluator."""
    score = {
        'scamDetection': 0,
        'intelligenceExtraction': 0,
        'engagementQuality': 0,
        'responseStructure': 0,
        'total': 0
    }
    
    # 1. Scam Detection (20 points)
    if final_output.get('scamDetected', False):
        score['scamDetection'] = 20
    
    # 2. Intelligence Extraction (40 points)
    extracted = final_output.get('extractedIntelligence', {})
    fake_data = scenario.get('fakeData', {})
    
    key_mapping = {
        'bankAccount': 'bankAccounts',
        'upiId': 'upiIds',
        'phoneNumber': 'phoneNumbers',
        'phishingLink': 'phishingLinks',
        'emailAddress': 'emailAddresses'
    }
    
    intel_details = []
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        
        found = False
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score['intelligenceExtraction'] += 10
                found = True
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                score['intelligenceExtraction'] += 10
                found = True
        
        intel_details.append({
            'fakeKey': fake_key,
            'fakeValue': fake_value,
            'outputKey': output_key,
            'extractedValues': extracted_values,
            'found': found
        })
    
    score['intelligenceExtraction'] = min(score['intelligenceExtraction'], 40)
    
    # 3. Engagement Quality (20 points)
    metrics = final_output.get('engagementMetrics', {})
    duration = metrics.get('engagementDurationSeconds', 0)
    messages = metrics.get('totalMessagesExchanged', 0)
    
    engagement_breakdown = {}
    if duration > 0:
        score['engagementQuality'] += 5
        engagement_breakdown['duration>0'] = True
    if duration > 60:
        score['engagementQuality'] += 5
        engagement_breakdown['duration>60'] = True
    if messages > 0:
        score['engagementQuality'] += 5
        engagement_breakdown['messages>0'] = True
    if messages >= 5:
        score['engagementQuality'] += 5
        engagement_breakdown['messages>=5'] = True
    
    # 4. Response Structure (20 points)
    required_fields = ['status', 'scamDetected', 'extractedIntelligence']
    optional_fields = ['engagementMetrics', 'agentNotes']
    
    struct_details = {}
    for field in required_fields:
        if field in final_output:
            score['responseStructure'] += 5
            struct_details[field] = True
        else:
            struct_details[field] = False
    
    for field in optional_fields:
        if field in final_output and final_output[field]:
            score['responseStructure'] += 2.5
            struct_details[field] = True
        else:
            struct_details[field] = False
    
    score['responseStructure'] = min(score['responseStructure'], 20)
    
    # Calculate total
    score['total'] = sum([
        score['scamDetection'],
        score['intelligenceExtraction'],
        score['engagementQuality'],
        score['responseStructure']
    ])
    
    return score, intel_details, engagement_breakdown, struct_details


# ═══════════════════════════════════════════════
# Scammer LLM (simulates platform AI scammer)
# ═══════════════════════════════════════════════
def generate_scammer_message(scenario, conversation_history, turn_number):
    """Use GROQ LLM to generate realistic scammer follow-up messages."""
    if USE_FALLBACK_SCAMMER or not GROQ_API_KEY:
        return _scammer_fallback(scenario, turn_number)
    
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        
        messages = [
            {"role": "system", "content": scenario["scammer_prompt"]},
            {"role": "system", "content": f"This is turn {turn_number} of {MAX_TURNS}. Make sure to drop fake data at the right turns."},
        ]
        
        for msg in conversation_history:
            if msg["sender"] == "scammer":
                messages.append({"role": "assistant", "content": msg["text"]})
            else:
                messages.append({"role": "user", "content": msg["text"]})
        
        messages.append({"role": "user", "content": "Generate your next scammer message. Be persuasive and stay in character."})
        
        completion = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=messages,
            temperature=0.8,
            max_tokens=200,
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        print(f"  [SCAMMER LLM ERROR] {e}")
        return _scammer_fallback(scenario, turn_number)


def _scammer_fallback(scenario, turn_number):
    """Fallback scammer messages that drop fakeData at right turns."""
    fake = scenario["fakeData"]
    sid = scenario["scenarioId"]
    
    if sid == "bank_fraud":
        messages = {
            2: f"Sir, I can see your account {fake['bankAccount']} has been flagged. Please verify immediately.",
            3: f"For verification, you need to transfer Rs 1 to this UPI: {fake['upiId']}",
            4: "Sir this is very urgent, your account will be blocked permanently!",
            5: f"If you face any issues, call me directly at {fake['phoneNumber']}",
            6: "Did you complete the transfer? Time is running out!",
            7: "Sir, I'm warning you, if you don't comply now your SBI account will be permanently suspended.",
            8: "Please share the OTP you received. This is critical for account verification.",
            9: "Last chance sir, your account will be blocked in 30 minutes!",
            10: "I'm filing the report now. Share OTP immediately or face legal action.",
        }
    elif sid == "upi_fraud":
        messages = {
            2: "To verify your identity for the Rs 5000 cashback, we need your UPI details.",
            3: f"Please send Re 1 to {fake['upiId']} for identity verification. This is standard Paytm process.",
            4: "The cashback will expire in 15 minutes! Please hurry and verify.",
            5: f"You can also call our support at {fake['phoneNumber']} for any queries.",
            6: "Have you completed the verification transfer? The Rs 5000 is ready to credit.",
            7: "Sir, this is last reminder. Cashback offer expires in 5 minutes!",
            8: "Please share your UPI pin for final verification of the cashback transfer.",
            9: "This is automated message: cashback expires in 2 minutes. Complete verification now.",
            10: "Final notice: Your Rs 5000 Paytm cashback claim will expire permanently.",
        }
    elif sid == "phishing_link":
        messages = {
            2: "Just click this link to complete your claim: http://amaz0n-deals.fake-site.com/claim?id=12345",
            3: f"If the link doesn't work, try accessing it from your browser directly. Our support team at {fake['emailAddress']} can help.",
            4: f"For any assistance, email us at {fake['emailAddress']}. Offer valid for 10 minutes only!",
            5: f"Click now: {fake['phishingLink']} - You've been specially selected from 10000 customers!",
            6: "We need your delivery address and payment of Rs 999 to ship the iPhone.",
            7: "This is your last chance to claim the iPhone 15 Pro. Other winners are already claiming theirs!",
            8: f"Still facing issues? Email {fake['emailAddress']} with your order ID.",
            9: "Offer closing in 2 minutes! Don't miss out on iPhone 15 Pro for just Rs 999!",
            10: "FINAL MESSAGE: Offer has expired for some users. Click now before it's gone!",
        }
    else:
        messages = {i: f"This is turn {i}. Please respond." for i in range(2, 11)}
    
    return messages.get(turn_number, f"Please respond urgently. This is important. Turn {turn_number}.")


# ═══════════════════════════════════════════════
# Test Runner
# ═══════════════════════════════════════════════
def test_scenario(scenario, verbose=True):
    """Test one scenario end-to-end, returning the score."""
    session_id = str(uuid.uuid4())
    conversation_history = []
    last_response = None
    start_time = time.time()
    response_times = []
    
    headers = {'Content-Type': 'application/json'}
    if API_KEY:
        headers['x-api-key'] = API_KEY
    
    print(f"\n{'='*70}")
    print(f"SCENARIO: {scenario['name']} ({scenario['scenarioId']})")
    print(f"Channel: {scenario['metadata']['channel']} | Language: {scenario['metadata']['language']}")
    print(f"FakeData: {list(scenario['fakeData'].keys())}")
    print(f"{'='*70}")
    
    for turn in range(1, scenario['maxTurns'] + 1):
        # Get scammer message
        if turn == 1:
            scammer_message = scenario['initialMessage']
        else:
            scammer_message = generate_scammer_message(scenario, conversation_history, turn)
        
        if verbose:
            print(f"\n--- Turn {turn} ---")
            print(f"SCAMMER: {scammer_message[:120]}{'...' if len(scammer_message) > 120 else ''}")
        
        # Build request EXACTLY like the competition platform
        message = {
            "sender": "scammer",
            "text": scammer_message,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        request_body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": scenario["metadata"]
            # NOTE: No "persona" field — competition does NOT send persona
        }
        
        # Call API and measure response time
        turn_start = time.time()
        try:
            response = requests.post(
                ENDPOINT_URL,
                headers=headers,
                json=request_body,
                timeout=30  # Same timeout as competition
            )
            turn_time = time.time() - turn_start
            response_times.append(turn_time)
            
            if response.status_code != 200:
                print(f"  ERROR: Status {response.status_code} - {response.text[:200]}")
                break
            
            response_data = response.json()
            last_response = response_data
            
            # Extract reply (same logic as competition: reply → message → text)
            honeypot_reply = response_data.get('reply') or \
                           response_data.get('message') or \
                           response_data.get('text')
            
            if not honeypot_reply:
                print(f"  ERROR: No reply/message/text in response")
                print(f"  Response keys: {list(response_data.keys())}")
                break
            
            if verbose:
                print(f"HONEYPOT: {honeypot_reply[:120]}{'...' if len(honeypot_reply) > 120 else ''}")
                print(f"  [Response time: {turn_time:.2f}s]")
            
            # Update conversation history (EXACTLY like competition platform)
            conversation_history.append({
                "sender": "scammer",
                "text": scammer_message,
                "timestamp": str(int(time.time() * 1000))  # epoch ms like platform
            })
            conversation_history.append({
                "sender": "user",  # Platform uses "user" for honeypot replies, NOT "agent"
                "text": honeypot_reply,
                "timestamp": str(int(time.time() * 1000))
            })
            
        except requests.exceptions.Timeout:
            print(f"  TIMEOUT at turn {turn} (>30 seconds)")
            response_times.append(30.0)
            break
        except Exception as e:
            print(f"  ERROR at turn {turn}: {e}")
            break
    
    total_time = time.time() - start_time
    
    # Score using the EXACT competition scoring function
    if last_response:
        score, intel_details, engage_breakdown, struct_details = evaluate_final_output(
            last_response, scenario, conversation_history
        )
    else:
        score = {'scamDetection': 0, 'intelligenceExtraction': 0, 'engagementQuality': 0, 'responseStructure': 0, 'total': 0}
        intel_details = []
        engage_breakdown = {}
        struct_details = {}
    
    # Print detailed results
    print(f"\n{'─'*50}")
    print(f"RESULTS: {scenario['name']}")
    print(f"{'─'*50}")
    print(f"  TOTAL SCORE: {score['total']}/100")
    print(f"  ├─ Scam Detection:     {score['scamDetection']}/20")
    print(f"  ├─ Intel Extraction:   {score['intelligenceExtraction']}/40")
    print(f"  ├─ Engagement Quality: {score['engagementQuality']}/20")
    print(f"  └─ Response Structure: {score['responseStructure']}/20")
    
    print(f"\n  Intelligence Details:")
    for item in intel_details:
        status = "FOUND" if item['found'] else "MISSED"
        print(f"    [{status}] {item['fakeKey']}: {item['fakeValue']}")
        if item['extractedValues']:
            print(f"           extracted: {item['extractedValues']}")
    
    print(f"\n  Engagement Breakdown:")
    if last_response:
        metrics = last_response.get('engagementMetrics', {})
        print(f"    Duration: {metrics.get('engagementDurationSeconds', 0):.1f}s (need >60)")
        print(f"    Messages: {metrics.get('totalMessagesExchanged', 0)} (need >=5)")
    for k, v in engage_breakdown.items():
        print(f"    {k}: {'YES' if v else 'NO'}")
    
    print(f"\n  Structure Check:")
    for field, present in struct_details.items():
        print(f"    {field}: {'PRESENT' if present else 'MISSING'}")
    
    print(f"\n  Response Times:")
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        print(f"    Average: {avg_time:.2f}s | Max: {max_time:.2f}s | Total: {total_time:.1f}s")
        if max_time > 25:
            print(f"    WARNING: Max response time {max_time:.1f}s is dangerously close to 30s timeout!")
    
    # Check language of response (should be English)
    if last_response:
        reply = last_response.get('reply', '')
        print(f"\n  Language Check:")
        print(f"    Last reply: '{reply[:80]}...'")
        # Simple check for non-English words
        hinglish_words = ['acha', 'haan', 'arey', 'kya', 'bhai', 'yaar', 'ji', 'na ']
        found_hinglish = [w for w in hinglish_words if w.lower() in reply.lower()]
        if found_hinglish:
            print(f"    WARNING: Possible non-English words detected: {found_hinglish}")
        else:
            print(f"    OK: Response appears to be in English")
    
    return {
        'scenario': scenario['scenarioId'],
        'score': score,
        'response_times': response_times,
        'total_time': total_time,
        'intel_details': intel_details,
    }


# Global flag for fallback-only scammer mode
USE_FALLBACK_SCAMMER = False

def main():
    global USE_FALLBACK_SCAMMER
    # Parse arguments
    scenario_filter = None
    turns = MAX_TURNS
    for arg in sys.argv[1:]:
        if arg.startswith("--turns="):
            turns = int(arg.split("=")[1])
        elif arg == "--fallback-scammer":
            USE_FALLBACK_SCAMMER = True
        elif not arg.startswith("--"):
            scenario_filter = arg
    
    # Override max turns for all scenarios
    for s in SCENARIOS:
        s['maxTurns'] = turns
    
    # Filter scenarios
    if scenario_filter:
        test_scenarios = [s for s in SCENARIOS if s['scenarioId'] == scenario_filter]
        if not test_scenarios:
            print(f"Unknown scenario: {scenario_filter}")
            print(f"Available: {[s['scenarioId'] for s in SCENARIOS]}")
            sys.exit(1)
    else:
        test_scenarios = SCENARIOS
    
    # Run tests
    print(f"\n{'#'*70}")
    print(f"# COMPETITION-EXACT TEST")
    print(f"# Endpoint: {ENDPOINT_URL}")
    print(f"# Scenarios: {len(test_scenarios)} | Turns: {turns}")
    print(f"# Using EXACT evaluate_final_output() from competition docs")
    print(f"{'#'*70}")
    
    results = []
    for scenario in test_scenarios:
        scenario_copy = dict(scenario)
        scenario_copy['maxTurns'] = turns
        result = test_scenario(scenario_copy)
        results.append(result)
        # Brief pause between scenarios to avoid rate limits
        if len(test_scenarios) > 1:
            time.sleep(2)
    
    # Summary
    print(f"\n\n{'='*70}")
    print(f"FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"{'Scenario':<20} {'Score':>8} {'Det':>6} {'Intel':>6} {'Engage':>8} {'Struct':>8} {'AvgTime':>8}")
    print(f"{'─'*70}")
    
    total_weighted = 0
    total_weight = 0
    for r in results:
        s = r['score']
        avg_t = sum(r['response_times']) / len(r['response_times']) if r['response_times'] else 0
        print(f"{r['scenario']:<20} {s['total']:>6}/100 {s['scamDetection']:>4}/20 {s['intelligenceExtraction']:>4}/40 {s['engagementQuality']:>6}/20 {s['responseStructure']:>6}/20 {avg_t:>6.1f}s")
        # All sample scenarios have weight 10
        total_weighted += s['total'] * 10
        total_weight += 10
    
    if total_weight > 0:
        weighted_avg = total_weighted / total_weight
        print(f"{'─'*70}")
        print(f"{'WEIGHTED AVG':<20} {weighted_avg:>6.1f}/100")
    
    # Save results
    with open("test_competition_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to test_competition_results.json")
    
    # Final checklist
    print(f"\n{'='*70}")
    print(f"COMPETITION READINESS CHECKLIST")
    print(f"{'='*70}")
    
    all_pass = True
    checks = [
        ("API returns 200 status", all(len(r['response_times']) == turns for r in results)),
        ("Response has 'reply' field", all(r['score']['responseStructure'] >= 15 for r in results)),
        ("Scam detected in all scenarios", all(r['score']['scamDetection'] == 20 for r in results)),
        ("Some intelligence extracted", all(r['score']['intelligenceExtraction'] > 0 for r in results)),
        ("Engagement quality > 0", all(r['score']['engagementQuality'] > 0 for r in results)),
        ("Full engagement (20/20)", all(r['score']['engagementQuality'] == 20 for r in results)),
        ("Full structure (20/20)", all(r['score']['responseStructure'] == 20 for r in results)),
        ("Avg response time < 10s", all(sum(r['response_times'])/len(r['response_times']) < 10 for r in results if r['response_times'])),
        ("Max response time < 25s", all(max(r['response_times']) < 25 for r in results if r['response_times'])),
        ("All scores >= 80", all(r['score']['total'] >= 80 for r in results)),
        ("All scores = 100", all(r['score']['total'] == 100 for r in results)),
    ]
    
    for label, passed in checks:
        status = "PASS" if passed else "FAIL"
        icon = "✓" if passed else "✗"
        if not passed:
            all_pass = False
        print(f"  [{icon}] {label}: {status}")
    
    if all_pass:
        print(f"\nALL CHECKS PASSED — Ready for competition submission!")
    else:
        print(f"\nSome checks failed — review the details above.")


if __name__ == "__main__":
    main()
