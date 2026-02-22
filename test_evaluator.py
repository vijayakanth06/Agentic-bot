"""
Comprehensive Honeypot Evaluation Test Script
Simulates the EXACT evaluator scoring logic from the competition docs.
Tests all 3 sample scenarios with multi-turn conversation simulation.
"""

import requests
import uuid
import json
import time
import re
from datetime import datetime

# Configuration
ENDPOINT_URL = "https://agentic-bot-tau.vercel.app/api/honeypot"
API_KEY = "fae26946fc2015d9bd6f1ddbb447e2f7"

# All 3 sample test scenarios
TEST_SCENARIOS = [
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "initialMessage": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210"
        },
        # Simulated scammer follow-ups that include fakeData
        "scammerFollowUps": [
            "I am calling from SBI fraud department. My name is Rajesh Kumar. Your account ending 3456 has been flagged for suspicious activity.",
            "Yes sir, I am authorized officer ID SBI-12345. Please verify your identity. What is your registered mobile number?",
            "Sir, for verification I need to send you an OTP. My official number is +91-9876543210. You can call me back on this.",
            "Sir, there is a refund of Rs. 15,000 pending. To process it, I need your bank account number 1234567890123456 for cross-verification.",
            "Thank you sir. Now I need to verify the UPI linked to your account. The flagged UPI is scammer.fraud@fakebank. Can you confirm?",
            "Sir the refund will be processed within 24 hours. Please share the OTP that you will receive now.",
            "Sir please hurry, your account will be blocked soon. Can you check if you received the OTP?",
            "Sir this is very urgent. The RBI has issued a directive. We need to complete verification before 5 PM today.",
            "OK sir, one last thing. Please confirm your date of birth and full name as per bank records."
        ]
    },
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "scamType": "upi_fraud",
        "initialMessage": "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details. This is from official customer support.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109"
        },
        "scammerFollowUps": [
            "This is from Paytm official rewards team. Your cashback ID is PTM-2026-789. You were selected in our Republic Day offer.",
            "Sir, to verify your identity, can you share your Paytm registered mobile number? You can also reach us at +91-8765432109.",
            "Thank you. Now to release the cashback, please make a small verification payment of Rs. 99 to our official UPI: cashback.scam@fakeupi",
            "Sir this is a standard verification process. Once you pay Rs. 99, the Rs. 5000 cashback will be credited immediately to your account.",
            "Sir please hurry, this offer expires in 30 minutes. Many people are claiming this reward. Don't miss out!",
            "OK sir, you can also scan the QR code I will send. The UPI ID is cashback.scam@fakeupi. Please verify before sending.",
            "Sir the payment gateway is showing your transaction is pending. Can you try again? The UPI is cashback.scam@fakeupi",
            "Sir do not worry, this is 100% safe. Paytm's terms and conditions apply. You will see Rs. 5000 in 5 minutes after payment.",
            "Sir this is the last reminder. Offer closing at midnight. Shall I extend it for 10 more minutes for you?"
        ]
    },
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "initialMessage": "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com"
        },
        "scammerFollowUps": [
            "Dear customer, this is a verified offer from Amazon India. You can contact us at offers@fake-amazon-deals.com for any queries.",
            "Sir, only 5 units left! Click http://amaz0n-deals.fake-site.com/claim?id=12345 and fill in your delivery address to claim.",
            "This offer is part of Amazon's Great Indian Festival. You can verify at offers@fake-amazon-deals.com. Your claim ID is AMZ-2026-PROMO.",
            "Sir, you just need to pay Rs. 999 processing fee. After payment, iPhone 15 Pro 256GB will be delivered in 3-5 business days.",
            "Sir, please fill the form at http://amaz0n-deals.fake-site.com/claim?id=12345 with your name, address, and payment details.",
            "Sir many customers have already claimed. See the testimonials on our website. Your slot is being held for 5 more minutes.",
            "Sir, if you face any issues with the link, email us at offers@fake-amazon-deals.com and we will send you an alternate link.",
            "This is final notice. Your exclusive slot will be released in 2 minutes. Click http://amaz0n-deals.fake-site.com/claim?id=12345 NOW.",
            "Sir thank you for your interest. The offer is genuine. We are registered company. Your order will be confirmed once payment is done."
        ]
    }
]


def evaluate_final_output(final_output, scenario, conversation_history):
    """Evaluate final output using the EXACT same logic as the competition evaluator."""
    
    score = {
        'scamDetection': 0,
        'intelligenceExtraction': 0,
        'engagementQuality': 0,
        'responseStructure': 0,
        'total': 0,
        'details': {}
    }
    
    # 1. Scam Detection (20 points)
    if final_output.get('scamDetected', False):
        score['scamDetection'] = 20
    score['details']['scamDetected'] = final_output.get('scamDetected', 'MISSING')
    
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
    
    intel_details = {}
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        
        matched = False
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                matched = True
                score['intelligenceExtraction'] += 10
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                matched = True
                score['intelligenceExtraction'] += 10
        
        intel_details[fake_key] = {
            'fakeValue': fake_value,
            'extractedField': output_key,
            'extractedValues': extracted_values,
            'matched': matched,
            'points': 10 if matched else 0
        }
    
    score['intelligenceExtraction'] = min(score['intelligenceExtraction'], 40)
    score['details']['intelligence'] = intel_details
    
    # 3. Engagement Quality (20 points)
    metrics = final_output.get('engagementMetrics', {})
    duration = metrics.get('engagementDurationSeconds', 0)
    messages = metrics.get('totalMessagesExchanged', 0)
    
    engagement_details = {
        'engagementMetricsPresent': bool(metrics),
        'duration': duration,
        'messages': messages,
        'durationGt0': duration > 0,
        'durationGt60': duration > 60,
        'messagesGt0': messages > 0,
        'messagesGte5': messages >= 5
    }
    
    if duration > 0:
        score['engagementQuality'] += 5
    if duration > 60:
        score['engagementQuality'] += 5
    if messages > 0:
        score['engagementQuality'] += 5
    if messages >= 5:
        score['engagementQuality'] += 5
    
    score['details']['engagement'] = engagement_details
    
    # 4. Response Structure (20 points)
    required_fields = ['status', 'scamDetected', 'extractedIntelligence']
    optional_fields = ['engagementMetrics', 'agentNotes']
    
    structure_details = {}
    for field in required_fields:
        present = field in final_output
        structure_details[field] = {'present': present, 'points': 5 if present else 0}
        if present:
            score['responseStructure'] += 5
    
    for field in optional_fields:
        present = field in final_output and final_output[field]
        structure_details[field] = {'present': present, 'points': 2.5 if present else 0}
        if present:
            score['responseStructure'] += 2.5
    
    score['responseStructure'] = min(score['responseStructure'], 20)
    score['details']['structure'] = structure_details
    
    # Calculate total
    score['total'] = sum([
        score['scamDetection'],
        score['intelligenceExtraction'],
        score['engagementQuality'],
        score['responseStructure']
    ])
    
    return score


def test_scenario(scenario, verbose=True):
    """Run a complete multi-turn test for one scenario."""
    session_id = str(uuid.uuid4())
    conversation_history = []
    
    headers = {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
    }
    
    if verbose:
        print(f"\n{'='*70}")
        print(f"SCENARIO: {scenario['name']} ({scenario['scenarioId']})")
        print(f"{'='*70}")
    
    max_turns = scenario['maxTurns']
    follow_ups = scenario.get('scammerFollowUps', [])
    last_response = None
    all_responses = []
    turn_times = []
    errors = []
    
    for turn in range(1, max_turns + 1):
        # Get scammer message
        if turn == 1:
            scammer_message = scenario['initialMessage']
        else:
            follow_idx = turn - 2  # 0-indexed for follow-ups
            if follow_idx < len(follow_ups):
                scammer_message = follow_ups[follow_idx]
            else:
                scammer_message = f"Sir please respond quickly, time is running out. Turn {turn}."
        
        # Prepare request
        message = {
            "sender": "scammer",
            "text": scammer_message,
            "timestamp": int(time.time() * 1000)  # epoch ms as integer (like evaluator)
        }
        
        request_body = {
            'sessionId': session_id,
            'message': message,
            'conversationHistory': conversation_history,
            'metadata': scenario['metadata']
        }
        
        if verbose:
            print(f"\n--- Turn {turn}/{max_turns} ---")
            print(f"  Scammer: {scammer_message[:100]}{'...' if len(scammer_message) > 100 else ''}")
        
        start_time = time.time()
        try:
            response = requests.post(
                ENDPOINT_URL,
                headers=headers,
                json=request_body,
                timeout=30
            )
            elapsed = time.time() - start_time
            turn_times.append(elapsed)
            
            if response.status_code != 200:
                error_msg = f"Turn {turn}: HTTP {response.status_code} - {response.text[:200]}"
                errors.append(error_msg)
                if verbose:
                    print(f"  ERROR: {error_msg}")
                continue
            
            response_data = response.json()
            all_responses.append(response_data)
            last_response = response_data
            
            # Extract reply
            honeypot_reply = response_data.get('reply') or \
                           response_data.get('message') or \
                           response_data.get('text')
            
            if not honeypot_reply:
                error_msg = f"Turn {turn}: No reply/message/text in response"
                errors.append(error_msg)
                if verbose:
                    print(f"  ERROR: {error_msg}")
                continue
            
            if verbose:
                print(f"  Honeypot: {honeypot_reply[:100]}{'...' if len(honeypot_reply) > 100 else ''}")
                print(f"  Time: {elapsed:.2f}s")
            
            # Update conversation history (same as evaluator)
            conversation_history.append(message)
            conversation_history.append({
                'sender': 'user',
                'text': honeypot_reply,
                'timestamp': int(time.time() * 1000)
            })
            
        except requests.exceptions.Timeout:
            errors.append(f"Turn {turn}: TIMEOUT (>30s)")
            if verbose:
                print(f"  TIMEOUT!")
        except Exception as e:
            errors.append(f"Turn {turn}: {str(e)}")
            if verbose:
                print(f"  ERROR: {e}")
    
    # Score the last response (same as evaluator)
    if last_response:
        score = evaluate_final_output(last_response, scenario, conversation_history)
    else:
        score = {'scamDetection': 0, 'intelligenceExtraction': 0, 
                 'engagementQuality': 0, 'responseStructure': 0, 'total': 0, 'details': {}}
    
    # Additional response quality checks
    quality_checks = {
        'all_turns_completed': len(all_responses) == max_turns,
        'turns_completed': len(all_responses),
        'avg_response_time': round(sum(turn_times) / len(turn_times), 2) if turn_times else 0,
        'max_response_time': round(max(turn_times), 2) if turn_times else 0,
        'all_under_30s': all(t < 30 for t in turn_times),
        'errors': errors,
        'reply_field_present': all('reply' in r or 'message' in r or 'text' in r for r in all_responses),
        'status_200_all': len(all_responses) == max_turns,
    }
    
    # Check for AI identity leaks
    ai_leak = False
    for r in all_responses:
        reply = (r.get('reply') or r.get('message') or r.get('text') or '').lower()
        if any(x in reply for x in ['language model', 'as an ai', 'i\'m an ai', 'artificial intelligence', 'openai', 'groq', 'llama']):
            ai_leak = True
            break
    quality_checks['no_ai_identity_leak'] = not ai_leak
    
    # Check for repeated replies
    replies = [r.get('reply') or r.get('message') or r.get('text') or '' for r in all_responses]
    unique_replies = set(replies)
    quality_checks['all_replies_unique'] = len(unique_replies) == len(replies)
    quality_checks['unique_reply_ratio'] = f"{len(unique_replies)}/{len(replies)}"
    
    return {
        'scenario': scenario['name'],
        'scenarioId': scenario['scenarioId'],
        'score': score,
        'quality': quality_checks,
        'lastResponse': last_response
    }


def run_all_tests():
    """Run all scenarios and compute final weighted score."""
    print("=" * 70)
    print("AGENTIC HONEYPOT — COMPREHENSIVE EVALUATION")
    print(f"Endpoint: {ENDPOINT_URL}")
    print(f"Time: {datetime.now().isoformat()}")
    print("=" * 70)
    
    results = []
    for scenario in TEST_SCENARIOS:
        result = test_scenario(scenario)
        results.append(result)
    
    # Final score (weighted average — equal weights for 3 scenarios)
    total_weight = sum(s['weight'] for s in TEST_SCENARIOS)
    weighted_score = 0
    
    print("\n" + "=" * 70)
    print("DETAILED SCORE BREAKDOWN")
    print("=" * 70)
    
    for i, result in enumerate(results):
        scenario = TEST_SCENARIOS[i]
        s = result['score']
        weight = scenario['weight'] / total_weight
        
        print(f"\n{'─'*60}")
        print(f"Scenario: {result['scenario']} (weight: {scenario['weight']}/{total_weight} = {weight:.2%})")
        print(f"{'─'*60}")
        print(f"  Scam Detection:        {s['scamDetection']:5.1f} / 20")
        print(f"  Intelligence Extract:   {s['intelligenceExtraction']:5.1f} / 40")
        print(f"  Engagement Quality:     {s['engagementQuality']:5.1f} / 20")
        print(f"  Response Structure:     {s['responseStructure']:5.1f} / 20")
        print(f"  SCENARIO TOTAL:        {s['total']:5.1f} / 100")
        
        # Intelligence detail
        if 'intelligence' in s.get('details', {}):
            print(f"\n  Intelligence Detail:")
            for key, val in s['details']['intelligence'].items():
                status = "MATCHED" if val['matched'] else "MISSED"
                print(f"    {key}: {status}")
                print(f"      Fake: {val['fakeValue']}")
                print(f"      Extracted: {val['extractedValues'][:3] if isinstance(val['extractedValues'], list) else val['extractedValues']}")
        
        # Engagement detail
        if 'engagement' in s.get('details', {}):
            eng = s['details']['engagement']
            print(f"\n  Engagement Detail:")
            print(f"    Duration: {eng['duration']}s (>0: {eng['durationGt0']}, >60: {eng['durationGt60']})")
            print(f"    Messages: {eng['messages']} (>0: {eng['messagesGt0']}, >=5: {eng['messagesGte5']})")
        
        # Structure detail
        if 'structure' in s.get('details', {}):
            print(f"\n  Structure Detail:")
            for field, val in s['details']['structure'].items():
                status = "PRESENT" if val['present'] else "MISSING"
                print(f"    {field}: {status} ({val['points']} pts)")
        
        # Quality checks
        q = result['quality']
        print(f"\n  Quality Checks:")
        print(f"    Turns completed: {q['turns_completed']}/10")
        print(f"    Avg response time: {q['avg_response_time']}s")
        print(f"    Max response time: {q['max_response_time']}s")
        print(f"    All under 30s: {q['all_under_30s']}")
        print(f"    No AI leak: {q['no_ai_identity_leak']}")
        print(f"    Unique replies: {q['unique_reply_ratio']}")
        if q['errors']:
            print(f"    ERRORS: {q['errors']}")
        
        weighted_score += s['total'] * weight
    
    # Final summary
    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    
    print(f"\n{'Scenario':<30} {'Score':>10} {'Weight':>10} {'Contribution':>15}")
    print(f"{'─'*65}")
    for i, result in enumerate(results):
        scenario = TEST_SCENARIOS[i]
        s = result['score']
        weight = scenario['weight'] / total_weight
        contribution = s['total'] * weight
        print(f"{result['scenario']:<30} {s['total']:>8.1f}/100 {weight:>9.2%} {contribution:>12.2f}/100")
    
    print(f"{'─'*65}")
    print(f"{'WEIGHTED FINAL SCORE':<30} {'':>10} {'':>10} {weighted_score:>12.2f}/100")
    
    # CHECKLIST
    print("\n" + "=" * 70)
    print("SUBMISSION CHECKLIST")
    print("=" * 70)
    
    checks = [
        ("Endpoint publicly accessible", True),
        ("API returns 200 for valid requests", all(r['quality']['status_200_all'] for r in results)),
        ("Response includes reply field", all(r['quality']['reply_field_present'] for r in results)),
        ("Response time under 30s", all(r['quality']['all_under_30s'] for r in results)),
        ("Handles 10 sequential requests", all(r['quality']['turns_completed'] == 10 for r in results)),
        ("No AI identity leaks", all(r['quality']['no_ai_identity_leak'] for r in results)),
        ("All replies unique (no repetition)", all(r['quality']['all_replies_unique'] for r in results)),
        ("scamDetected: true", all(r['score']['scamDetection'] == 20 for r in results)),
        ("extractedIntelligence present", all('extractedIntelligence' in (r['lastResponse'] or {}) for r in results)),
        ("engagementMetrics present", all('engagementMetrics' in (r['lastResponse'] or {}) for r in results)),
        ("agentNotes present", all('agentNotes' in (r['lastResponse'] or {}) for r in results)),
        ("status field present", all('status' in (r['lastResponse'] or {}) for r in results)),
    ]
    
    all_pass = True
    for label, passed in checks:
        icon = "PASS" if passed else "FAIL"
        print(f"  [{icon}] {label}")
        if not passed:
            all_pass = False
    
    print(f"\n{'ALL CHECKS PASSED' if all_pass else 'SOME CHECKS FAILED'}!")
    print(f"\nPREDICTED SCORE: {weighted_score:.1f}/100")
    
    return weighted_score, results


if __name__ == "__main__":
    final_score, results = run_all_tests()
