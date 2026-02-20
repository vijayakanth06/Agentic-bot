"""
Dynamic Honeypot Tester - Matches EXACT Platform Behavior
==========================================================
Uses GROQ LLM as a dynamic SCAMMER to interact with the honeypot API.
Matches the EXACT platform request format, sender conventions, and scoring function.

Platform behavior:
  - Sends metadata (channel, language, locale) - NOT persona
  - Conversation history uses sender="scammer" and sender="user" (NOT "agent")
  - Scoring uses evaluate_final_output() from competition docs
  - 15 scenarios x 10 turns = 150 API calls
  - Each scenario has fakeData the scammer drops during conversation

Usage:
    python test_dynamic.py                    # Run all 15 scenarios
    python test_dynamic.py bank_fraud         # Run single scenario
    python test_dynamic.py --turns 5          # Custom turn count
"""

import os
import sys
import json
import time
import uuid
import random
import requests
from datetime import datetime, timezone

# ── Configuration ─────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
API_KEY = os.environ.get("TEST_API_KEY", "")
BASE_URL = os.environ.get("TEST_URL", "http://localhost:8001")
SCAMMER_MODEL = "llama-3.1-8b-instant"   # Fast model for scammer generation
NUM_TURNS = 10                            # Competition uses 10
DELAY_BETWEEN_TURNS = 1.5                 # Rate limit safety
DELAY_BETWEEN_SCENARIOS = 3.0

# ── The 15 Scenarios (matching competition evaluation) ────
# Each has fakeData that the scammer must drop during conversation.
# The scoring function checks if these exact values appear in extractedIntelligence.
SCENARIOS = [
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "initialMessage": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "bankAccount": "50100489372615",
            "upiId": "sbi.service@ybl",
            "phoneNumber": "+91-9876543210",
            "phishingLink": "http://sbi-secure-verify.com/login"
        },
        "scammer_prompt": "You are a scammer pretending to be from SBI bank fraud department. Your name is Mr. Verma. The victim's account has been 'compromised' and will be blocked. You must share these details naturally across the conversation:\n- Your callback number: +91-9876543210 (mention in turn 1-3)\n- Verification link: http://sbi-secure-verify.com/login (mention in turn 3-5)\n- UPI for security deposit: sbi.service@ybl (mention in turn 5-7)\n- Reference account: 50100489372615 (mention in turn 7-9)\nKeep messages SHORT (2-3 sentences). Sound professional but urgent."
    },
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "scamType": "upi_fraud",
        "initialMessage": "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details. This is from official customer support.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "upiId": "paytm.refund@paytm",
            "phoneNumber": "8765432109",
            "bankAccount": "6011238947562301",
            "phishingLink": "https://paytm-cashback-claim.in/verify"
        },
        "scammer_prompt": "You are a Paytm customer support scammer named Rohit. The victim won cashback of Rs. 5000 and needs to verify UPI to claim it. Drop these details naturally:\n- Your WhatsApp number: 8765432109 (turn 1-3)\n- UPI for verification: paytm.refund@paytm (turn 3-5)\n- Claim page: https://paytm-cashback-claim.in/verify (turn 5-7)\n- Bank account for NEFT: 6011238947562301 (turn 7-9)\nBe enthusiastic about the prize. Push urgency."
    },
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "initialMessage": "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com",
            "phoneNumber": "8877665544",
            "bankAccount": "6789012345678901"
        },
        "scammer_prompt": "You are running a fake Amazon deal scam. Victim 'won' an iPhone 15 Pro for Rs 999. Drop these naturally:\n- The phishing link http://amaz0n-deals.fake-site.com/claim?id=12345 was in the first message (repeat if needed)\n- Support email: offers@fake-amazon-deals.com (turn 2-4)\n- Customer care number: 8877665544 (turn 3-5)\n- Payment account: 6789012345678901 (turn 6-8)\nCreate urgency about the deal expiring."
    },
    {
        "scenarioId": "kyc_fraud",
        "name": "KYC Verification Scam",
        "scamType": "kyc_scam",
        "initialMessage": "Dear customer, your bank KYC is incomplete. Your account will be permanently blocked within 24 hours. Complete KYC immediately to avoid disruption of services.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "7654321098",
            "phishingLink": "http://kyc-update-india.com/verify-now",
            "upiId": "kyc.update@oksbi",
            "bankAccount": "3210567894561230"
        },
        "scammer_prompt": "You are from 'RBI KYC Department' named Pradeep. The victim's KYC is expiring and their account will be blocked. Drop details:\n- KYC helpline: 7654321098 (turn 1-3)\n- KYC update link: http://kyc-update-india.com/verify-now (turn 3-5)\n- Processing fee UPI: kyc.update@oksbi for Rs 99 (turn 5-7)\n- Verification deposit account: 3210567894561230 (turn 7-9)\nQuote fake RBI regulations. Be bureaucratic."
    },
    {
        "scenarioId": "job_scam",
        "name": "Job Fraud Detection",
        "scamType": "job_scam",
        "initialMessage": "Dear candidate, congratulations! You have been shortlisted for a Work From Home position at Amazon India. Salary: Rs. 30,000/month. Limited positions available. Register immediately.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "9123456780",
            "phishingLink": "http://amazon-jobs-india.com/apply",
            "upiId": "hr.recruit@paytm",
            "bankAccount": "5678901234567890"
        },
        "scammer_prompt": "You are HR recruiter Ananya from 'Amazon India Hiring Team'. Offering WFH data entry job at Rs 30,000/month. Drop details:\n- HR line: 9123456780 (turn 1-3)\n- Application portal: http://amazon-jobs-india.com/apply (turn 3-5)\n- Registration fee UPI: hr.recruit@paytm Rs 2000 (turn 5-7)\n- Or bank transfer: 5678901234567890 (turn 7-9)\nSound professional. Only 3 positions left."
    },
    {
        "scenarioId": "lottery_scam",
        "name": "Lottery Prize Scam",
        "scamType": "lottery_scam",
        "initialMessage": "CONGRATULATIONS! Your mobile number has won Rs. 25,00,000 in the India Digital Lottery! Winner ID: IDL-2026-78432. Contact the claims office immediately to receive your prize.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "9988776655",
            "phishingLink": "http://india-mega-lottery.com/winner",
            "upiId": "lottery.claim@ybl",
            "bankAccount": "7890123456789012"
        },
        "scammer_prompt": "You are from the 'India Digital Lottery Commission', Mr. David Williams. Victim won Rs 25 lakh. Drop details:\n- Claims office: 9988776655 (turn 1-3)\n- Winner verification page: http://india-mega-lottery.com/winner (turn 3-5)\n- Processing fee UPI: lottery.claim@ybl Rs 5000 (turn 5-7)\n- Alternative bank account: 7890123456789012 (turn 7-9)\nBe very excited and congratulatory."
    },
    {
        "scenarioId": "electricity_bill",
        "name": "Electricity Bill Scam",
        "scamType": "electricity_scam",
        "initialMessage": "ALERT: Your electricity bill of Rs. 4,850 is overdue. Power supply will be disconnected within 2 hours. Pay immediately to avoid disconnection. Contact our helpline.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "9922334455",
            "phishingLink": "http://tneb-bill-pay.com/urgent",
            "upiId": "eb.payment@ybl",
            "bankAccount": "5432109876543210"
        },
        "scammer_prompt": "You are from 'TNEB Bill Collection', operator Anand. The victim's electricity bill is overdue, power cut in 2 hours. Drop details:\n- Emergency helpline: 9922334455 (turn 1-3)\n- Payment portal: http://tneb-bill-pay.com/urgent (turn 3-5)\n- Quick pay UPI: eb.payment@ybl Rs 4850 (turn 5-7)\n- RTGS account: 5432109876543210 (turn 7-9)\nExtreme time pressure. Lineman is on the way."
    },
    {
        "scenarioId": "govt_scheme",
        "name": "Government Scheme Fraud",
        "scamType": "govt_scheme",
        "initialMessage": "Dear citizen, you are eligible for PM Kisan Samman Nidhi benefit of Rs. 6,000 yearly. Your Aadhaar is pre-verified. Complete registration to start receiving payments.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "8833445566",
            "phishingLink": "http://pm-kisan-yojana.com/register",
            "upiId": "pmkisan.reg@ybl",
            "bankAccount": "6543210987654321"
        },
        "scammer_prompt": "You are 'Government e-Seva Agent' Dinesh from the district collector's office. Victim is eligible for PM Kisan scheme. Drop details:\n- e-Seva helpline: 8833445566 (turn 1-3)\n- Registration: http://pm-kisan-yojana.com/register (turn 3-5)\n- Processing fee UPI: pmkisan.reg@ybl Rs 499 (turn 5-7)\n- Or deposit to account: 6543210987654321 (turn 7-9)\nSound helpful and government-official-like."
    },
    {
        "scenarioId": "crypto_investment",
        "name": "Crypto Investment Scam",
        "scamType": "crypto_investment",
        "initialMessage": "Exclusive opportunity! Join our certified crypto trading group. Guaranteed 300% returns in 90 days. RBI approved investment scheme. Minimum investment just Rs. 10,000.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "7788996655",
            "phishingLink": "http://gold-invest-india.com/start",
            "upiId": "invest.gold@oksbi",
            "bankAccount": "9876543210987654"
        },
        "scammer_prompt": "You are 'Financial Advisor Rakesh' from 'Golden Trust Investments'. Offering crypto/gold investment with 300% returns. Drop details:\n- Advisory helpline: 7788996655 (turn 1-3)\n- Investment portal: http://gold-invest-india.com/start (turn 3-5)\n- Quick invest UPI: invest.gold@oksbi (turn 5-7)\n- Main investment account: 9876543210987654 (turn 7-9)\nCite past investor success stories. Sound knowledgeable."
    },
    {
        "scenarioId": "customs_parcel",
        "name": "Customs Parcel Fraud",
        "scamType": "customs_fraud",
        "initialMessage": "NOTICE: A parcel addressed to you is held at Delhi International Cargo Terminal. Contents flagged as suspicious. Pay customs duty immediately or face legal action.",
        "metadata": {"channel": "Phone", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "9900887766",
            "phishingLink": "http://india-customs-clearance.com/pay",
            "upiId": "customs.fee@ybl",
            "bankAccount": "8901234567890123"
        },
        "scammer_prompt": "You are 'Customs Officer Rajan' from Delhi International Cargo Terminal. Victim's parcel is held with suspicious contents. Drop details:\n- Customs helpdesk: 9900887766 (turn 1-3)\n- Clearance form: http://india-customs-clearance.com/pay (turn 3-5)\n- Duty payment UPI: customs.fee@ybl Rs 8000 (turn 5-7)\n- Clearance account: 8901234567890123 (turn 7-9)\nQuote AWB tracking numbers. Sound official."
    },
    {
        "scenarioId": "tech_support",
        "name": "Tech Support Scam",
        "scamType": "tech_support",
        "initialMessage": "SECURITY ALERT: Your device has been infected with critical malware. Your personal data and banking information are at risk. Contact Microsoft Security Team immediately.",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "9900112233",
            "phishingLink": "http://remote-fix-india.com/download",
            "upiId": "tech.support@axl",
            "bankAccount": "2345678901234567"
        },
        "scammer_prompt": "You are 'Microsoft Security Team' technician Kevin. Victim's device has malware that's stealing bank data. Drop details:\n- Tech support: 9900112233 (turn 1-3)\n- Security tool: http://remote-fix-india.com/download (turn 3-5)\n- Service charge UPI: tech.support@axl Rs 3500 (turn 5-7)\n- Premium support account: 2345678901234567 (turn 7-9)\nSound like urgent IT professional."
    },
    {
        "scenarioId": "loan_approval",
        "name": "Loan Approval Scam",
        "scamType": "loan_approval",
        "initialMessage": "Congratulations! Your personal loan of Rs. 5,00,000 has been pre-approved at just 5.5% interest rate. No documentation required. Process your loan disbursement immediately.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "9811223344",
            "phishingLink": "http://instant-loan-india.com/apply",
            "upiId": "loan.process@ybl",
            "bankAccount": "1122334455667788"
        },
        "scammer_prompt": "You are 'Loan Officer Sharma' from a major NBFC. Victim's Rs 5 lakh personal loan is pre-approved at 5.5%. Drop details:\n- Loan helpline: 9811223344 (turn 1-3)\n- Application portal: http://instant-loan-india.com/apply (turn 3-5)\n- Processing fee UPI: loan.process@ybl Rs 3000 (turn 5-7)\n- Stamp duty account: 1122334455667788 (turn 7-9)\nSound professional. Quote loan ID and EMI amounts."
    },
    {
        "scenarioId": "income_tax",
        "name": "Income Tax Scam",
        "scamType": "income_tax",
        "initialMessage": "NOTICE: Income Tax Department has identified discrepancies in your ITR filing. Your PAN will be deactivated within 48 hours. Respond immediately to resolve this matter.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "9922114433",
            "phishingLink": "http://it-dept-notice.in/resolve",
            "upiId": "tax.penalty@oksbi",
            "bankAccount": "2233445566778899"
        },
        "scammer_prompt": "You are from 'Income Tax Department CPC Bangalore'. Victim's ITR has discrepancies and PAN will be deactivated. Drop details:\n- IT helpline: 9922114433 (turn 1-3)\n- Notice resolution: http://it-dept-notice.in/resolve (turn 3-5)\n- Penalty payment UPI: tax.penalty@oksbi (turn 5-7)\n- Settlement account: 2233445566778899 (turn 7-9)\nQuote section numbers. Sound authoritative."
    },
    {
        "scenarioId": "refund_scam",
        "name": "Refund Fraud Detection",
        "scamType": "refund_scam",
        "initialMessage": "Dear customer, your refund of Rs. 3,499 for order #FLK-78234 has been processed but failed due to incorrect bank details. Please update your details to receive the refund.",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "7766554433",
            "phishingLink": "http://refund-claim-india.com/process",
            "upiId": "refund.process@paytm",
            "bankAccount": "3456789012345678"
        },
        "scammer_prompt": "You are 'Flipkart Refund Department' agent Sanjay. Victim's Rs 3499 refund failed due to wrong bank details. Then you'll 'accidentally' send Rs 34,999 instead. Drop details:\n- Refund helpline: 7766554433 (turn 1-3)\n- Refund status: http://refund-claim-india.com/process (turn 3-5)\n- Return excess via UPI: refund.process@paytm (turn 5-7)\n- Or NEFT to: 3456789012345678 (turn 7-9)\nApologize for the 'error' but insist on getting excess back."
    },
    {
        "scenarioId": "insurance_fraud",
        "name": "Insurance Fraud Detection",
        "scamType": "insurance_fraud",
        "initialMessage": "Dear policyholder, your LIC policy no. 812345678 has a maturity bonus of Rs. 2,50,000 pending. Contact us immediately to claim before the deadline expires.",
        "metadata": {"channel": "Phone", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "8811223344",
            "phishingLink": "http://lic-policy-renew.com/pay",
            "upiId": "lic.premium@oksbi",
            "bankAccount": "4321098765432109"
        },
        "scammer_prompt": "You are 'LIC Agent Ramesh' from the regional branch. Victim's policy has a Rs 2.5 lakh maturity bonus pending but needs premium payment. Drop details:\n- Agent direct line: 8811223344 (turn 1-3)\n- Premium payment: http://lic-policy-renew.com/pay (turn 3-5)\n- Quick payment UPI: lic.premium@oksbi Rs 12750 (turn 5-7)\n- LIC premium account: 4321098765432109 (turn 7-9)\nQuote policy numbers. Sound concerned about victim losing their investment."
    },
]


# ── EXACT Platform Scoring Function ───────────────────────
# This is the EXACT evaluate_final_output() from the competition docs
def evaluate_final_output(final_output, scenario, conversation_history):
    """Evaluate final output using the EXACT same logic as the platform evaluator."""
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

    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])

        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score['intelligenceExtraction'] += 10
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                score['intelligenceExtraction'] += 10

    score['intelligenceExtraction'] = min(score['intelligenceExtraction'], 40)

    # 3. Engagement Quality (20 points)
    metrics = final_output.get('engagementMetrics', {})
    duration = metrics.get('engagementDurationSeconds', 0)
    messages = metrics.get('totalMessagesExchanged', 0)

    if duration > 0:
        score['engagementQuality'] += 5
    if duration > 60:
        score['engagementQuality'] += 5
    if messages > 0:
        score['engagementQuality'] += 5
    if messages >= 5:
        score['engagementQuality'] += 5

    # 4. Response Structure (20 points)
    required_fields = ['status', 'scamDetected', 'extractedIntelligence']
    optional_fields = ['engagementMetrics', 'agentNotes']

    for field in required_fields:
        if field in final_output:
            score['responseStructure'] += 5

    for field in optional_fields:
        if field in final_output and final_output[field]:
            score['responseStructure'] += 2.5

    score['responseStructure'] = min(score['responseStructure'], 20)

    # Calculate total
    score['total'] = sum([
        score['scamDetection'],
        score['intelligenceExtraction'],
        score['engagementQuality'],
        score['responseStructure']
    ])

    return score


# ── GROQ Scammer Client ──────────────────────────────────
def get_groq_client():
    from groq import Groq
    return Groq(api_key=GROQ_API_KEY)


def generate_scammer_message(client, scenario, conversation, turn):
    """Generate a dynamic scammer message using GROQ LLM.
    The scammer drops fakeData values naturally during conversation."""
    messages = [
        {"role": "system", "content": scenario["scammer_prompt"]},
        {"role": "system", "content": (
            f"This is turn {turn + 1} of {scenario['maxTurns']}. "
            f"{'Start the scam introduction.' if turn == 0 else 'Continue based on what the victim said. Stay in character.'}\n\n"
            "RULES:\n"
            "- Keep responses SHORT (2-4 sentences max, like real phone/SMS)\n"
            "- DO NOT break character\n"
            "- DO NOT use markdown formatting\n"
            "- When sharing phone numbers, UPI IDs, bank accounts, or URLs, include them EXACTLY as specified in your instructions\n"
            "- Respond naturally to what the victim says"
        )},
    ]

    # Add conversation history - scammer is "assistant", honeypot victim is "user"
    for msg in conversation:
        if msg["sender"] == "scammer":
            messages.append({"role": "assistant", "content": msg["text"]})
        else:
            messages.append({"role": "user", "content": msg["text"]})

    try:
        resp = client.chat.completions.create(
            model=SCAMMER_MODEL,
            messages=messages,
            temperature=0.8,
            max_tokens=200,
            top_p=0.95,
        )
        text = resp.choices[0].message.content.strip()
        text = text.replace("**", "").replace("*", "").strip('"').strip("'")
        if not text:
            # Fallback with fakeData embedded
            fd = scenario["fakeData"]
            parts = []
            if "phoneNumber" in fd:
                parts.append(f"Call us at {fd['phoneNumber']}")
            if "upiId" in fd:
                parts.append(f"Send to {fd['upiId']}")
            return ". ".join(parts) or "Please respond urgently, this is very important."
        return text
    except Exception as e:
        print(f"  [SCAMMER LLM ERROR] {e}")
        # Fallback: drop fakeData directly
        fd = scenario["fakeData"]
        options = []
        if "phoneNumber" in fd:
            options.append(f"Please call us back at {fd['phoneNumber']} for immediate assistance.")
        if "upiId" in fd:
            options.append(f"Please transfer the amount to {fd['upiId']} for verification.")
        if "phishingLink" in fd:
            options.append(f"Visit {fd['phishingLink']} to complete the process.")
        if "bankAccount" in fd:
            options.append(f"Transfer to account {fd['bankAccount']} immediately.")
        return random.choice(options) if options else "Sir please respond, this is very urgent."


# ── Honeypot API Client (matches EXACT platform format) ──
def call_honeypot(session_id, message, conversation_history, metadata, turn):
    """Send a message to the honeypot API using the EXACT platform request format.

    Key differences from before:
    - Sends metadata (channel, language, locale) - NOT persona
    - Conversation history uses sender="user" for honeypot responses (NOT "agent")
    """
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": message,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
        },
        "conversationHistory": conversation_history,
        "metadata": metadata
        # NOTE: No "persona" field - the platform does NOT send persona
    }

    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
    }

    try:
        resp = requests.post(
            f"{BASE_URL}/api/honeypot",
            json=payload,
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Cannot connect to {BASE_URL}. Is the server running?")
        return None
    except Exception as e:
        print(f"  [HONEYPOT ERROR] {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"  Response: {e.response.text[:200]}")
        return None


# ── Single Scenario Runner ────────────────────────────────
def run_scenario(client, scenario, num_turns=NUM_TURNS):
    """Run a complete scenario matching EXACT platform behavior."""
    scenario_id = scenario["scenarioId"]
    session_id = str(uuid.uuid4())  # Platform uses UUID v4
    # Platform uses sender="scammer" and sender="user" (NOT "agent")
    conversation_history = []
    last_response = None
    start_time = time.time()

    print(f"\n{'='*70}")
    print(f"  SCENARIO: {scenario_id} ({scenario['name']})")
    print(f"  Session: {session_id}")
    print(f"  FakeData keys: {list(scenario['fakeData'].keys())}")
    print(f"{'='*70}")

    for turn in range(num_turns):
        # ── Generate scammer message ──
        if turn == 0:
            scammer_msg = scenario["initialMessage"]
        else:
            scammer_msg = generate_scammer_message(client, scenario, conversation_history, turn)

        print(f"\n  [Turn {turn+1}/{num_turns}]")
        print(f"  SCAMMER: {scammer_msg[:130]}{'...' if len(scammer_msg) > 130 else ''}")

        # ── Send to honeypot (EXACT platform format) ──
        response = call_honeypot(
            session_id, scammer_msg, conversation_history,
            scenario["metadata"], turn + 1
        )

        if response is None:
            print(f"  [FAILED] No response from honeypot")
            break

        # Platform checks for reply, message, or text (in that order)
        reply = response.get('reply') or response.get('message') or response.get('text') or "..."
        if isinstance(reply, dict):
            reply = reply.get('text', '...')
        print(f"  HONEYPOT: {reply[:130]}{'...' if len(reply) > 130 else ''}")

        # ── Update conversation history (platform format) ──
        # Platform uses sender="scammer" and sender="user"
        conversation_history.append({
            "sender": "scammer",
            "text": scammer_msg,
            "timestamp": str(int(time.time() * 1000))  # epoch ms as per docs
        })
        conversation_history.append({
            "sender": "user",  # Platform uses "user" NOT "agent"
            "text": reply,
            "timestamp": str(int(time.time() * 1000))
        })
        last_response = response

        if turn < num_turns - 1:
            time.sleep(DELAY_BETWEEN_TURNS)

    elapsed = time.time() - start_time

    # ── Score using EXACT platform function ──
    if last_response:
        final_score = evaluate_final_output(last_response, scenario, conversation_history)
    else:
        final_score = {'scamDetection': 0, 'intelligenceExtraction': 0,
                       'engagementQuality': 0, 'responseStructure': 0, 'total': 0}

    print(f"\n  {'~'*50}")
    print(f"  SCORE: {final_score['total']}/100")
    print(f"    Scam Detection:     {final_score['scamDetection']}/20")
    print(f"    Intel Extraction:   {final_score['intelligenceExtraction']}/40", end="")

    # Show which fakeData was/wasn't extracted
    if last_response:
        extracted = last_response.get('extractedIntelligence', {})
        key_mapping = {
            'bankAccount': 'bankAccounts', 'upiId': 'upiIds',
            'phoneNumber': 'phoneNumbers', 'phishingLink': 'phishingLinks',
            'emailAddress': 'emailAddresses'
        }
        missed = []
        found = []
        for fk, fv in scenario['fakeData'].items():
            ok = key_mapping.get(fk, fk)
            vals = extracted.get(ok, [])
            if isinstance(vals, list) and any(fv in str(v) for v in vals):
                found.append(fk)
            else:
                missed.append(f"{fk}={fv}")
        if missed:
            print(f"  [MISSED: {'; '.join(missed)}]")
        else:
            print(f"  [ALL FOUND]")
    else:
        print()

    print(f"    Engagement:         {final_score['engagementQuality']}/20")
    print(f"    Response Structure: {final_score['responseStructure']}/20")
    print(f"  Elapsed: {elapsed:.1f}s | Turns completed: {len(conversation_history)//2}/{num_turns}")

    # Show actual extracted intelligence
    if last_response:
        intel = last_response.get('extractedIntelligence', {})
        for k, v in intel.items():
            if v:
                print(f"    {k}: {v}")

    return {
        "scenario": scenario_id,
        "session_id": session_id,
        "score": final_score,
        "turns_completed": len(conversation_history) // 2,
        "elapsed_seconds": round(elapsed, 1),
        "final_response": last_response,
    }


# ── Main Test Runner ──────────────────────────────────────
def main():
    # Parse arguments
    target_scenario = None
    turns = NUM_TURNS

    skip_next = False
    for i, arg in enumerate(sys.argv[1:]):
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("--turns="):
            turns = int(arg.split("=")[1])
        elif arg == "--turns":
            if i + 1 < len(sys.argv) - 1:
                turns = int(sys.argv[i + 2])  # +2 because sys.argv[0] is script
                skip_next = True
        elif not arg.startswith("-"):
            target_scenario = arg

    print("+" + "="*58 + "+")
    print("|  DYNAMIC HONEYPOT TESTER - Platform-Accurate             |")
    print("|  Scammer: GROQ llama-3.1-8b-instant                     |")
    print("|  Honeypot: Your API                                      |")
    print("|  Scoring: EXACT platform evaluate_final_output()         |")
    print("+" + "="*58 + "+")
    print(f"\n  Server: {BASE_URL}")
    print(f"  Turns per scenario: {turns}")
    print(f"  API Key: {API_KEY[:8]}...{API_KEY[-4:]}")

    # Test server connectivity
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        health = resp.json()
        print(f"  Server health: {health.get('status', 'unknown')} | GROQ: {health.get('groq', False)}")
    except Exception:
        print(f"\n  [FATAL] Cannot connect to server at {BASE_URL}")
        print(f"  Start the server first: python -m uvicorn api.index:app --port 8001")
        sys.exit(1)

    # Initialize GROQ client for scammer
    try:
        client = get_groq_client()
        test_resp = client.chat.completions.create(
            model=SCAMMER_MODEL,
            messages=[{"role": "user", "content": "Say OK"}],
            max_tokens=5,
        )
        print(f"  Scammer LLM: OK ({SCAMMER_MODEL})")
    except Exception as e:
        print(f"\n  [FATAL] Cannot initialize GROQ client: {e}")
        sys.exit(1)

    # Select scenarios
    if target_scenario:
        scenarios = [s for s in SCENARIOS if s["scenarioId"] == target_scenario]
        if not scenarios:
            print(f"\n  [ERROR] Unknown scenario: {target_scenario}")
            print(f"  Available: {', '.join(s['scenarioId'] for s in SCENARIOS)}")
            sys.exit(1)
    else:
        scenarios = SCENARIOS

    print(f"  Scenarios: {len(scenarios)}")
    print(f"\n  Starting in 2 seconds...")
    time.sleep(2)

    # Run all scenarios
    results = []
    total_start = time.time()

    for i, scenario in enumerate(scenarios):
        result = run_scenario(client, scenario, num_turns=turns)
        results.append(result)
        if i < len(scenarios) - 1:
            time.sleep(DELAY_BETWEEN_SCENARIOS)

    total_elapsed = time.time() - total_start

    # ── Summary ──────────────────────────────────────────
    print(f"\n\n{'='*70}")
    print(f"  FINAL RESULTS SUMMARY")
    print(f"{'='*70}")

    total_score = 0
    perfect_count = 0
    cat_totals = {"scam": 0, "intel": 0, "engage": 0, "struct": 0}

    for r in results:
        s = r["score"]
        cat_totals["scam"] += s["scamDetection"]
        cat_totals["intel"] += s["intelligenceExtraction"]
        cat_totals["engage"] += s["engagementQuality"]
        cat_totals["struct"] += s["responseStructure"]

        status = "PASS" if s["total"] >= 100 else f"{s['total']}"
        total_score += s["total"]
        if s["total"] >= 100:
            perfect_count += 1

        missing = ""
        if s["intelligenceExtraction"] < 40:
            missing = f" [intel:{s['intelligenceExtraction']}/40]"
        print(f"  {r['scenario']:<22} {status:>6}  (det:{s['scamDetection']:.0f} intel:{s['intelligenceExtraction']:.0f} engage:{s['engagementQuality']:.0f} struct:{s['responseStructure']:.0f}){missing}")

    n = len(results)
    avg = total_score / n if n > 0 else 0

    print(f"\n  {'~'*50}")
    print(f"  Perfect Scores: {perfect_count}/{n}")
    print(f"  Average Score:  {avg:.1f}/100")
    print(f"  Total Time:     {total_elapsed:.1f}s")
    print(f"\n  Category Averages:")
    print(f"    Scam Detection:     {cat_totals['scam']/n:.1f}/20")
    print(f"    Intel Extraction:   {cat_totals['intel']/n:.1f}/40")
    print(f"    Engagement:         {cat_totals['engage']/n:.1f}/20")
    print(f"    Response Structure: {cat_totals['struct']/n:.1f}/20")

    # Save results
    output_file = "test_dynamic_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        summary = []
        for r in results:
            summary.append({
                "scenario": r["scenario"],
                "score": r["score"],
                "turns": r["turns_completed"],
                "elapsed": r["elapsed_seconds"],
            })
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "server": BASE_URL,
            "scammer_model": SCAMMER_MODEL,
            "turns_per_scenario": turns,
            "total_scenarios": n,
            "perfect_scores": perfect_count,
            "average_score": round(avg, 1),
            "results": summary,
        }, f, indent=2, ensure_ascii=False)

    print(f"\n  Results saved to {output_file}")

    if perfect_count == n:
        print(f"\n  ALL {n} SCENARIOS SCORED 100/100 - READY FOR SUBMISSION!")
        sys.exit(0)
    else:
        print(f"\n  {n - perfect_count} scenario(s) scored below 100 - review needed")
        sys.exit(1)


if __name__ == "__main__":
    main()
