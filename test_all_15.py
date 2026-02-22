"""
Comprehensive 15-Scenario Honeypot Evaluation Test
Simulates the EXACT evaluator scoring with all 15 competition scam types.
Each scenario: 10 turns, realistic scammer follow-ups with fakeData embedded.
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

# ============================================================================
# ALL 15 SCENARIOS
# ============================================================================

TEST_SCENARIOS = [
    # 1. BANK FRAUD
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud",
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

    # 2. UPI FRAUD
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud",
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
            "Sir this is a standard verification process. Once you pay Rs. 99, the Rs. 5000 cashback will be credited immediately.",
            "Sir please hurry, this offer expires in 30 minutes. Many people are claiming this reward.",
            "OK sir, you can also scan the QR code I will send. The UPI ID is cashback.scam@fakeupi.",
            "Sir the payment gateway is showing your transaction is pending. Can you try again?",
            "Sir do not worry, this is 100% safe. Paytm's terms and conditions apply.",
            "Sir this is the last reminder. Offer closing at midnight."
        ]
    },

    # 3. PHISHING
    {
        "scenarioId": "phishing",
        "name": "Phishing Link",
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
            "Sir, only 5 units left! Click http://amaz0n-deals.fake-site.com/claim?id=12345 and fill in your delivery address.",
            "This offer is part of Amazon's Great Indian Festival. You can verify at offers@fake-amazon-deals.com.",
            "Sir, you just need to pay Rs. 999 processing fee. After payment, iPhone 15 Pro will be delivered in 3-5 days.",
            "Sir, please fill the form at http://amaz0n-deals.fake-site.com/claim?id=12345 with name and payment details.",
            "Sir many customers have already claimed. See the testimonials on our website.",
            "Sir, if you face any issues with the link, email us at offers@fake-amazon-deals.com.",
            "This is final notice. Your exclusive slot will be released in 2 minutes.",
            "Sir the offer is genuine. We are a registered company. Your order will be confirmed once payment is done."
        ]
    },

    # 4. KYC FRAUD
    {
        "scenarioId": "kyc_fraud",
        "name": "KYC Fraud",
        "scamType": "kyc_scam",
        "initialMessage": "ALERT: Your SIM card will be deactivated within 24 hours due to incomplete KYC verification. Update your Aadhaar details immediately to avoid disconnection. Reply NOW.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-7654321098",
            "emailAddress": "kyc.verify@faketel.com"
        },
        "scammerFollowUps": [
            "This is Jio KYC verification department. Your number has been flagged by TRAI for incomplete KYC. I am officer Priya Sharma.",
            "Sir, to keep your number active, please share your Aadhaar number and date of birth for re-verification.",
            "You can also call our helpline at +91-7654321098 for instant KYC update. This is our official verification number.",
            "Sir, we need to verify your PAN card as well. Please share your PAN number for cross-verification with TRAI records.",
            "Sir, you can also email your Aadhaar and PAN copies to kyc.verify@faketel.com for faster processing.",
            "Sir, only 6 hours remaining. After that your number will be permanently blocked and you will lose your number.",
            "Sir, please download our verification app from http://jio-kyc-verify.fakeapp.com and complete the process.",
            "Sir, for security I will send you an OTP. Please share it to confirm your identity.",
            "Sir, this is mandatory as per new TRAI guidelines. All numbers must be re-verified by this month end."
        ]
    },

    # 5. JOB SCAM
    {
        "scenarioId": "job_scam",
        "name": "Job Scam",
        "scamType": "job_scam",
        "initialMessage": "Dear Candidate, You have been shortlisted for a Data Entry position at Amazon India. Salary: Rs. 45,000/month. Work from home. Reply with your resume to confirm. Limited seats!",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-6543210987",
            "emailAddress": "hr.amazon.recruit@fakejobs.com"
        },
        "scammerFollowUps": [
            "Welcome! I am Anil from Amazon HR department. Your application ID is AMZN-HR-2026-456. Congratulations on being shortlisted.",
            "Sir, to proceed with onboarding, please share your full name, date of birth, and Aadhaar number for background verification.",
            "Sir you can also send your documents to hr.amazon.recruit@fakejobs.com. Our HR team will verify within 2 hours.",
            "Sir, there is a one-time registration fee of Rs. 2,500 for training materials and ID card. Please pay to proceed.",
            "Sir, you can contact our HR head at +91-6543210987 for any doubts. He will explain everything.",
            "Sir, payment can be made via UPI to amazon.hr.pay@fakebank or bank transfer. I will share account details.",
            "Sir, many candidates have already completed registration. Only 3 seats remaining in your batch.",
            "Sir, after payment you will receive your offer letter and joining date on email within 24 hours.",
            "Sir, this is a genuine Amazon opportunity. We have placed 500+ candidates this year. Please complete payment today."
        ]
    },

    # 6. LOTTERY SCAM
    {
        "scenarioId": "lottery_scam",
        "name": "Lottery Scam",
        "scamType": "lottery_scam",
        "initialMessage": "CONGRATULATIONS!! You have won Rs. 25,00,000 in the KBC Lucky Draw 2026! Your ticket number KBC-99887766. Contact us immediately to claim your prize!",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-5432109876",
            "bankAccount": "9876543210654321"
        },
        "scammerFollowUps": [
            "Congratulations once again! I am Rohit from KBC Prize Department. Your winning amount of Rs. 25 lakhs is confirmed.",
            "Sir, to release your prize money, we need your bank account details for direct transfer. Please share your account number.",
            "Sir, our prize verification officer can be reached at +91-5432109876. You can confirm the prize with him.",
            "Sir, there is a government tax of Rs. 12,500 that needs to be paid first. This is as per Income Tax rules for prize money.",
            "Sir, please transfer the tax amount to our official account 9876543210654321. This is the RBI authorized account.",
            "Sir, once we receive the tax payment, your Rs. 25 lakhs will be credited within 4 hours. This is guaranteed.",
            "Sir, don't miss this opportunity. Many winners have already claimed their prizes this week.",
            "Sir, if you have any doubts, you can call our verification number +91-5432109876. We are available 24/7.",
            "Sir, the prize claim deadline is tomorrow. After that your prize will be forfeited and given to the next winner."
        ]
    },

    # 7. ELECTRICITY BILL SCAM
    {
        "scenarioId": "electricity_bill",
        "name": "Electricity Bill Scam",
        "scamType": "electricity_scam",
        "initialMessage": "FINAL NOTICE: Your electricity will be disconnected TODAY at 8 PM due to pending bill of Rs. 8,450. Pay immediately to avoid disconnection. Contact helpline NOW.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-4321098765",
            "upiId": "ebill.payment@scamupi"
        },
        "scammerFollowUps": [
            "This is from TANGEDCO/State Electricity Board. Your consumer number has 3 months pending bill. Disconnection order has been issued.",
            "Sir, to avoid disconnection, pay Rs. 8,450 immediately. Our lineman is already on the way to your area.",
            "Sir, you can reach our billing department at +91-4321098765. They will confirm your pending amount.",
            "Sir, for instant payment, use UPI to ebill.payment@scamupi. This is the official electricity board payment ID.",
            "Sir, your meter reading shows excessive usage. There might be additional penalty if not paid today.",
            "Sir, once payment is confirmed, I will cancel the disconnection order. Please share payment screenshot.",
            "Sir, if UPI is not working, you can also do NEFT to our account. I will share the details.",
            "Sir, this is the last warning. After 8 PM, reconnection will cost Rs. 5,000 extra plus the pending bill.",
            "Sir, many people in your area have already paid. Don't wait until the last moment."
        ]
    },

    # 8. GOVT SCHEME FRAUD
    {
        "scenarioId": "govt_scheme",
        "name": "Government Scheme Fraud",
        "scamType": "govt_scheme",
        "initialMessage": "PM Kisan Samman Nidhi: You are eligible for Rs. 6,000 annual benefit. Your Aadhaar is not linked. Complete verification to receive payment. Visit our portal immediately.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-3210987654",
            "phishingLink": "http://pm-kisan-verify.fakegovt.in/register"
        },
        "scammerFollowUps": [
            "Namaste! I am from the Agriculture Ministry, PM Kisan Yojana cell. Your Aadhaar needs linking to receive Rs. 6,000 benefit.",
            "Sir, please visit http://pm-kisan-verify.fakegovt.in/register and fill your details — Aadhaar, bank account, mobile number.",
            "Sir, our helpline number is +91-3210987654. You can call for assistance in filling the form.",
            "Sir, along with Aadhaar, we need your PAN card number and bank passbook photo for verification.",
            "Sir, there is a small processing fee of Rs. 250 for Aadhaar linking. This is one-time charge by CSC center.",
            "Sir, the portal http://pm-kisan-verify.fakegovt.in/register will be active only till this week. Please complete soon.",
            "Sir, after verification, Rs. 2,000 first installment will be credited directly to your bank account within 7 days.",
            "Sir, you can also forward this message to other farmers in your village. They can also benefit from this scheme.",
            "Sir, please complete the registration today. The government has set a deadline for this batch of beneficiaries."
        ]
    },

    # 9. CRYPTO INVESTMENT SCAM
    {
        "scenarioId": "crypto_investment",
        "name": "Crypto Investment Scam",
        "scamType": "crypto_investment",
        "initialMessage": "EXCLUSIVE OPPORTUNITY: Invest Rs. 10,000 in Bitcoin today and get guaranteed returns of Rs. 1,00,000 in just 30 days! Our AI-powered trading bot has 98% success rate!",
        "metadata": {"channel": "Telegram", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-2109876543",
            "emailAddress": "invest@fakecrypto.exchange"
        },
        "scammerFollowUps": [
            "Welcome to CryptoMax Trading! I am your personal investment advisor Vikash. Our AI bot has generated 10x returns for 5000+ investors.",
            "Sir, to start investing, create your account. Send your details to invest@fakecrypto.exchange and our team will set up your portfolio.",
            "Sir, minimum investment is just Rs. 10,000. You can start with Bitcoin, Ethereum, or our exclusive CryptoMax token.",
            "Sir, call our investment helpline at +91-2109876543. Our senior advisor will explain the profit strategy in detail.",
            "Sir, I can share screenshots of other investors' profits. One client invested Rs. 50,000 and got Rs. 5,00,000 in 45 days.",
            "Sir, the crypto market is booming right now. Bitcoin is going to reach $200,000 soon. This is the best time to invest.",
            "Sir, your investment is 100% safe. We use blockchain technology and cold wallet storage. No risk at all.",
            "Sir, for quick registration, email invest@fakecrypto.exchange with your name, phone, and investment amount.",
            "Sir, this offer is limited to first 100 investors this week. Already 87 seats are taken. Don't miss this golden opportunity."
        ]
    },

    # 10. CUSTOMS PARCEL SCAM
    {
        "scenarioId": "customs_parcel",
        "name": "Customs Parcel Scam",
        "scamType": "customs_fraud",
        "initialMessage": "CUSTOMS ALERT: Your international parcel #IPC-2026-88432 has been seized at Mumbai customs. Contents flagged as undeclared goods. Pay clearance fee or face legal action.",
        "metadata": {"channel": "Phone", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-1098765432",
            "bankAccount": "5678901234567890"
        },
        "scammerFollowUps": [
            "This is Inspector Sharma from Mumbai Customs Department. Your parcel from United Kingdom has been detained. Consignment ID IPC-2026-88432.",
            "Sir, the parcel contains items worth Rs. 3,50,000 which were undeclared. This is a violation of Customs Act Section 112.",
            "Sir, to avoid prosecution and release the parcel, you need to pay customs duty of Rs. 28,500 immediately.",
            "Sir, contact our customs clearance desk at +91-1098765432 for details. Ask for Inspector Sharma, badge number CB-4455.",
            "Sir, the payment should be made to customs account 5678901234567890 at State Bank of India, Branch: Mumbai Fort.",
            "Sir, if payment is not received by today, the matter will be forwarded to Narcotics Bureau for further investigation.",
            "Sir, don't worry, this is a standard customs procedure. Once payment is made, your parcel will be delivered within 48 hours.",
            "Sir, many NRI parcels get flagged. It's just a formality. Pay the duty and collect your parcel from the nearest post office.",
            "Sir, I am trying to help you avoid legal trouble. The fine can go up to Rs. 5,00,000 if this goes to court."
        ]
    },

    # 11. TECH SUPPORT SCAM
    {
        "scenarioId": "tech_support",
        "name": "Tech Support Scam",
        "scamType": "tech_support",
        "initialMessage": "WARNING: Your computer has been infected with a critical virus! Your banking data and passwords are at risk! Call Microsoft Technical Support immediately to fix this issue!",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-9988776655",
            "emailAddress": "support@fake-microsoft-help.com"
        },
        "scammerFollowUps": [
            "This is Microsoft Tech Support. I am Agent David Wilson, Employee ID MSFT-7890. Your computer's IP address has been flagged for malware activity.",
            "Sir, this is a very serious issue. Hackers have already accessed your system. We need to fix this immediately before your bank account is compromised.",
            "Sir, please download TeamViewer or AnyDesk so I can remotely access your computer and remove the virus. The software is safe.",
            "Sir, call our helpline +91-9988776655 if you need assistance with the download. Our team is available 24/7.",
            "Sir, you can also email support@fake-microsoft-help.com and we will send you the cleanup tool directly.",
            "Sir, I can see from our system that your Windows license has also expired. You need to renew it to stay protected.",
            "Sir, the annual Microsoft Security Package costs only Rs. 4,999. This includes antivirus, firewall, and 24/7 support.",
            "Sir, payment can be made via UPI or bank transfer. Once paid, I will activate your license and remove all viruses.",
            "Sir, please act now. Every minute your computer is unprotected, hackers can steal more data. This is very urgent."
        ]
    },

    # 12. LOAN APPROVAL SCAM
    {
        "scenarioId": "loan_approval",
        "name": "Loan Approval Scam",
        "scamType": "loan_approval",
        "initialMessage": "PRE-APPROVED: Personal loan of Rs. 5,00,000 at 0% interest for first 3 months! Instant disbursal in 30 minutes. No documentation required. Apply NOW before offer expires!",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-8877665544",
            "emailAddress": "loans@fake-finance.com"
        },
        "scammerFollowUps": [
            "Congratulations! I am Amit from QuickLoan Finance. Your CIBIL score qualifies you for a pre-approved loan of Rs. 5 lakhs.",
            "Sir, to process your loan, I need basic details — your full name, date of birth, PAN card, and Aadhaar number.",
            "Sir, you can also email your documents to loans@fake-finance.com for faster processing.",
            "Sir, there is a small processing fee of Rs. 3,999 which will be adjusted in your first EMI. This is standard bank procedure.",
            "Sir, our loan officer can be reached at +91-8877665544 if you have any questions about the terms.",
            "Sir, after payment of processing fee, your loan will be disbursed within 30 minutes directly to your bank account.",
            "Sir, the interest rate is just 0.5% per month after the 3-month free period. No hidden charges at all.",
            "Sir, we are RBI registered NBFC. Our license number is NBFC-2026-1234. You can verify on RBI website.",
            "Sir, this pre-approved offer is valid only till today 5 PM. After that the loan amount will reduce to Rs. 2 lakhs."
        ]
    },

    # 13. INCOME TAX SCAM
    {
        "scenarioId": "income_tax",
        "name": "Income Tax Scam",
        "scamType": "income_tax",
        "initialMessage": "NOTICE from Income Tax Department: Your ITR for AY 2025-26 has discrepancies. PAN ABCDE1234F flagged. Tax demand of Rs. 1,85,000 raised. Respond within 24 hours or face prosecution.",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-7766554433",
            "emailAddress": "notice@fake-incometax.gov.in"
        },
        "scammerFollowUps": [
            "This is from the Income Tax Department, Assessment Unit. I am Tax Inspector Gupta. Your PAN ABCDE1234F has been flagged under Section 148.",
            "Sir, our records show undisclosed income of Rs. 12,50,000 in your account. This attracts a penalty of Rs. 1,85,000.",
            "Sir, you can contact our assessment desk at +91-7766554433 or email notice@fake-incometax.gov.in to discuss settlement.",
            "Sir, if you pay the demand within 24 hours, we can waive the penalty and close the case. Otherwise prosecution will be initiated.",
            "Sir, payment can be made through the IT portal or directly to our designated account. I will share the challan details.",
            "Sir, please also share your updated contact details and bank statements for the last 6 months for verification.",
            "Sir, I am trying to help you avoid arrest and prosecution. Many taxpayers have settled their cases by paying promptly.",
            "Sir, you can verify this notice by emailing notice@fake-incometax.gov.in with your PAN and assessment year.",
            "Sir, the deadline is strictly 24 hours. The Commissioner has already signed the prosecution order. Please act immediately."
        ]
    },

    # 14. REFUND SCAM
    {
        "scenarioId": "refund_scam",
        "name": "Refund Scam",
        "scamType": "refund_scam",
        "initialMessage": "Your Flipkart order #FK-2026-998877 worth Rs. 12,499 has been cancelled and a refund is pending. Your account was double-charged. Click to claim refund immediately.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-6655443322",
            "upiId": "refund.process@scampay"
        },
        "scammerFollowUps": [
            "Hi, I am Sneha from Flipkart Customer Support. Order #FK-2026-998877 was double-charged Rs. 12,499. Total refund: Rs. 24,998.",
            "Sir, to process the refund, I need your registered mobile number and UPI ID linked to your Flipkart account.",
            "Sir, our refund helpline is +91-6655443322. You can also call to track your refund status.",
            "Sir, for instant refund, please install our refund verification app and enter code REFUND2026 to initiate the process.",
            "Sir, alternatively, you can send Rs. 1 as verification to refund.process@scampay to confirm your UPI is active.",
            "Sir, once verification is done, Rs. 24,998 will be credited within 10 minutes. This is Flipkart's guaranteed refund policy.",
            "Sir, many customers have successfully received their refunds through this process today.",
            "Sir, please share the OTP that will be sent to your registered number for final verification.",
            "Sir, the refund window closes in 2 hours. After that you will have to raise a new complaint which takes 15-20 days."
        ]
    },

    # 15. INSURANCE SCAM
    {
        "scenarioId": "insurance",
        "name": "Insurance Scam",
        "scamType": "insurance_fraud",
        "initialMessage": "LIC Policy Maturity Alert: Your old LIC policy has matured. Unclaimed bonus of Rs. 3,75,000 is available. Contact our office immediately before it lapses. Policy: LIC-2026-554433.",
        "metadata": {"channel": "Phone", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-5544332211",
            "bankAccount": "3344556677889900"
        },
        "scammerFollowUps": [
            "Namaste sir, I am Meena from LIC Maturity Claims Department. Your policy LIC-2026-554433 has matured with a bonus of Rs. 3,75,000.",
            "Sir, to claim this amount, I need your policy holder name, date of birth, and nominee details for verification.",
            "Sir, you can reach our claims desk directly at +91-5544332211. We operate Monday to Saturday, 9 AM to 6 PM.",
            "Sir, your maturity amount will be transferred to your bank account. Please share account number for NEFT transfer.",
            "Sir, for your reference, the amount will be credited to account 3344556677889900 — is this your correct bank account?",
            "Sir, there is a service charge of Rs. 5,600 for processing the maturity claim. This is as per LIC policy terms.",
            "Sir, please pay the processing charge today. Your unclaimed bonus will lapse if not claimed within this month.",
            "Sir, after payment, the full amount of Rs. 3,75,000 plus bonus will be credited within 5-7 working days.",
            "Sir, I am personally handling your case. Please trust me, this is genuine. Many policy holders have already received their maturity amounts."
        ]
    },
]


# ============================================================================
# EVALUATOR SCORING LOGIC (Exact match to competition)
# ============================================================================

def evaluate_final_output(final_output, scenario, conversation_history):
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
    
    score['total'] = sum([
        score['scamDetection'],
        score['intelligenceExtraction'],
        score['engagementQuality'],
        score['responseStructure']
    ])
    
    return score


# ============================================================================
# TEST RUNNER
# ============================================================================

def test_scenario(scenario, verbose=True):
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
        if turn == 1:
            scammer_message = scenario['initialMessage']
        else:
            follow_idx = turn - 2
            if follow_idx < len(follow_ups):
                scammer_message = follow_ups[follow_idx]
            else:
                scammer_message = f"Sir please respond quickly, time is running out. Turn {turn}."
        
        message = {
            "sender": "scammer",
            "text": scammer_message,
            "timestamp": int(time.time() * 1000)
        }
        
        request_body = {
            'sessionId': session_id,
            'message': message,
            'conversationHistory': conversation_history,
            'metadata': scenario['metadata']
        }
        
        if verbose:
            print(f"\n--- Turn {turn}/{max_turns} ---")
            print(f"  Scammer: {scammer_message[:90]}{'...' if len(scammer_message) > 90 else ''}")
        
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
            
            honeypot_reply = response_data.get('reply') or \
                           response_data.get('message') or \
                           response_data.get('text')
            
            if not honeypot_reply:
                error_msg = f"Turn {turn}: No reply in response"
                errors.append(error_msg)
                if verbose:
                    print(f"  ERROR: {error_msg}")
                continue
            
            if verbose:
                print(f"  Honeypot: {honeypot_reply[:90]}{'...' if len(honeypot_reply) > 90 else ''}")
                print(f"  Time: {elapsed:.2f}s")
            
            conversation_history.append(message)
            conversation_history.append({
                'sender': 'user',
                'text': honeypot_reply,
                'timestamp': int(time.time() * 1000)
            })
            
        except requests.exceptions.Timeout:
            errors.append(f"Turn {turn}: TIMEOUT")
            if verbose:
                print(f"  TIMEOUT!")
        except Exception as e:
            errors.append(f"Turn {turn}: {str(e)}")
            if verbose:
                print(f"  ERROR: {e}")
        
        # Small delay between turns to avoid rate limits
        if turn < max_turns:
            time.sleep(0.5)
    
    if last_response:
        score = evaluate_final_output(last_response, scenario, conversation_history)
    else:
        score = {'scamDetection': 0, 'intelligenceExtraction': 0,
                 'engagementQuality': 0, 'responseStructure': 0, 'total': 0, 'details': {}}
    
    # Quality checks
    replies = [r.get('reply') or r.get('message') or r.get('text') or '' for r in all_responses]
    unique_replies = set(replies)
    
    ai_leak = False
    for reply in replies:
        lower = reply.lower()
        if any(x in lower for x in ['language model', 'as an ai', "i'm an ai", 'artificial intelligence', 'openai', 'groq', 'llama']):
            ai_leak = True
            break
    
    quality = {
        'turns_completed': len(all_responses),
        'avg_time': round(sum(turn_times) / len(turn_times), 2) if turn_times else 0,
        'max_time': round(max(turn_times), 2) if turn_times else 0,
        'all_under_30s': all(t < 30 for t in turn_times),
        'no_ai_leak': not ai_leak,
        'unique_ratio': f"{len(unique_replies)}/{len(replies)}",
        'all_unique': len(unique_replies) == len(replies),
        'errors': errors,
    }
    
    return {
        'scenario': scenario['name'],
        'scenarioId': scenario['scenarioId'],
        'score': score,
        'quality': quality,
        'lastResponse': last_response
    }


def run_all_tests(scenarios=None, verbose=True):
    scenarios = scenarios or TEST_SCENARIOS
    
    print("=" * 70)
    print("AGENTIC HONEYPOT — FULL 15-SCENARIO EVALUATION")
    print(f"Endpoint: {ENDPOINT_URL}")
    print(f"Time: {datetime.now().isoformat()}")
    print(f"Scenarios: {len(scenarios)}")
    print("=" * 70)
    
    results = []
    for i, scenario in enumerate(scenarios):
        print(f"\n[{i+1}/{len(scenarios)}] Testing {scenario['name']}...")
        result = test_scenario(scenario, verbose=verbose)
        results.append(result)
        
        # Brief score after each scenario
        s = result['score']
        print(f"  => Score: {s['total']:.0f}/100 "
              f"(Det:{s['scamDetection']:.0f} Intel:{s['intelligenceExtraction']:.0f} "
              f"Eng:{s['engagementQuality']:.0f} Str:{s['responseStructure']:.0f})")
        
        # Delay between scenarios to avoid rate limits
        if i < len(scenarios) - 1:
            print("  [Waiting 3s between scenarios...]")
            time.sleep(3)
    
    # ======================================================================
    # RESULTS SUMMARY
    # ======================================================================
    total_weight = sum(s['weight'] for s in scenarios)
    weighted_score = 0
    
    print("\n" + "=" * 70)
    print("SCORE BREAKDOWN BY SCENARIO")
    print("=" * 70)
    print(f"{'#':<3} {'Scenario':<25} {'Det':>4} {'Intel':>6} {'Eng':>4} {'Str':>4} {'Total':>6} {'Turns':>6} {'Unique':>7}")
    print("-" * 70)
    
    for i, result in enumerate(results):
        s = result['score']
        q = result['quality']
        weight = scenarios[i]['weight'] / total_weight
        weighted_score += s['total'] * weight
        
        print(f"{i+1:<3} {result['scenario']:<25} "
              f"{s['scamDetection']:>4.0f} {s['intelligenceExtraction']:>6.0f} "
              f"{s['engagementQuality']:>4.0f} {s['responseStructure']:>4.0f} "
              f"{s['total']:>6.0f} {q['turns_completed']:>5}/10 {q['unique_ratio']:>7}")
    
    print("-" * 70)
    print(f"{'WEIGHTED AVERAGE':<45} {weighted_score:>24.1f}/100")
    
    # Intelligence extraction detail
    print("\n" + "=" * 70)
    print("INTELLIGENCE EXTRACTION DETAIL")
    print("=" * 70)
    
    total_fake = 0
    total_matched = 0
    for i, result in enumerate(results):
        intel = result['score'].get('details', {}).get('intelligence', {})
        if intel:
            for key, val in intel.items():
                total_fake += 1
                status = "MATCH" if val['matched'] else "MISS"
                if val['matched']:
                    total_matched += 1
                print(f"  {result['scenarioId']:<20} {key:<15} [{status}] "
                      f"want={val['fakeValue'][:30]} got={str(val['extractedValues'])[:40]}")
    
    print(f"\n  Total: {total_matched}/{total_fake} fakeData items matched "
          f"({total_matched/total_fake*100:.0f}%)")
    
    # Quality summary
    print("\n" + "=" * 70)
    print("QUALITY CHECKS")
    print("=" * 70)
    
    all_turns = all(r['quality']['turns_completed'] == 10 for r in results)
    all_under_30 = all(r['quality']['all_under_30s'] for r in results)
    all_no_leak = all(r['quality']['no_ai_leak'] for r in results)
    all_unique = all(r['quality']['all_unique'] for r in results)
    has_errors = any(r['quality']['errors'] for r in results)
    
    checks = [
        ("All 10 turns completed per scenario", all_turns),
        ("All responses under 30s", all_under_30),
        ("No AI identity leaks", all_no_leak),
        ("All replies unique (no repetition)", all_unique),
        ("No HTTP errors", not has_errors),
        ("scamDetected=true all scenarios", all(r['score']['scamDetection'] == 20 for r in results)),
        ("engagementMetrics present", all('engagementMetrics' in (r['lastResponse'] or {}) for r in results)),
        ("agentNotes present", all('agentNotes' in (r['lastResponse'] or {}) for r in results)),
    ]
    
    for label, passed in checks:
        icon = "PASS" if passed else "FAIL"
        print(f"  [{icon}] {label}")
    
    # Errors
    if has_errors:
        print("\n  ERRORS:")
        for r in results:
            if r['quality']['errors']:
                for e in r['quality']['errors']:
                    print(f"    [{r['scenarioId']}] {e}")
    
    print("\n" + "=" * 70)
    print(f"FINAL PREDICTED SCORE: {weighted_score:.1f}/100")
    print("=" * 70)
    
    return weighted_score, results


if __name__ == "__main__":
    import sys
    
    # Allow running specific scenario: python test_all_15.py bank_fraud
    if len(sys.argv) > 1:
        scenario_id = sys.argv[1]
        matched = [s for s in TEST_SCENARIOS if s['scenarioId'] == scenario_id]
        if matched:
            run_all_tests(scenarios=matched, verbose=True)
        else:
            print(f"Unknown scenario: {scenario_id}")
            print(f"Available: {', '.join(s['scenarioId'] for s in TEST_SCENARIOS)}")
    else:
        run_all_tests(verbose=True)
