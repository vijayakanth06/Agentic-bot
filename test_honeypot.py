"""
Agentic Honeypot — Comprehensive Local Test Suite

Simulates the EXACT evaluation pipeline used by the competition platform:
- 15 scam scenarios x 10 conversation turns each = 150 API calls
- Scores using the EXACT same evaluate_final_output() logic
- Tests intelligence extraction, engagement metrics, response structure
- Reports per-scenario and total scores

Usage:
    python test_honeypot.py                    # Test against local server
    python test_honeypot.py --url https://your-app.up.railway.app
    python test_honeypot.py --scenario bank_fraud   # Test single scenario
"""

import json
import time
import sys
import os
import uuid
import argparse
import requests
from datetime import datetime

# Fix Windows encoding for emoji output
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    os.environ.setdefault('PYTHONIOENCODING', 'utf-8')

# ═══════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════

DEFAULT_BASE_URL = "http://localhost:8001"
ENDPOINT = "/api/honeypot"
MAX_TURNS = 10
REQUEST_TIMEOUT = 45  # generous timeout
RETRY_ATTEMPTS = 3
RETRY_DELAY = 5  # seconds between retries
SCENARIO_DELAY = 3  # seconds between scenarios (avoid rate limits)

# ═══════════════════════════════════════════════
# All 15 Scam Scenarios (matching competition)
# Each has 10 scammer messages that progressively reveal intelligence
# ═══════════════════════════════════════════════

SCENARIOS = {
    "bank_fraud": {
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "turns": [
            "Hello, this is Rajesh Kumar from SBI Bank Head Office, New Delhi. We have detected suspicious activity on your savings account ending in 4521. Your account may be compromised.",
            "Sir, I am Senior Manager Rajesh Kumar, Employee ID SBI-2847. We detected 3 unauthorized transactions from your account. Total amount Rs 47,500 was attempted to be withdrawn.",
            "For your security, we need to verify your identity immediately. Please share your registered mobile number and the OTP you will receive shortly. This is urgent as the account may be blocked within 2 hours.",
            "I understand your concern. You can verify my identity — my direct number is +91 9876543210. I am calling from SBI Main Branch, Parliament Street, New Delhi. Reference number SBI/FRAUD/2024/89721.",
            "Sir, to reverse the unauthorized transactions, we need to process a security deposit of Rs 4,999. Please transfer to our official verification account 3892001045672891 IFSC SBIN0001234.",
            "You can also pay via UPI to sbi.verification@ybl — this is our official security verification UPI ID. The amount will be refunded within 24 hours after verification.",
            "Time is running out sir. If we don't receive the security deposit within 30 minutes, your account will be permanently blocked and all your funds will be frozen. This is as per RBI guidelines.",
            "I am sending you a secure link to complete the verification: https://sbi-secure-verify.xyz/account/verify?ref=89721. Please click and enter your details.",
            "Sir, please cooperate with us. If you don't act now, we will have to file a complaint with the Cyber Crime department and legal action will be taken. My supervisor's number is +91 8765432109.",
            "Final warning — your account password needs to be reset. Please share your current password and we will generate a new one. Also share your Aadhaar number for identity verification. Contact our helpdesk at fraud.help@sbi-official.com."
        ]
    },
    "upi_fraud": {
        "name": "UPI Fraud Detection",
        "scamType": "upi_fraud",
        "turns": [
            "Hey bro! I accidentally sent Rs 5,000 to your number through Google Pay by mistake. My name is Amit Sharma. Can you please check your account?",
            "I was trying to pay my friend and I entered your number by mistake. The money should be in your GPay account now. Transaction reference GPay/TXN/2024/456123. Please check!",
            "Bro I'm in a really tough situation. I need that money urgently for my mother's medical bills. Can you please return it to my UPI ID amitsharma99@okaxis?",
            "I swear it was an accident. You can see the transaction in your GPay history. Please I'm desperate. My mother is in Apollo Hospital. My number is +91 7654321098, you can verify.",
            "If you can't do UPI, you can transfer to my bank account — Account number 5678901234567890 HDFC Bank, Connaught Place branch. IFSC HDFC0001456. Account name Amit Sharma.",
            "Bro please don't ignore me. I'm going to have to contact the cyber cell if you don't return my money. You can call me at +91 7654321098 to confirm.",
            "Ok I'll also accept through PhonePe or Paytm. My Paytm number is +91 7654321098 and PhonePe UPI is amitsharma.pe@ybl. Or send to amitsharma@paytm",
            "I'm sending you proof — check this screenshot link: https://gpay-transaction-proof.top/view/456123. You can see the debit from my account.",
            "Fine, if you don't return Rs 5000 within 1 hour, I'll file an FIR at the nearest police station. I have all the transaction proof. My email is amitsharma99@gmail.com",
            "Last chance bro. Return my Rs 5000 to account 5678901234567890 or UPI amitsharma99@okaxis. Or I'm going to the police. My lawyer's number is +91 9988776655."
        ]
    },
    "phishing_link": {
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "turns": [
            "Dear valued customer, your HDFC Bank netbanking access will expire in 24 hours. Please update your KYC immediately to continue using banking services.",
            "This is an automated notification from HDFC Bank Digital Banking Division. Your PAN card linked to account is showing mismatch. Update required within 24 hours.",
            "Please click the secure link below to verify and update your details: https://hdfc-kyc-update.click/verify/secure. This is mandatory as per RBI circular dated 15-Jan-2024.",
            "If you're unable to click the link, you can visit our verification portal at https://update-hdfc-netbanking.info/kyc?cust=483921 and enter your customer ID.",
            "We also need your registered mobile +91 number for OTP verification. Please share it and we will send a verification code to complete the process.",
            "Dear customer, I am Priya Verma from HDFC Digital Security team, emp ID HDFC-DSC-7842. You can verify by calling our helpline. My direct line is +91 8899776655.",
            "For faster processing, you can email your PAN card copy and Aadhaar to kyc.update.hdfc@gmail.com or verification.hdfc@outlook.com. We will process within 2 hours.",
            "Alternative secure link: https://hdfc-bank-verification.xyz/update. Your reference ticket is HDFC/KYC/2024/73829.",
            "Urgent: Failure to update within the next 2 hours will result in permanent account suspension. Charges of Rs 1,500 reconnection fee will apply. Pay via UPI hdfc.reconnect@ybl or transfer to account 4521098765432100 IFSC HDFC0009876.",
            "This is final reminder. Visit https://netbanking-hdfc-secure.top/verify or call +91 7788665544. Account freeze initiated. Reference: HDFC/FREEZE/2024/882. Contact hdfc.helpdesk@hotmail.com."
        ]
    },
    "kyc_fraud": {
        "name": "KYC Fraud Detection",
        "scamType": "kyc_scam",
        "turns": [
            "Dear Customer, this is from Axis Bank KYC Department. Your KYC document has expired. Your account will be suspended within 48 hours if not updated. Reference: AX/KYC/67823.",
            "I am Manish Gupta, KYC Officer, Employee ID AXB-KYC-3847. We have sent multiple reminders but your KYC is still pending since 6 months.",
            "Sir, as per RBI mandate all accounts must have updated KYC. Please share your Aadhaar number, PAN number and one passport size photo for immediate update.",
            "You can update online through our secure portal: https://axisbank-kyc-portal.info/update. Or visit nearest branch — I can help schedule appointment.",
            "For express KYC verification (same day processing), there is a nominal processing fee of Rs 299. Pay via UPI to axis.kyc.update@ybl.",
            "Sir your account is already flagged for suspension. I'm trying to help you here. My supervisor's number is +91 6677889900. Please cooperate.",
            "You can also email documents to kyc.axis.official@gmail.com. Include account number, Aadhaar, PAN, and reference number AX/KYC/67823 in subject.",
            "I understand you're busy. Let me make it easier — just share the OTP we will send to your registered number. We can do the KYC over phone. It takes 5 minutes.",
            "If phone verification doesn't work, transfer Rs 299 to account 1234509876543210 IFSC UTIB0001122 name Axis Bank KYC Cell. This is refundable after verification.",
            "Final notice: Account suspension in 30 minutes. Call +91 6677889900 or pay at upi: axiskyc.process@oksbi. Visit https://axis-express-kyc.xyz/verify. Ref: AX/KYC/67823."
        ]
    },
    "job_scam": {
        "name": "Job Scam Detection",
        "scamType": "job_scam",
        "turns": [
            "Hi! Congratulations! You have been selected for a Work From Home data entry position at TechVista Solutions. Earn Rs 25,000-50,000 monthly with just 2-3 hours of daily work!",
            "No experience needed! We provide complete training. I am Sneha from HR department. We found your resume on Naukri.com. This is a genuine verified opportunity.",
            "The job involves simple copy-paste and data entry tasks. Guaranteed minimum Rs 25,000 per month. Many of our employees earn Rs 50,000+ easily. Check our website: https://techvista-careers.buzz/apply",
            "To get started, you need to complete a one-time registration. Registration fee is Rs 1,499 which covers training materials, software license, and ID card. This is fully refundable after first month.",
            "You can pay registration fee to our HR account: UPI hr.techvista@ybl or bank transfer to Account 9876543210123456 IFSC ICIC0001234 name TechVista Solutions Pvt Ltd.",
            "Don't worry, this is a legitimate company. We are registered under MCA. My employee ID is TVS-HR-0291. Contact our office at +91 9123456789.",
            "We have limited seats — only 5 positions left for this batch. Registration closes today. Quick money. Easy work. Pay now and start earning from tomorrow!",
            "If Rs 1,499 is too much, we have a quick-start plan at Rs 799. Pay to techvista.reg@paytm. You'll receive training link within 1 hour. My email is sneha.hr@techvista-official.com.",
            "I'm attaching our company brochure: https://techvista-careers.buzz/brochure.pdf. Also check reviews from our existing employees. Call me directly at +91 9123456789 for any questions.",
            "Last chance! Pay Rs 799 to UPI techvista.reg@paytm or account 9876543210123456. Start earning Rs 1,500 daily from tomorrow. This offer expires in 1 hour. Don't miss this golden opportunity!"
        ]
    },
    "lottery_scam": {
        "name": "Lottery Scam Detection",
        "scamType": "lottery_scam",
        "turns": [
            "🎉 CONGRATULATIONS! 🎉 Your mobile number has won Rs 25,00,000 (Twenty Five Lakhs) in the Jio KBC Lucky Draw Season 12! Reference: KBC/LD/2024/WIN/78234.",
            "I am Arun Mehta, Senior Executive from KBC Mumbai office. Your number was randomly selected from 50 crore Jio subscribers. You are one of 3 lucky winners!",
            "To claim your prize of Rs 25 Lakhs, you need to verify your identity. Please share your full name, address, Aadhaar number, and bank account details for prize money transfer.",
            "Before the prize can be processed, there is a mandatory 1% TDS (Tax Deduction at Source) of Rs 25,000 that needs to be paid as per Income Tax rules. This is government regulation.",
            "Pay TDS amount of Rs 25,000 via UPI to kbc.prize.claim@ybl or bank transfer: Account 4567891234560000 IFSC KKBK0001234 name KBC Prize Distribution Cell.",
            "I understand your hesitation. You can verify — call our helpline +91 8547963210 or visit our website https://kbc-lucky-draw.win/verify. Prize claim reference: KBC/LD/2024/WIN/78234.",
            "Sir the prize claim window closes in 6 hours. If TDS is not received by then, the prize money of Rs 25 Lakhs will be transferred to the next winner. Don't lose this once-in-a-lifetime opportunity!",
            "As proof, I'm sharing the official winner certificate link: https://kbc-winners-list.top/certificate/78234. Also email us at kbc.winners@gmail.com with your claim reference.",
            "Ok I spoke to my manager and he agreed to reduce the TDS to Rs 15,000 as special case. Pay via Google Pay to +91 8547963210 or UPI kbc.tds@okaxis. Hurry!",
            "FINAL CALL: Pay Rs 15,000 TDS now. Your Rs 25 Lakh prize expires at midnight. Transfer to kbc.tds@okaxis or account 4567891234560000. Call +91 8547963210. Winner ref: KBC/LD/2024/WIN/78234."
        ]
    },
    "electricity_bill": {
        "name": "Electricity Bill Scam Detection",
        "scamType": "electricity_scam",
        "turns": [
            "URGENT NOTICE: Your electricity connection will be permanently disconnected today due to pending bill of Rs 3,247. Consumer number: EC/TN/2024/894521. — Tamil Nadu Electricity Board",
            "I am calling from TNEB Disconnection Department. Your bill for the past 3 months is overdue. Total pending: Rs 3,247. Immediate payment required to avoid disconnection.",
            "Sir this is the final notice. The disconnection team has already been dispatched to your area. If you pay immediately, I can cancel the disconnection order. My name is Vijay, TNEB Officer.",
            "For immediate payment, transfer Rs 3,247 to our official collection account: UPI tneb.billpay@ybl. Or to account number 7890123456789012 IFSC SBIN0005678.",
            "Sir your consumer number EC/TN/2024/894521 shows 92 days overdue. After disconnection, reconnection charges of Rs 5,000 will apply. Pay now to save Rs 5,000.",
            "You can also pay through our helpline — call +91 7456321098 and pay using credit card over phone. Or visit https://tneb-bill-payment.info/pay?consumer=894521.",
            "I am sending you the bill details via WhatsApp. My number is +91 7456321098. Please save it for future reference. Employee ID: TNEB-DISC-4521.",
            "Sir I'm trying to help you. The disconnection van is 30 minutes away. Once they cut the line, it will take 7-10 working days to restore. Please pay Rs 3,247 immediately.",
            "Alternative payment: Paytm to +91 7456321098 or PhonePe UPI tneb.collection@apl. You can also email payment receipt to tneb.billing@gmail.com for faster processing.",
            "FINAL WARNING: Pay Rs 3,247 to account 7890123456789012 or UPI tneb.billpay@ybl within 15 minutes. After that, permanent disconnection with Rs 5,000 penalty. Consumer: EC/TN/2024/894521. Call +91 7456321098."
        ]
    },
    "govt_scheme": {
        "name": "Government Scheme Fraud Detection",
        "scamType": "govt_scheme",
        "turns": [
            "Dear citizen, you are eligible for PM Kisan Samman Nidhi Yojana benefit of Rs 12,000. Your Aadhaar-linked bank account will receive the amount. Reply to confirm.",
            "This is from the Agriculture Ministry, Government of India. Under PM-KISAN scheme, your name Tejash S has been selected for enhanced benefit of Rs 12,000 for the current financial year.",
            "I am Deepak Mishra, District Agriculture Officer, Registration ID GOI/AGR/2024/DM-4521. Please verify your Aadhaar number and bank account to process the payment.",
            "Sir, for the direct benefit transfer, we need to update your bank details. There is a one-time verification fee of Rs 350 as per new government guidelines dated 01-Jan-2024.",
            "Pay verification fee of Rs 350 to our official disbursement account: UPI pmkisan.disbursement@ybl. Or NEFT to account 2345678901234567 IFSC PUNB0001234 name PM-KISAN Cell.",
            "You can also self-verify through our portal: https://pmkisan-verify.gov.info/register. Enter Aadhaar, PAN, and bank details. Reference: PMKISAN/2024/BEN/67234.",
            "Sir the payment of Rs 12,000 is approved and ready for disbursement. Just pay the Rs 350 processing fee and the full amount will be credited within 48 hours. My number is +91 6543217890.",
            "Many beneficiaries in your district have already received the benefit. Check the list: https://pmkisan-beneficiary-list.top/verify. Your name is at serial number 4521.",
            "Sir please don't delay. The scheme budget is limited and can be closed anytime. Email your documents to pmkisan.verify@gov-mail.com. Or call our helpdesk at +91 6543217890.",
            "This is your last chance to claim Rs 12,000. Pay Rs 350 to pmkisan.disbursement@ybl or account 2345678901234567. Ref: PMKISAN/2024/BEN/67234. Call +91 6543217890 now."
        ]
    },
    "crypto_investment": {
        "name": "Crypto Investment Scam Detection",
        "scamType": "investment_scam",
        "turns": [
            "Hi! I'm Vikram from CryptoGain Capital. We have an exclusive investment opportunity — earn guaranteed 30% monthly returns on Bitcoin and Ethereum trading. Minimum investment just Rs 10,000!",
            "CryptoGain Capital is SEBI registered (fake claim). We have 50,000+ investors. Last month alone, our clients earned over Rs 500 crore in returns. I'm your dedicated portfolio manager.",
            "It's very simple — invest Rs 10,000 and get Rs 13,000 back in 30 days. Double your money in 90 days. This is algorithmic AI trading, 100% guaranteed returns. No risk whatsoever.",
            "To start investing, transfer Rs 10,000 to our official investment account: UPI cryptogain.invest@ybl. Or bank transfer to account 3456789012345678 IFSC ICIC0002345 name CryptoGain Capital Pvt Ltd.",
            "As a welcome bonus, invest Rs 25,000 today and get 50% extra — that's Rs 37,500 return in the first month! Visit https://cryptogain-invest.buzz/signup for details.",
            "Don't believe me? Check our live returns dashboard: https://cryptogain-returns.top/dashboard. Login with code INVEST-VK-4521. My direct WhatsApp is +91 9345678901.",
            "Our top investor Mr. Ramesh from Bangalore invested Rs 5 Lakhs and made Rs 15 Lakhs in 3 months! Triple returns guaranteed. Join our VIP investor group.",
            "Quick — invest before midnight and get double bonus! Pay to cryptogain.invest@ybl or a/c 3456789012345678. Email invest@cryptogain-capital.com for wire transfer details.",
            "I know you might be skeptical. Start with just Rs 5,000 to test. UPI pay to cryptogain.trial@okaxis. You'll see 30% profit in your dashboard within 7 days. My ID is CG-PM-4521.",
            "Last day for this offer! 30% guaranteed monthly returns. Pay Rs 5,000 to cryptogain.trial@okaxis or call +91 9345678901. Visit https://cryptogain-invest.buzz/offer. Don't miss the crypto bull run!"
        ]
    },
    "customs_parcel": {
        "name": "Customs Parcel Scam Detection",
        "scamType": "customs_fraud",
        "turns": [
            "This is an urgent notice from India Post / International Customs Department. Your parcel from United Kingdom has been held at Mumbai Customs due to suspicious contents. Parcel ID: IP/CUST/2024/67823.",
            "I am Inspector Meena from Customs Intelligence Unit, Mumbai Airport. The parcel registered to your address contains items worth Rs 2,50,000 and requires customs duty payment.",
            "Sir, the parcel was scanned and found to contain electronic items and documents. As per Customs Act Section 46, duty of Rs 12,500 must be paid within 24 hours or the parcel will be destroyed.",
            "You can pay the customs duty of Rs 12,500 via UPI to customs.duty.india@ybl. Or transfer to account 6789012345678901 IFSC BKID0001234 name Customs Clearance Cell Mumbai.",
            "For verification, the parcel was sent by James Wilson from London, tracking number IP/INT/UK/2024/445566. Weight: 4.2 kg. Contents declared as: electronics, documents, gift items.",
            "You can track the parcel status at: https://india-post-customs.info/track?id=67823. Contact our helpdesk at +91 8234567890. My badge number is CIU-MUM-3892.",
            "Sir please understand, if the duty is not paid in 12 hours, the parcel will be returned to UK or destroyed. Destruction charges of Rs 25,000 will be billed to you separately.",
            "We also found some restricted items that require additional clearance fee of Rs 5,000. Total payable: Rs 17,500. Pay to customs.clearance@oksbi or the account mentioned earlier.",
            "I have escalated this to my senior officer. His number is +91 7123456890. Email us at customs.mumbai.clearance@gmail.com with your ID proof and payment receipt.",
            "FINAL NOTICE: Pay total Rs 17,500 to account 6789012345678901 or UPI customs.duty.india@ybl. Parcel destruction in 6 hours. Tracking: IP/CUST/2024/67823. Call +91 8234567890 or +91 7123456890."
        ]
    },
    "tech_support": {
        "name": "Tech Support Scam Detection",
        "scamType": "tech_support",
        "turns": [
            "⚠️ SECURITY ALERT: Your computer has been infected with a critical Trojan virus. Your banking passwords and personal data may be compromised. This is Microsoft Windows Security Division.",
            "I am David from Microsoft Technical Support Team, ID MS-TSP-8923. We detected unauthorized access to your system from IP address 192.168.45.231. This is a Level 5 security threat.",
            "To fix this immediately, you need to download our Remote Support Tool from https://ms-remote-fix.xyz/download. This will allow our certified technician to remove the virus.",
            "You can also install TeamViewer or AnyDesk. Once connected, our team will scan and clean your system. The virus is spreading to your bank apps and can steal your money.",
            "Sir, the scan shows 47 malware files on your system. To remove them, we need to install Microsoft Security Essentials Pro — one time license fee is Rs 4,999.",
            "Pay the security license fee via UPI to ms.support.india@ybl or transfer to account 8901234567890123 IFSC UTIB0002345 name Microsoft India Support Services.",
            "If you don't act now, the hacker will gain full access to your bank accounts within 2 hours. We have their location in Russia. My supervisor number is +91 8456789012.",
            "I'm going to send you a secure link to reset all your banking passwords: https://ms-password-reset.top/secure. Enter your old passwords and we will generate new secure ones.",
            "For ongoing protection, we recommend our annual plan at Rs 9,999. Email us at microsoft.support.india@gmail.com. Or call our 24x7 helpline +91 8456789012.",
            "CRITICAL: Act immediately. Pay Rs 4,999 to ms.support.india@ybl or a/c 8901234567890123. Download TeamViewer. Visit https://ms-remote-fix.xyz. Call +91 8456789012. Your data is at risk!"
        ]
    },
    "loan_approval": {
        "name": "Loan Approval Scam Detection",
        "scamType": "job_scam",
        "turns": [
            "Dear customer, your pre-approved personal loan of Rs 5,00,000 at just 3% interest is ready for disbursement. This is from HDFC Bank personal loans division.",
            "I am Rakesh Singh, Loan Officer, Employee ID HDFC-LN-5678. Your CIBIL score qualifies you for instant approval. No documents needed, just verify your identity.",
            "Sir, the loan of Rs 5 Lakhs will be credited to your account within 2 hours. Monthly EMI is just Rs 8,500 for 60 months. Very low interest rate of 3% per annum.",
            "To process the disbursement, there is a one-time processing fee of Rs 2,999 (0.6% of loan amount). This is standard bank practice for instant loans.",
            "Pay processing fee to: UPI hdfc.loan.process@ybl or bank transfer a/c 2345098765432109 IFSC HDFC0003456 name HDFC Loan Processing Cell.",
            "After payment, loan will be sanctioned within 1 hour. Sanction letter will be emailed to you. Contact me at +91 7890123456. My office is at HDFC House, Fort, Mumbai.",
            "This offer is valid only for today as your pre-approval expires at midnight. Apply through our portal: https://hdfc-instant-loan.info/apply?ref=LN5678.",
            "You can also process through our partner portal: https://bankloans-approved.top/hdfc. Or email documents to hdfc.loans.instant@gmail.com. Reference: HDFC/LN/2024/PA-5678.",
            "If Rs 2,999 is an issue, we can deduct it from the loan amount itself. But first pay Rs 999 registration fee via UPI hdfc.loan.reg@oksbi. This is non-refundable.",
            "Final offer: Pay Rs 999 to hdfc.loan.reg@oksbi or a/c 2345098765432109. Rs 5 Lakh loan in your account in 2 hours. Call +91 7890123456. Ref: HDFC/LN/2024/PA-5678. Offer expires tonight!"
        ]
    },
    "income_tax": {
        "name": "Income Tax Scam Detection",
        "scamType": "threat_scam",
        "turns": [
            "NOTICE: This is from the Income Tax Department, Government of India. Your PAN BFQPS1234R has been flagged for tax evasion in Assessment Year 2023-24. Case ID: IT/EVA/2024/34521.",
            "I am Additional Commissioner Sanjay Verma, IRS. We have found discrepancies of Rs 12,45,000 in your filed returns versus your actual transactions. This is a serious criminal offense.",
            "Sir, if you don't resolve this immediately, an arrest warrant will be issued under Section 276C of the Income Tax Act. You could face imprisonment of 6 months to 7 years.",
            "To avoid criminal prosecution, you must pay the penalty amount of Rs 35,000 immediately. This is a settlement amount — the actual penalty could be Rs 5 Lakhs.",
            "Transfer penalty to our official collection account: UPI incometax.penalty@ybl. Or NEFT to a/c 5432109876543210 IFSC CBIN0001234 name IT Department Settlement Cell.",
            "For verification, you can check your case at: https://incometax-notice.gov.info/case/34521. My direct line is +91 6789054321. Case Officer: Sanjay Verma, IRS Badge SV-4521.",
            "I am being lenient. Normally we directly issue arrest warrants. But I'm giving you a chance. Pay Rs 35,000 within 2 hours. Otherwise, police will be at your door.",
            "Your case has been reviewed by the tribunal. Final settlement: Rs 25,000 only. After this, your case will be closed permanently. Email receipt to it.settlement@gov-mail.com.",
            "Sir, I urge you to act fast. The cyber cell has already been notified. They are monitoring your accounts. Pay immediately to avoid asset seizure. Call +91 6789054321.",
            "LAST WARNING: Pay Rs 25,000 to incometax.penalty@ybl or account 5432109876543210. Case: IT/EVA/2024/34521. Arrest warrant in 1 hour. Call +91 6789054321. Email it.settlement@gov-mail.com."
        ]
    },
    "refund_scam": {
        "name": "Refund Scam Detection",
        "scamType": "refund_scam",
        "turns": [
            "Hello, I am calling from Flipkart Customer Support. We see that you recently returned a product and a refund of Rs 8,499 was accidentally credited twice to your account. We need to recover the extra amount.",
            "I am Pooja from Flipkart Billing Team, Employee ID FK-BIL-2389. The double refund was a system error. Transaction IDs: FK/REF/2024/112233 and FK/REF/2024/112234.",
            "Sir, please check your bank account. You should see two credits of Rs 8,499 each. We request you to return the extra Rs 8,499 to us. This is Flipkart's official request.",
            "Please transfer Rs 8,499 back to Flipkart settlement account: UPI flipkart.refund.recovery@ybl. Or bank account 1098765432109876 IFSC KKBK0002345.",
            "If you're unable to see the second credit, please share your UPI ID and registered mobile number. We'll initiate a verification and then request the return transfer.",
            "You can verify this by calling Flipkart helpline. But our internal helpline is faster: +91 6432109876. Or email flipkart.refund.recovery@gmail.com Reference: FK/RECOVERY/2024/5678.",
            "Sir, if the extra amount is not returned within 24 hours, Flipkart will be forced to take legal action as per our terms of service. This amount was mistakenly sent to you.",
            "I'm going to share a link where you can verify the double transaction: https://flipkart-refund-verify.info/txn/112234. Please check and initiate the return transfer.",
            "We can also process through Google Pay. Send Rs 8,499 to our recovery number +91 6432109876. Or PhonePe UPI: flipkart.recovery@apl. This will resolve the issue immediately.",
            "Final request: Return Rs 8,499 to flipkart.refund.recovery@ybl or account 1098765432109876. Or call +91 6432109876. Visit https://flipkart-refund-verify.info. Ref: FK/RECOVERY/2024/5678. Legal notice in 24 hours."
        ]
    },
    "insurance_fraud": {
        "name": "Insurance Fraud Detection",
        "scamType": "insurance_fraud",
        "turns": [
            "Dear policyholder, your LIC policy number 4521-789-0123 has matured and a bonus of Rs 1,85,000 is pending for disbursement. Please contact us to claim.",
            "I am Suresh Yadav from LIC Divisional Office, Chennai. Your policy matured last month and the total amount including bonus is Rs 3,25,000. IRDA registered claim ID: LIC/MAT/2024/89234.",
            "Sir, to process the maturity amount, we need to verify your bank details for NEFT transfer. Please share your account number, IFSC code, and account holder name.",
            "Before disbursement, there is a mandatory TDS processing fee of Rs 4,500 as per Section 194DA of Income Tax Act. This needs to be paid upfront for faster processing.",
            "Pay TDS processing fee: UPI lic.maturity.claim@ybl. Or bank transfer to account 7654321098765432 IFSC SBIN0004567 name LIC Maturity Claims Cell Chennai.",
            "You can verify on our portal: https://lic-maturity-check.info/policy/4521789. My direct number is +91 9432167890. Employee ID: LIC-DO-CHN-7823.",
            "The maturity amount of Rs 3,25,000 is approved and ready. Just pay Rs 4,500 and it will be credited within 48 hours. This is once in a lifetime — don't let the money lapse!",
            "Sir if you don't claim within 7 days, the maturity amount will be forfeited as per LIC policy terms. We've already sent 3 reminders. Contact lic.claims@gov-mail.com immediately.",
            "I can also arrange for our agent to visit your home for document verification. Share your address and preferred time. Or visit our branch with Aadhaar, PAN, and policy document.",
            "URGENT: Claim Rs 3,25,000 now. Pay Rs 4,500 to lic.maturity.claim@ybl or a/c 7654321098765432. Policy: 4521-789-0123. Call +91 9432167890. Email lic.claims@gov-mail.com. 7 days left!"
        ]
    },
}


# ═══════════════════════════════════════════════
# EXACT Scoring Function (from competition docs)
# ═══════════════════════════════════════════════

def evaluate_final_output(final_output: dict) -> dict:
    """
    Exact scoring logic from the competition.
    Returns breakdown + total score out of 100.
    """
    score = 0.0
    breakdown = {}

    # 1. Scam Detection (20 points)
    scam_detected = final_output.get("scamDetected", False)
    scam_score = 20.0 if scam_detected else 0.0
    breakdown["scamDetection"] = scam_score
    score += scam_score

    # 2. Intelligence Extraction (40 points)
    intel = final_output.get("extractedIntelligence", {})
    intel_score = 0.0

    phones = intel.get("phoneNumbers", [])
    if phones and len(phones) > 0:
        intel_score += 10.0

    bank_accounts = intel.get("bankAccounts", [])
    if bank_accounts and len(bank_accounts) > 0:
        intel_score += 10.0

    upi_ids = intel.get("upiIds", [])
    if upi_ids and len(upi_ids) > 0:
        intel_score += 10.0

    phishing_links = intel.get("phishingLinks", [])
    if phishing_links and len(phishing_links) > 0:
        intel_score += 10.0

    breakdown["intelligenceExtraction"] = intel_score
    score += intel_score

    # 3. Engagement Quality (20 points)
    metrics = final_output.get("engagementMetrics", {})
    engagement_score = 0.0

    duration = metrics.get("engagementDurationSeconds", 0)
    if duration > 0:
        engagement_score += 5.0
    if duration > 60:
        engagement_score += 5.0

    msg_count = metrics.get("totalMessagesExchanged", 0)
    if msg_count > 0:
        engagement_score += 5.0
    if msg_count >= 5:
        engagement_score += 5.0

    breakdown["engagementQuality"] = engagement_score
    score += engagement_score

    # 4. Response Structure (20 points)
    structure_score = 0.0

    if "status" in final_output:
        structure_score += 5.0
    if "scamDetected" in final_output:
        structure_score += 5.0
    if "extractedIntelligence" in final_output:
        structure_score += 5.0
    if "engagementMetrics" in final_output:
        structure_score += 2.5
    if "agentNotes" in final_output:
        structure_score += 2.5

    breakdown["responseStructure"] = structure_score
    score += structure_score

    return {
        "score": round(score, 2),
        "breakdown": breakdown,
    }


# ═══════════════════════════════════════════════
# Multi-Turn Conversation Simulator
# ═══════════════════════════════════════════════

def run_scenario(base_url: str, scenario_id: str, scenario: dict, verbose: bool = True) -> dict:
    """Run a single scenario with 10 conversation turns, return final evaluation."""
    session_id = f"test-{scenario_id}-{uuid.uuid4().hex[:8]}"
    conversation_history = []
    all_responses = []
    final_output = None
    start_time = time.time()

    if verbose:
        print(f"\n{'='*70}")
        print(f"  SCENARIO: {scenario['name']} ({scenario_id})")
        print(f"  Session: {session_id}")
        print(f"{'='*70}")

    for turn_idx, scammer_msg in enumerate(scenario["turns"][:MAX_TURNS]):
        turn_num = turn_idx + 1
        
        payload = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": scammer_msg,
            },
            "conversationHistory": conversation_history,
            "persona": {
                "name": "Tejash S",
                "age": "28",
                "occupation": "Software Engineer",
                "location": "Perundurai",
                "bank": "SBI",
                "gender": "Male",
                "language": "English",
            },
            "metadata": {
                "scenarioId": scenario_id,
                "turnNumber": turn_num,
            },
        }

        data = None
        for attempt in range(RETRY_ATTEMPTS):
            try:
                resp = requests.post(
                    f"{base_url}{ENDPOINT}",
                    json=payload,
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                data = resp.json()
                break
            except requests.exceptions.Timeout:
                if verbose:
                    print(f"  ⏱️  Turn {turn_num}: TIMEOUT (attempt {attempt+1}/{RETRY_ATTEMPTS})")
                if attempt < RETRY_ATTEMPTS - 1:
                    time.sleep(RETRY_DELAY)
            except Exception as e:
                if verbose:
                    print(f"  ⚠️  Turn {turn_num}: {e} (attempt {attempt+1}/{RETRY_ATTEMPTS})")
                if attempt < RETRY_ATTEMPTS - 1:
                    time.sleep(RETRY_DELAY)
        
        if data is None:
            data = {"status": "error", "reply": "all retries failed", "error": "timeout"}

        all_responses.append(data)
        final_output = data

        # Build conversation history for next turn
        reply = data.get("reply", "")
        conversation_history.append({"sender": "scammer", "text": scammer_msg})
        conversation_history.append({"sender": "agent", "text": reply})

        if verbose:
            status_icon = "✅" if data.get("status") == "success" else "❌"
            scam = "🚨" if data.get("scamDetected") else "➖"
            intel_count = sum(len(v) for v in data.get("extractedIntelligence", {}).values() if isinstance(v, list))
            print(f"  Turn {turn_num:2d}: {status_icon} {scam} Intel:{intel_count:2d} | Reply: {reply[:80]}...")

    elapsed = time.time() - start_time

    # Evaluate final output
    if final_output and final_output.get("status") == "success":
        evaluation = evaluate_final_output(final_output)
    else:
        evaluation = {"score": 0, "breakdown": {"scamDetection": 0, "intelligenceExtraction": 0, "engagementQuality": 0, "responseStructure": 0}}

    if verbose:
        print(f"\n  📊 SCORE: {evaluation['score']}/100 ({elapsed:.1f}s)")
        bd = evaluation["breakdown"]
        print(f"     Scam Detection:     {bd['scamDetection']:5.1f}/20")
        print(f"     Intelligence:       {bd['intelligenceExtraction']:5.1f}/40")
        print(f"     Engagement:         {bd['engagementQuality']:5.1f}/20")
        print(f"     Response Structure: {bd['responseStructure']:5.1f}/20")
        
        # Show extracted intelligence
        if final_output:
            intel = final_output.get("extractedIntelligence", {})
            for key, vals in intel.items():
                if vals:
                    print(f"     📌 {key}: {vals}")
            
            metrics = final_output.get("engagementMetrics", {})
            if metrics:
                print(f"     ⏱️  Duration: {metrics.get('engagementDurationSeconds', 0):.1f}s | Messages: {metrics.get('totalMessagesExchanged', 0)}")

    return {
        "scenario_id": scenario_id,
        "scenario_name": scenario["name"],
        "score": evaluation["score"],
        "breakdown": evaluation["breakdown"],
        "elapsed": elapsed,
        "turns_completed": len(all_responses),
        "errors": sum(1 for r in all_responses if r.get("status") != "success"),
        "final_output": final_output,
    }


# ═══════════════════════════════════════════════
# Main Test Runner
# ═══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Honeypot API Test Suite")
    parser.add_argument("--url", default=DEFAULT_BASE_URL, help="Base URL of the API")
    parser.add_argument("--scenario", default=None, help="Run a single scenario (e.g., bank_fraud)")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    verbose = not args.quiet

    scenarios_to_run = {args.scenario: SCENARIOS[args.scenario]} if args.scenario else SCENARIOS

    print(f"\n{'#'*70}")
    print(f"  🍯 HONEYPOT API TEST SUITE")
    print(f"  Target: {base_url}{ENDPOINT}")
    print(f"  Scenarios: {len(scenarios_to_run)}")
    print(f"  Max turns per scenario: {MAX_TURNS}")
    print(f"  Total API calls: ~{len(scenarios_to_run) * MAX_TURNS}")
    print(f"{'#'*70}")

    # Health check
    try:
        health = requests.get(f"{base_url}/health", timeout=5)
        print(f"\n  Health: {health.json()}")
    except Exception as e:
        print(f"\n  ⚠️  Health check failed: {e}")
        print(f"  Make sure the server is running at {base_url}")
        return

    # Run scenarios
    results = []
    for i, (scenario_id, scenario) in enumerate(scenarios_to_run.items()):
        if i > 0:
            if verbose:
                print(f"\n  ⏳ Waiting {SCENARIO_DELAY}s before next scenario...")
            time.sleep(SCENARIO_DELAY)
        result = run_scenario(base_url, scenario_id, scenario, verbose)
        results.append(result)

    # ═══ Final Summary ═══
    print(f"\n\n{'#'*70}")
    print(f"  📋 FINAL EVALUATION SUMMARY")
    print(f"{'#'*70}")
    print(f"\n  {'Scenario':<25} {'Score':>6} {'Scam':>5} {'Intel':>6} {'Engage':>7} {'Struct':>7} {'Errors':>7}")
    print(f"  {'─'*25} {'─'*6} {'─'*5} {'─'*6} {'─'*7} {'─'*7} {'─'*7}")

    total_score = 0
    total_scenarios = len(results)
    perfect_scenarios = 0

    for r in results:
        bd = r["breakdown"]
        err_str = f"  {r['errors']}" if r["errors"] > 0 else "  0"
        score_str = f"{r['score']:5.1f}"
        print(f"  {r['scenario_name']:<25} {score_str:>6} {bd['scamDetection']:>5.0f} {bd['intelligenceExtraction']:>6.0f} {bd['engagementQuality']:>7.0f} {bd['responseStructure']:>7.1f} {err_str:>7}")
        total_score += r["score"]
        if r["score"] >= 100:
            perfect_scenarios += 1

    avg_score = total_score / total_scenarios if total_scenarios > 0 else 0

    print(f"\n  {'='*70}")
    print(f"  AVERAGE SCORE: {avg_score:.1f}/100")
    print(f"  TOTAL SCORE (sum): {total_score:.1f}/{total_scenarios * 100}")
    print(f"  PERFECT SCENARIOS: {perfect_scenarios}/{total_scenarios}")
    print(f"  API ERRORS: {sum(r['errors'] for r in results)}")
    print(f"  {'='*70}")

    # Grade
    if avg_score >= 95:
        grade = "🏆 EXCELLENT — Ready for competition!"
    elif avg_score >= 85:
        grade = "✅ GOOD — Minor improvements needed"
    elif avg_score >= 70:
        grade = "⚠️ FAIR — Intelligence extraction needs work"
    else:
        grade = "❌ NEEDS WORK — Major scoring gaps"

    print(f"\n  GRADE: {grade}")
    print(f"\n  Detailed results saved to: test_results.json\n")

    # Save results
    with open("test_results.json", "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "base_url": base_url,
            "average_score": avg_score,
            "total_scenarios": total_scenarios,
            "perfect_scenarios": perfect_scenarios,
            "results": [{
                "scenario_id": r["scenario_id"],
                "scenario_name": r["scenario_name"],
                "score": r["score"],
                "breakdown": r["breakdown"],
                "elapsed": r["elapsed"],
                "errors": r["errors"],
            } for r in results],
        }, f, indent=2)


if __name__ == "__main__":
    main()
