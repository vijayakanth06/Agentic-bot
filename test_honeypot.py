"""
Agentic Honeypot — Comprehensive API Test Suite (v2)

Tests 12 scam categories + edge cases for 100% coverage.

Usage:
  python test_honeypot.py                                    # local :8000
  python test_honeypot.py http://localhost:8001               # custom port
  python test_honeypot.py https://your-app.vercel.app         # deployed
"""

import httpx
import json
import sys
import time
from datetime import datetime

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
API_KEY = "fae26946fc2015d9bd6f1ddbb447e2f7"
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}
TIMEOUT = 30

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; D = "\033[2m"; X = "\033[0m"


def send(sid, text, history=None):
    payload = {"sessionId": sid, "message": {"sender": "scammer", "text": text},
               "conversationHistory": history or [], "metadata": {}}
    try:
        r = httpx.post(f"{BASE_URL}/api/honeypot", json=payload, headers=HEADERS, timeout=TIMEOUT)
        return r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def run_convo(sid, msgs, label):
    print(f"\n{'='*70}\n{B}{C}  {label}{X}\n{'='*70}")
    history, all_intel, final = [], {}, None
    for i, msg in enumerate(msgs, 1):
        print(f"\n{Y}  Scammer [{i}/{len(msgs)}]:{X} {msg[:100]}{'...' if len(msg)>100 else ''}")
        resp = send(sid, msg, history)
        if "error" in resp:
            print(f"  {R}ERROR: {resp['error']}{X}"); continue
        reply = resp.get("reply", "")
        det = resp.get("scamDetected", False)
        conf = resp.get("analysis", {}).get("scam_confidence", 0)
        stype = resp.get("analysis", {}).get("scam_type", "?")
        urg = resp.get("analysis", {}).get("urgency_level", "?")
        intel = resp.get("extractedIntelligence", {})
        print(f"  {G}Honeypot:{X} {reply[:120]}{'...' if len(reply)>120 else ''}")
        print(f"  {D}detected={det} | conf={conf:.2f} | type={stype} | urgency={urg}{X}")
        for key in ["bankAccounts","upiIds","phishingLinks","phoneNumbers","suspiciousKeywords"]:
            items = intel.get(key, [])
            if items:
                all_intel.setdefault(key, set()).update(items)
                print(f"  {C}  → {key}: {items}{X}")
        history.append({"sender":"scammer","text":msg})
        history.append({"sender":"agent","text":reply})
        final = resp
    all_intel = {k: list(v) for k, v in all_intel.items()}
    return {"label": label, "sid": sid, "turns": len(msgs), "intel": all_intel, "final": final,
            "detected": (final or {}).get("scamDetected", False),
            "confidence": (final or {}).get("analysis", {}).get("scam_confidence", 0),
            "scam_type": (final or {}).get("analysis", {}).get("scam_type", "?")}


# ═══════════════════════════════════════════════
# 12 TEST SCENARIOS
# ═══════════════════════════════════════════════

TESTS = [
    # 1. GUVI Test 1 — Bank fraud multi-turn (10 msgs)
    ("guvi-1", "GUVI Test 1: SBI Bank Fraud (10 turns)", [
        "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "My employee ID is 12345, I'm calling from the SBI Delhi branch, and you can reach me at +91-9876543210; please send the OTP now to verify your account.",
        "My name is Ramesh Kumar, and the SBI Delhi helpline is 1800-11-1234; please send the OTP now so we can secure your account.",
        "Sure, my UPI ID is scammer.fraud@fakebank; please send the OTP now so we can secure your account immediately.",
        "Sir, I understand your concerns, but this is a security verification from SBI Delhi; please share the OTP you received right away so we can protect your account 1234567890123456.",
        "Here is the reference number: REF987654. Please send the OTP you received immediately so we can complete the verification; you can also check the status at https://sbi-security.com/verify?ref=REF987654.",
        "This is the official SBI portal, and the OTP you received is the only way to protect your account 1234567890123456—please send it now before the session expires.",
        "I'm from the Delhi branch, employee ID 98765; please send the OTP you received immediately so we can secure your account 1234567890123456 before the session times out.",
        "You can call me at +91-9876543210 if needed, but please send the OTP you received right away so we can finish securing your account 1234567890123456 before the session expires.",
        "I'm Rahul Sharma from the Delhi branch, and my supervisor is Mr. Anil Kumar; please send the OTP you received right away so we can secure your account 1234567890123456 before the session expires.",
    ]),

    # 2. GUVI Test 2 — Bank fraud variant (10 msgs)
    ("guvi-2", "GUVI Test 2: SBI Bank Fraud Variant (10 turns)", [
        "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "My employee ID is 00123 and I'm calling from the Delhi branch; you can verify me at +91-9876543210, now please share your account number and OTP to secure your account.",
        "I am Rajesh Kumar, senior officer at SBI Delhi branch; you can reach me at +91-9876543210. Please send your OTP right away so we can secure your account.",
        "Reference number is REF987654; you can email me at support@sbi-delhi.com, but I need your account number and OTP immediately to prevent the block.",
        "Please use our secure link https://sbi-secure.com/update?ref=REF987654 to verify; once you log in, send me the OTP you receive right away so we can unblock your account.",
        "Sure, the UPI ID is scammer.fraud@fakebank. Please send the OTP you receive from the secure link immediately so we can unblock your account.",
        "Our official email is support@sbi-delhi.com; the verification link is still active, please send me the OTP you receive right away so we can release the hold on your account.",
        "Yes, my employee ID is 00123. Please send the OTP you receive from the secure link right away so we can unblock your account.",
        "We're calling from the SBI Delhi main branch and the verification link will expire in a few minutes – please send the OTP you just received so we can immediately unblock your account.",
        "My full name is Amit Sharma. Please send the OTP you just received right away, the verification link will expire in a few minutes.",
    ]),

    # 3. UPI Refund Fraud (subtle social engineering)
    ("upi-1", "UPI Refund Fraud (3 turns)", [
        "Hi, I accidentally sent Rs. 5000 to your UPI ID instead of someone else. Can you please send it back to my UPI priya.refund@ybl?",
        "Please check your account, the money should be there. Just send it back to priya.refund@ybl using Google Pay or PhonePe. My phone number is 9123456789.",
        "I'm really in trouble, please help. You can also transfer to my bank account 12345678901234 at HDFC Bank, IFSC: HDFC0001234.",
    ]),

    # 4. KYC Scam
    ("kyc-1", "KYC Expiry Scam (3 turns)", [
        "Dear Customer, your KYC has expired. Update your KYC immediately or your account will be suspended within 24 hours. Click here to update: https://sbi-kyc-update.com/verify",
        "This is from SBI KYC department. Your PAN card ABCDE1234F needs immediate verification. Share your Aadhaar number for cross-verification.",
        "Your KYC update is mandatory. Failure to comply will result in account freezing. Send your details to our secure portal immediately.",
    ]),

    # 5. Lottery / Prize
    ("lottery-1", "Lottery/Prize Scam (3 turns)", [
        "Congratulations! You have been selected as the lucky winner of Rs. 25 Lakhs in the Amazon Lucky Draw 2024! Claim your prize now by paying a processing fee of Rs. 999.",
        "To claim your prize, transfer Rs. 999 to our UPI ID prize.claim@okaxis. Contact our manager Mr. Vijay at +91-8765432109 for assistance.",
        "This is your last chance! The prize will expire in 2 hours. Send the processing fee immediately to redeem your Rs. 25 Lakh jackpot reward.",
    ]),

    # 6. Job / Income
    ("job-1", "Job/Income Scam (3 turns)", [
        "URGENT JOB OFFER: Earn Rs. 50,000/month working from home! Part-time data entry job with guaranteed income. No experience needed!",
        "To register, pay Rs. 500 registration fee to our UPI ID jobs.hiring@paytm. Contact HR manager Priyanka at +91-7654321098 for immediate placement.",
        "Easy money, quick returns! Work just 2 hours daily. Send your resume to hr@quickjobs-india.com and pay activation fee to start earning.",
    ]),

    # 7. Threat / Legal
    ("threat-1", "Threat/Legal Scam (3 turns)", [
        "This is the Cyber Crime Department. Your Aadhaar aadhaar 1234-5678-9012 has been used in suspicious activities. An arrest warrant has been issued against you.",
        "Legal action will be taken if you don't cooperate. You need to pay a fine of Rs. 50,000 immediately. Contact officer Amit at +91-6543210987.",
        "If you don't pay the fine within 1 hour, FIR will be filed and your SIM card will be blocked permanently. Transfer to account 9876543210123 IFSC: ICIC0005678.",
    ]),

    # 8. Investment / Ponzi
    ("invest-1", "Investment/Ponzi Scam (3 turns)", [
        "Exclusive opportunity! Invest Rs. 10,000 today and get guaranteed returns of Rs. 1,00,000 in just 30 days. SEBI registered company with 100% assured profit.",
        "Double your money in 15 days! Join our forex trading group. Transfer Rs. 5000 to start. UPI: invest.guru@ybl. Contact Vikash at +91-9988776655.",
        "Last 3 slots remaining! This investment scheme has 10x returns guaranteed by our SEBI registered fund manager. Act now before the offer expires!",
    ]),

    # 9. Tech Support / Remote Access
    ("tech-1", "Tech Support Scam (3 turns)", [
        "ALERT: We have detected a virus on your computer. Your banking details may have been compromised. Call our tech support immediately at +91-8877665544.",
        "To fix this issue, download TeamViewer and give us remote access. Our technician Mr. Suresh will connect to your system and remove the malware. Employee ID: TS-4567.",
        "This is Microsoft Security. Your Windows license has expired and hackers are accessing your files. Install AnyDesk now and share the code: connect remotely to fix it.",
    ]),

    # 10. Delivery / Customs Fee
    ("delivery-1", "Delivery/Customs Scam (3 turns)", [
        "Your international parcel from Amazon UK is held at customs. Pay customs clearance fee of Rs. 2,500 immediately or it will be returned to sender.",
        "Dear customer, your package tracking ID TRK9876543 requires immediate customs duty payment. Transfer Rs. 2500 to customs.dept@ybl to release your package.",
        "This is India Post. If you don't pay the delivery fee within 24 hours, your parcel will be destroyed. Contact officer at +91-7766554433 for clearance.",
    ]),

    # 11. Insurance / Pension Fraud
    ("insurance-1", "Insurance/Pension Fraud (3 turns)", [
        "Dear policyholder, your LIC policy is about to lapse. Pay the premium immediately to avoid losing all benefits. Your policy number is LIC-2024-789012.",
        "This is from LIC Head Office. Your maturity bonus of Rs. 5,00,000 is ready for disbursement. Pay processing fee Rs. 3000 to lic.claims@paytm to receive it.",
        "If you don't pay the processing fee immediately, your LIC bonus will be forfeited. Send Rs. 3000 right now. Call our manager Deepak at +91-6655443322.",
    ]),

    # 12. Electricity / Utility Bill
    ("utility-1", "Utility Bill Disconnection (3 turns)", [
        "Your electricity connection will be disconnected today due to pending bill of Rs. 3,456. Pay immediately to avoid disconnection. Call +91-5544332211.",
        "Dear consumer, this is from the electricity department. Your bill is overdue. Pay Rs. 3456 to avoid disconnection. UPI: power.bill@oksbi. Consumer ID: ELEC-789456.",
        "FINAL WARNING: Power supply will be cut in 2 hours. Share your consumer number and pay Rs. 3456 immediately. Failure to pay will result in permanent disconnection.",
    ]),
]


def run_all():
    print(f"\n{B}{'═'*70}")
    print(f"  🍯 AGENTIC HONEYPOT — COMPREHENSIVE TEST SUITE v2")
    print(f"  Target: {BASE_URL}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Tests:  {len(TESTS)} scenarios")
    print(f"{'═'*70}{X}")

    # Health check
    print(f"\n{D}Health check...{X}", end=" ")
    try:
        r = httpx.get(f"{BASE_URL}/health", timeout=10)
        print(f"{G}OK{X} ({r.json()})")
    except Exception as e:
        print(f"{R}FAILED: {e}{X}"); return

    results = []
    for sid, label, msgs in TESTS:
        res = run_convo(sid, msgs, label)
        results.append(res)
        time.sleep(0.3)

    # ═══════════════════════════════════════════════
    # REPORT
    # ═══════════════════════════════════════════════
    print(f"\n\n{'═'*70}")
    print(f"{B}{C}  📊 FINAL TEST REPORT{X}")
    print(f"{'═'*70}")

    total_det = 0
    total_intel = {"bankAccounts": set(), "upiIds": set(), "phoneNumbers": set(), "phishingLinks": set()}

    for r in results:
        status = f"{G}✅ DETECTED{X}" if r["detected"] else f"{R}❌ MISSED{X}"
        if r["detected"]: total_det += 1
        print(f"\n  {B}{r['label']}{X}")
        print(f"    {status} | conf={r['confidence']:.2f} | type={r['scam_type']}")
        if r["intel"]:
            for k, v in r["intel"].items():
                if v and k != "suspiciousKeywords":
                    print(f"    {C}• {k}: {v}{X}")
                    if k in total_intel: total_intel[k].update(v)

    n = len(results)
    rate = total_det / n * 100

    print(f"\n{'─'*70}")
    print(f"{B}  SUMMARY{X}")
    print(f"  Conversations: {n} | Turns: {sum(r['turns'] for r in results)}")
    print(f"  Detection:     {total_det}/{n} ({rate:.0f}%)")
    if rate == 100:
        print(f"  {G}{B}  🎯 PERFECT 100% DETECTION RATE!{X}")
    print(f"\n  {B}Intelligence:{X}")
    for k, v in total_intel.items():
        print(f"    • {k}: {len(v)} unique")

    # Types detected
    types_seen = set(r["scam_type"] for r in results if r["detected"])
    print(f"\n  {B}Scam Types Classified:{X} {', '.join(sorted(types_seen))}")
    print(f"{'─'*70}\n")

    # Save JSON
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": BASE_URL,
        "total_tests": n,
        "total_turns": sum(r["turns"] for r in results),
        "detected": total_det,
        "detection_rate": f"{rate:.0f}%",
        "intelligence": {k: list(v) for k, v in total_intel.items()},
        "scam_types_classified": sorted(types_seen),
        "tests": [{
            "label": r["label"], "detected": r["detected"],
            "confidence": r["confidence"], "scam_type": r["scam_type"],
            "intel": r["intel"],
        } for r in results],
    }
    with open("test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"  {G}Saved: test_report.json{X}\n")


if __name__ == "__main__":
    run_all()
