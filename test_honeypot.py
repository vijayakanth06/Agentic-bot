"""
Agentic Honeypot — Comprehensive API Test Suite

Tests the deployed API with:
  1. GUVI Test Case 1 (SBI bank fraud — multi-turn)
  2. GUVI Test Case 2 (SBI bank fraud variant)
  3. Additional scam categories: UPI, KYC, OTP, lottery, job, threat, phishing
  4. Intelligence extraction validation
  5. Detailed report output

Usage:
  python test_honeypot.py                          # test local server
  python test_honeypot.py https://your-app.vercel.app  # test deployed
"""

import httpx
import json
import sys
import time
from datetime import datetime

# ─── Config ───
BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
API_KEY = "fae26946fc2015d9bd6f1ddbb447e2f7"
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}
TIMEOUT = 30

# ─── Colors ───
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def send_message(session_id: str, text: str, history: list[dict] = None) -> dict:
    """Send a single message to the honeypot API."""
    payload = {
        "sessionId": session_id,
        "message": {"sender": "scammer", "text": text},
        "conversationHistory": history or [],
        "metadata": {},
    }
    try:
        r = httpx.post(f"{BASE_URL}/api/honeypot", json=payload, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def run_conversation(session_id: str, messages: list[str], label: str) -> dict:
    """Run a multi-turn conversation and collect results."""
    print(f"\n{'='*70}")
    print(f"{BOLD}{CYAN}  TEST: {label}{RESET}")
    print(f"{'='*70}")

    history = []
    results = []
    all_intel = {}
    final_response = None

    for i, msg in enumerate(messages, 1):
        print(f"\n{YELLOW}  Scammer [{i}/{len(messages)}]:{RESET} {msg[:100]}{'...' if len(msg)>100 else ''}")

        resp = send_message(session_id, msg, history)
        if "error" in resp:
            print(f"  {RED}ERROR: {resp['error']}{RESET}")
            results.append({"turn": i, "error": resp["error"]})
            continue

        reply = resp.get("reply", "")
        scam_detected = resp.get("scamDetected", False)
        confidence = resp.get("analysis", {}).get("scam_confidence", 0)
        scam_type = resp.get("analysis", {}).get("scam_type", "unknown")
        urgency = resp.get("analysis", {}).get("urgency_level", "low")
        intel = resp.get("extractedIntelligence", {})

        print(f"  {GREEN}Honeypot:{RESET} {reply[:120]}{'...' if len(reply)>120 else ''}")
        print(f"  {DIM}scamDetected={scam_detected} | confidence={confidence:.2f} | type={scam_type} | urgency={urgency}{RESET}")

        # Track extracted intelligence
        for key in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
            items = intel.get(key, [])
            if items:
                all_intel.setdefault(key, set()).update(items)
                print(f"  {CYAN}  → {key}: {items}{RESET}")

        history.append({"sender": "scammer", "text": msg})
        history.append({"sender": "agent", "text": reply})
        final_response = resp
        results.append({
            "turn": i,
            "reply": reply,
            "scamDetected": scam_detected,
            "confidence": confidence,
            "scam_type": scam_type,
            "urgency": urgency,
            "intel": intel,
        })

    # Convert sets to lists for JSON
    all_intel = {k: list(v) for k, v in all_intel.items()}
    return {
        "label": label,
        "session_id": session_id,
        "turns": len(messages),
        "results": results,
        "all_intel": all_intel,
        "final_response": final_response,
    }


# ═══════════════════════════════════════════════
# TEST CASES
# ═══════════════════════════════════════════════

GUVI_TEST_1 = [
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
]

GUVI_TEST_2 = [
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
]

UPI_FRAUD_TEST = [
    "Hi, I accidentally sent Rs. 5000 to your UPI ID instead of someone else. Can you please send it back to my UPI priya.refund@ybl?",
    "Please check your account, the money should be there. Just send it back to priya.refund@ybl using Google Pay or PhonePe. My phone number is 9123456789.",
    "I'm really in trouble, please help. You can also transfer to my bank account 12345678901234 at HDFC Bank, IFSC: HDFC0001234.",
]

KYC_SCAM_TEST = [
    "Dear Customer, your KYC has expired. Update your KYC immediately or your account will be suspended within 24 hours. Click here to update: https://sbi-kyc-update.com/verify",
    "This is from SBI KYC department. Your PAN card ABCDE1234F needs immediate verification. Share your Aadhaar number for cross-verification.",
    "Your KYC update is mandatory. Failure to comply will result in account freezing. Send your details to our secure portal immediately.",
]

LOTTERY_SCAM_TEST = [
    "Congratulations! You have been selected as the lucky winner of Rs. 25 Lakhs in the Amazon Lucky Draw 2024! Claim your prize now by paying a processing fee of Rs. 999.",
    "To claim your prize, transfer Rs. 999 to our UPI ID prize.claim@okaxis. Contact our manager Mr. Vijay at +91-8765432109 for assistance.",
    "This is your last chance! The prize will expire in 2 hours. Send the processing fee immediately to redeem your Rs. 25 Lakh jackpot reward.",
]

JOB_SCAM_TEST = [
    "URGENT JOB OFFER: Earn Rs. 50,000/month working from home! Part-time data entry job with guaranteed income. No experience needed!",
    "To register, pay Rs. 500 registration fee to our UPI ID jobs.hiring@paytm. Contact HR manager Priyanka at +91-7654321098 for immediate placement.",
    "Easy money, quick returns! Work just 2 hours daily. Send your resume to hr@quickjobs-india.com and pay activation fee to start earning.",
]

THREAT_SCAM_TEST = [
    "This is the Cyber Crime Department. Your Aadhaar aadhaar 1234-5678-9012 has been used in suspicious activities. An arrest warrant has been issued against you.",
    "Legal action will be taken if you don't cooperate. You need to pay a fine of Rs. 50,000 immediately. Contact officer Amit at +91-6543210987.",
    "If you don't pay the fine within 1 hour, FIR will be filed and your SIM card will be blocked permanently. Transfer to account 9876543210123 IFSC: ICIC0005678.",
]


def run_all_tests():
    """Run all test cases and generate report."""
    print(f"\n{BOLD}{'═'*70}")
    print(f"  🍯 AGENTIC HONEYPOT — COMPREHENSIVE TEST SUITE")
    print(f"  Target: {BASE_URL}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*70}{RESET}")

    # 0. Health check
    print(f"\n{DIM}Health check...{RESET}", end=" ")
    try:
        r = httpx.get(f"{BASE_URL}/health", timeout=10)
        print(f"{GREEN}OK{RESET} ({r.json()})")
    except Exception as e:
        print(f"{RED}FAILED: {e}{RESET}")
        print("Make sure the server is running!")
        return

    all_results = []

    test_cases = [
        ("guvi-1", GUVI_TEST_1, "GUVI Test 1: SBI Bank Fraud (10 turns)"),
        ("guvi-2", GUVI_TEST_2, "GUVI Test 2: SBI Bank Fraud Variant (10 turns)"),
        ("upi-1",  UPI_FRAUD_TEST, "UPI Refund Fraud (3 turns)"),
        ("kyc-1",  KYC_SCAM_TEST, "KYC Expiry Scam (3 turns)"),
        ("lottery-1", LOTTERY_SCAM_TEST, "Lottery/Prize Scam (3 turns)"),
        ("job-1",  JOB_SCAM_TEST, "Job/Income Scam (3 turns)"),
        ("threat-1", THREAT_SCAM_TEST, "Threat/Legal Scam (3 turns)"),
    ]

    for sid, messages, label in test_cases:
        result = run_conversation(sid, messages, label)
        all_results.append(result)
        time.sleep(0.5)  # small delay between tests

    # ═══════════════════════════════════════════════
    # FINAL REPORT
    # ═══════════════════════════════════════════════
    print(f"\n\n{'═'*70}")
    print(f"{BOLD}{CYAN}  📊 FINAL TEST REPORT{RESET}")
    print(f"{'═'*70}")

    total_turns = 0
    total_scam_detected = 0
    total_intel = {"bankAccounts": set(), "upiIds": set(), "phoneNumbers": set(), "phishingLinks": set()}

    for res in all_results:
        label = res["label"]
        turns = res["turns"]
        total_turns += turns

        last = res["results"][-1] if res["results"] else {}
        detected = last.get("scamDetected", False)
        conf = last.get("confidence", 0)
        stype = last.get("scam_type", "?")
        urgency = last.get("urgency", "?")
        intel = res["all_intel"]

        status = f"{GREEN}✅ DETECTED{RESET}" if detected else f"{RED}❌ MISSED{RESET}"
        if detected:
            total_scam_detected += 1

        print(f"\n  {BOLD}{label}{RESET}")
        print(f"    Status:     {status}")
        print(f"    Confidence: {conf:.2f} | Type: {stype} | Urgency: {urgency}")
        print(f"    Turns:      {turns}")

        if intel:
            print(f"    {CYAN}Extracted Intelligence:{RESET}")
            for key, items in intel.items():
                if items:
                    print(f"      • {key}: {items}")
                    if key in total_intel:
                        total_intel[key].update(items)

    # Summary
    print(f"\n{'─'*70}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"  Total conversations: {len(all_results)}")
    print(f"  Total turns:         {total_turns}")
    print(f"  Scams detected:      {total_scam_detected}/{len(all_results)}")
    print(f"  Detection rate:      {total_scam_detected/len(all_results)*100:.0f}%")
    print(f"\n  {BOLD}Total Intelligence Extracted:{RESET}")
    for key, items in total_intel.items():
        print(f"    • {key}: {len(items)} unique — {list(items)[:5]}")
    print(f"{'─'*70}\n")

    # Save JSON report
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": BASE_URL,
        "total_conversations": len(all_results),
        "total_turns": total_turns,
        "scams_detected": total_scam_detected,
        "detection_rate": f"{total_scam_detected/len(all_results)*100:.0f}%",
        "total_intelligence": {k: list(v) for k, v in total_intel.items()},
        "tests": [
            {
                "label": r["label"],
                "session_id": r["session_id"],
                "turns": r["turns"],
                "intel": r["all_intel"],
                "last_result": r["results"][-1] if r["results"] else {},
            }
            for r in all_results
        ],
    }
    with open("test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"  {GREEN}Report saved to test_report.json{RESET}\n")


if __name__ == "__main__":
    run_all_tests()
