"""
Competition-exact curl test — simulates the GUVI evaluation platform.
Tests response format, timing, intelligence extraction, and scoring.
"""
import urllib.request
import json
import time
import uuid

BASE = "http://localhost:8001/api/honeypot"
API_KEY = "fae26946fc2015d9bd6f1ddbb447e2f7"
SESSION = str(uuid.uuid4())

# Competition scenario (bank_fraud from docs) — all 5 intelligence types
FAKE_DATA = {
    "bankAccount": "1234567890123456",
    "upiId": "scammer.fraud@fakebank",
    "phoneNumber": "+91-9876543210",
    "phishingLink": "http://sbi-verify.fakesite.com/secure",
    "emailAddress": "support.sbi@fraudmail.com",
}

TURNS = [
    "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
    "Your account is flagged for suspicious activity and will be blocked unless you verify it now; please send your 6-digit OTP and confirm your account number 1234567890123456 immediately.",
    "I'm from SBI's fraud prevention team - we need the OTP right now to lift the block, please send it immediately so we can secure your account. You can reach us at support.sbi@fraudmail.com for verification.",
    "You can call me at +91-9876543210, but we need the OTP right now to lift the block and secure your account.",
    "I understand your concern — please verify your identity at http://sbi-verify.fakesite.com/secure and send the OTP now to lift the block on account 1234567890123456.",
    "The branch is SBI Main Branch, 123 MG Road, Mumbai. Please transfer Rs 5000 to scammer.fraud@fakebank to unlock your account immediately.",
]

METADATA = {"channel": "SMS", "language": "English", "locale": "IN"}

history = []
all_times = []
last_response = None

print(f"Session: {SESSION}")
print("=" * 70)

for i, msg in enumerate(TURNS):
    turn = i + 1
    print(f"\n--- Turn {turn} ---")
    print(f"Scammer: {msg[:80]}...")
    
    payload = json.dumps({
        "sessionId": SESSION,
        "message": {
            "sender": "scammer",
            "text": msg,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "conversationHistory": history,
        "metadata": METADATA
    }).encode()
    
    req = urllib.request.Request(
        BASE, data=payload,
        headers={"Content-Type": "application/json", "x-api-key": API_KEY}
    )
    
    t = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        elapsed = time.time() - t
        data = json.loads(resp.read())
        all_times.append(elapsed)
        last_response = data
        
        reply = data.get("reply", "NO REPLY")
        status_ok = "status" in data
        scam_ok = "scamDetected" in data
        intel_ok = "extractedIntelligence" in data
        engage_ok = "engagementMetrics" in data
        notes_ok = "agentNotes" in data
        
        print(f"  Reply: {reply}")
        print(f"  Time: {elapsed:.2f}s {'OK' if elapsed < 30 else 'TIMEOUT!'}")
        print(f"  scamDetected: {data.get('scamDetected')}")
        print(f"  Fields: status={status_ok} scamDetected={scam_ok} intel={intel_ok} engagement={engage_ok} notes={notes_ok}")
        
        # Update history as evaluator would
        history.append({"sender": "scammer", "text": msg, "timestamp": str(int(time.time()*1000))})
        history.append({"sender": "user", "text": reply, "timestamp": str(int(time.time()*1000))})
        
    except Exception as e:
        elapsed = time.time() - t
        print(f"  ERROR: {e} ({elapsed:.2f}s)")
        all_times.append(elapsed)

# === SCORING ===
print("\n" + "=" * 70)
print("FINAL OUTPUT SCORING (last response as finalOutput)")
print("=" * 70)

if last_response:
    fo = last_response
    
    # 1. Scam Detection (20 pts)
    sd = 20 if fo.get("scamDetected") else 0
    
    # 2. Intelligence Extraction (40 pts)
    ie = 0
    extracted = fo.get("extractedIntelligence", {})
    key_map = {
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phoneNumber": "phoneNumbers",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses",
    }
    for fake_key, fake_val in FAKE_DATA.items():
        out_key = key_map.get(fake_key, fake_key)
        vals = extracted.get(out_key, [])
        if isinstance(vals, list) and any(fake_val in str(v) for v in vals):
            ie += 8  # 5 types × 8 = 40 max
            print(f"  Intel OK: {fake_key} = {fake_val}")
        else:
            print(f"  Intel MISS: {fake_key} = {fake_val} (got: {vals})")
    ie = min(ie, 40)
    
    # 3. Engagement Quality (20 pts)
    eq = 0
    metrics = fo.get("engagementMetrics", {})
    dur = metrics.get("engagementDurationSeconds", 0)
    msgs = metrics.get("totalMessagesExchanged", 0)
    if dur > 0: eq += 5
    if dur > 60: eq += 5
    if msgs > 0: eq += 5
    if msgs >= 5: eq += 5
    print(f"  Engagement: duration={dur:.1f}s, messages={msgs}")
    
    # 4. Response Structure (20 pts)
    rs = 0
    for f in ["status", "scamDetected", "extractedIntelligence"]:
        if f in fo: rs += 5
    for f in ["engagementMetrics", "agentNotes"]:
        if f in fo and fo[f]: rs += 2.5
    rs = min(rs, 20)
    
    total = sd + ie + eq + rs
    
    print(f"\n  Scam Detection:        {sd}/20")
    print(f"  Intelligence Extract:  {ie}/40")
    print(f"  Engagement Quality:    {eq}/20")
    print(f"  Response Structure:    {rs}/20")
    print(f"  ─────────────────────────────")
    print(f"  TOTAL SCORE:           {total}/100")
    
print(f"\n  Response times: {['%.2fs' % t for t in all_times]}")
print(f"  Average: {sum(all_times)/len(all_times):.2f}s")
print(f"  Max: {max(all_times):.2f}s")
print(f"  All under 30s: {'YES' if all(t < 30 for t in all_times) else 'NO'}")
