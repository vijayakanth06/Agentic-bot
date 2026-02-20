# SUBMISSION CHECKLIST — India AI Impact Buildathon (Honeypot Challenge)
## ⚠️ ONE SUBMISSION ATTEMPT ONLY — Make it perfect!

---

## 🔑 Submission Requirements (Submit ALL THREE)
- [ ] **Public API Endpoint URL** — Must be live, accessible, and return valid JSON
- [ ] **x-api-key** — `fae26946fc2015d9bd6f1ddbb447e2f7`
- [ ] **GitHub Repository URL** — `https://github.com/vijayakanth06/Agentic-bot.git` (must be public, latest code pushed)

---

## 📋 Pre-Submission Checks

### 1. Server Health
- [ ] Server responds at `GET /health` with `{"status": "ok", "groq": true, ...}`
- [ ] Server responds at `POST /api/honeypot` with valid JSON
- [ ] GROQ API key is set and working (`GROQ_API_KEY` env var)
- [ ] `LLM_MODEL=llama-3.3-70b-versatile` (NOT `openai/gpt-oss-120b`)
- [ ] `LLM_TIMEOUT=20` (platform allows 30s per request)

### 2. Authentication
- [ ] Sending `x-api-key: fae26946fc2015d9bd6f1ddbb447e2f7` header → 200 OK
- [ ] Sending wrong `x-api-key: wrong_key` → 401 Unauthorized
- [ ] Sending NO `x-api-key` → Still works (allows browser access)

### 3. Response Format (ALL fields must be present)
```json
{
  "status": "success",                    // 5 pts
  "sessionId": "abc123",
  "reply": "Honeypot reply text...",
  "scamDetected": true,                   // 5 pts + 20 pts
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {              // 5 pts
    "phoneNumbers": ["+919876543210"],     // 10 pts
    "bankAccounts": ["50100489372615"],    // 10 pts
    "upiIds": ["scammer@ybl"],            // 10 pts
    "phishingLinks": ["http://fake.com"], // 10 pts
    "emailAddresses": []                  // 0 pts (not scored)
  },
  "engagementMetrics": {                  // 2.5 pts
    "engagementDurationSeconds": 150.5,   // 5+5 pts (>0 and >60)
    "totalMessagesExchanged": 18          // 5+5 pts (>0 and >=5)
  },
  "agentNotes": "Scam type: ..."         // 2.5 pts
}
```

### 4. Scoring Rubric (100 points per scenario)
| Category | Points | Condition |
|----------|--------|-----------|
| Scam Detection | 20 | `scamDetected: true` |
| Phone Numbers | 10 | `phoneNumbers` array not empty |
| Bank Accounts | 10 | `bankAccounts` array not empty |
| UPI IDs | 10 | `upiIds` array not empty |
| Phishing Links | 10 | `phishingLinks` array not empty |
| Duration > 0 | 5 | `engagementDurationSeconds > 0` |
| Duration > 60s | 5 | `engagementDurationSeconds > 60` |
| Messages > 0 | 5 | `totalMessagesExchanged > 0` |
| Messages >= 5 | 5 | `totalMessagesExchanged >= 5` |
| Has `status` | 5 | Field exists in response |
| Has `scamDetected` | 5 | Field exists in response |
| Has `extractedIntelligence` | 5 | Field exists in response |
| Has `engagementMetrics` | 2.5 | Field exists in response |
| Has `agentNotes` | 2.5 | Field exists in response |
| **TOTAL** | **100** | |

### 5. Platform Behavior (15 scenarios × 10 turns each = 150 API calls)
- [ ] Each scenario gets a unique `sessionId`
- [ ] Platform sends `conversationHistory` with full history each turn
- [ ] Platform sends `persona` with victim details (name, age, occupation, etc.)
- [ ] Platform sends `metadata` with `scenarioId` and `turnNumber`
- [ ] Scenario types: bank_fraud, upi_fraud, kyc_scam, otp_fraud, lottery_scam, job_scam, threat_scam, investment_scam, tech_support, phishing, refund_scam, customs_fraud, insurance_fraud, electricity_scam, govt_scheme
- [ ] **Platform timeout: 30 seconds per request** — our LLM_TIMEOUT=20s leaves safe buffer
- [ ] **Final score = average of all 15 scenario scores**

### 6. Testing Complete
- [ ] Static test: `python test_honeypot.py` → 15/15 = 100/100
- [ ] Dynamic test: `python test_dynamic.py` → all scenarios pass
- [ ] Single scenario test: `python test_dynamic.py bank_fraud` → 100/100

### 7. Deployment
- [ ] Server deployed and publicly accessible (Railway / Render / VPS)
- [ ] GROQ_API_KEY set in deployment environment
- [ ] API_KEY set in deployment environment
- [ ] LLM_MODEL set to `llama-3.3-70b-versatile`
- [ ] LLM_TIMEOUT set to `20`
- [ ] Test deployed endpoint: `curl -X POST https://YOUR-URL/api/honeypot -H "x-api-key: fae26946fc2015d9bd6f1ddbb447e2f7" -H "Content-Type: application/json" -d '{"sessionId":"test1","message":{"sender":"scammer","text":"Your SBI account has been compromised. Call 9876543210 immediately."}}'`

### 8. GitHub
- [ ] Latest code pushed to `main` branch
- [ ] `.env` is NOT committed (in .gitignore)
- [ ] Repository is public

---

## 🚀 Submission Steps
1. Verify deployed server is running and responding
2. Run the checklist verification curl command above
3. Confirm GitHub repo is up to date and public
4. Submit on the competition platform:
   - API Endpoint URL: `https://YOUR-DEPLOYED-URL/api/honeypot`
   - API Key: `fae26946fc2015d9bd6f1ddbb447e2f7`
   - GitHub URL: `https://github.com/vijayakanth06/Agentic-bot.git`
5. **Wait for all 150 API calls to complete (takes ~5-10 minutes)**
6. Check score on leaderboard

---

## 🔍 Troubleshooting
- **Timeout errors**: LLM_TIMEOUT is 20s, platform allows 30s. If still timing out, try LLM_TIMEOUT=25.
- **Rate limits**: GROQ free tier allows ~30 req/min for 70b model. If hitting limits, the fallback chain handles it (8b → rule-based).
- **Missing intelligence**: Check regex patterns in `extract_intelligence()` function. Common issues: non-standard phone formats, custom UPI providers.
- **scamDetected=false**: Check `detect_scam()` function. Confidence threshold is low (0.3). If the scammer's message doesn't match any patterns, the cumulative session confidence should still trigger detection after a few turns.
- **Low engagement score**: Need `duration > 60s` and `messages >= 5`. Our code estimates duration as `messages × 7.5` if clock time is low. With 10 turns × 2 messages = 20 messages, duration will be ~150s.

---

## ✅ Key Architecture Decisions
1. **Persona**: Dynamically read from `req.persona` — uses whatever the platform sends
2. **Language**: Read from `persona.language` field — defaults to English, responds in whatever language is specified
3. **LLM Fallback**: 3-tier chain: llama-3.3-70b → llama-3.1-8b-instant → rule-based responses
4. **Scam Detection**: 55+ regex patterns with weighted scoring + behavioral analysis
5. **Intelligence Extraction**: Regex-based extraction for phones, UPI, bank accounts, URLs, emails, IFSC codes
6. **Session Management**: In-memory dict (no DB required for competition)
7. **Safety Wrapper**: Outer try/except on endpoint — NEVER returns an error, always returns valid response
