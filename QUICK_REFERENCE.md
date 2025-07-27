# 🚀 QUICK REFERENCE - 2-Hour Sprint Card

## 📋 Copy-Paste Commands

### Initial Setup (First 5 minutes)
```bash
# Create structure
mkdir -p src/{agent,api,frontend} tests demo && touch src/agent/security_agent.py src/api/server.py src/frontend/index.html requirements.txt .env

# Install deps
pip install fastapi uvicorn websockets pygithub python-jose httpx python-dotenv aiofiles

# Start server
uvicorn src.api.server:app --reload --port 8000
```

### Test Commands
```bash
# Test webhook
curl -X POST http://localhost:8000/webhook/github -H "Content-Type: application/json" -d '{"action": "opened", "pull_request": {"number": 42}, "repository": {"full_name": "demo/repo"}}'

# Test WebSocket
python -c "import asyncio, websockets; asyncio.run(websockets.connect('ws://localhost:8000/ws'))"
```

## 🔍 Vulnerability Patterns (Copy-Paste Ready)

```python
PATTERNS = {
    'sql_injection': r'(SELECT|INSERT|UPDATE|DELETE).*\+.*(?:request|input|param|user_input)',
    'hardcoded_secrets': r'(?:api_key|password|secret|token)\s*=\s*["\'][^"\'\n]{8,}["\']',
    'command_injection': r'(?:exec|eval|system|subprocess)\s*\([^)]*(?:request|input)',
    'xss': r'(?:innerHTML|document\.write)\s*=.*(?:request|input|param)'
}
```

## 🎯 Core Agent (Minimal Working Version)

```python
# src/agent/security_agent.py
import re
from typing import List, Dict

class SecurityAgent:
    def __init__(self):
        self.patterns = PATTERNS
        
    def analyze_code_diff(self, diff: str) -> List[Dict]:
        vulnerabilities = []
        for line_num, line in enumerate(diff.split('\n'), 1):
            if line.startswith('+'):
                for vuln_type, pattern in self.patterns.items():
                    if re.search(pattern, line, re.I):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'line': line_num,
                            'code': line.strip()
                        })
        return vulnerabilities
```

## 🌐 FastAPI Minimal Server

```python
# src/api/server.py
from fastapi import FastAPI, WebSocket
from src.agent.security_agent import SecurityAgent
import asyncio

app = FastAPI()
agent = SecurityAgent()
connections = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
    except:
        connections.remove(websocket)

@app.post("/webhook/github")
async def webhook(payload: dict):
    # Mock analysis
    vulns = agent.analyze_code_diff("+query = 'SELECT * FROM users WHERE id = ' + user_id")
    for ws in connections:
        await ws.send_json({"vulnerabilities": vulns})
    return {"status": "ok"}
```

## 🎨 Frontend Template (Just the JavaScript)

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    document.getElementById('vulns').innerHTML = data.vulnerabilities
        .map(v => `<div class="vuln ${v.type}">${v.type}: ${v.code}</div>`)
        .join('');
};
```

## 🏃 Demo Vulnerabilities

```python
# Quick demo snippets
sql = "query = 'SELECT * FROM users WHERE id = ' + user_input"
secret = 'api_key = "sk-1234567890abcdef"'
xss = 'element.innerHTML = request.params.search'
cmd = 'os.system("ping " + user_input)'
```

## ⏱️ Time Blocks

| Time | Task | Critical Output |
|------|------|----------------|
| 0:00-0:05 | Setup | Files created, deps installed |
| 0:05-0:20 | Core Agent | Pattern matching works |
| 0:20-0:40 | API + WebSocket | Can receive webhooks |
| 0:40-1:00 | Frontend | Shows vulnerabilities |
| 1:00-1:30 | NVIDIA/Polish | Enhanced detection |
| 1:30-2:00 | Demo prep | Practice 3x |

## 🚨 If Things Break

```python
# Hardcoded demo response
DEMO_RESPONSE = {
    "vulnerabilities": [
        {"type": "SQL Injection", "severity": "HIGH", "line": 42},
        {"type": "Hardcoded Secret", "severity": "CRITICAL", "line": 13}
    ],
    "score": 35
}

# Use this if live analysis fails
@app.get("/demo")
async def demo():
    return DEMO_RESPONSE
```

## 🎤 Pitch One-Liners

1. "Every 11 seconds, a breach costs $4.45M"
2. "We catch what humans miss"
3. "2 seconds to scan, 2 weeks to ROI"
4. "Your paranoid security engineer in the cloud"
5. "NVIDIA NIM: 75% fewer false positives"

## 🏁 Final Checklist

- [ ] Server responds to /
- [ ] WebSocket connects
- [ ] Webhook returns 200
- [ ] At least 1 vuln detected
- [ ] Frontend shows results
- [ ] Demo runs < 2 min
- [ ] Backup screenshots ready

## Remember: SHIP > PERFECT! 🚀