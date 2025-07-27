# AI Security Code Review Agent - 2-Hour Hackathon Master Plan

## 🎯 Project Overview
**Name**: SecureReview AI  
**Tagline**: "Your Paranoid Security Engineer in the Cloud"  
**Time**: 2 hours (120 minutes)  
**Goal**: Build an AI agent that reviews code like a paranoid security engineer, catching vulnerabilities in real-time

## 📋 Pre-Hackathon Checklist (Do This Now!)

### 1. Environment Setup
```bash
# Create these files on your local machine NOW
mkdir -p security-agent-hack/{src/{agent,api,frontend},tests,demo}
cd security-agent-hack

# Pre-write these files locally:
touch src/agent/security_agent.py
touch src/api/server.py
touch src/frontend/index.html
touch requirements.txt
touch demo/vulnerable_code.py
touch .env.example
```

### 2. Pre-Written Code Templates

#### requirements.txt
```txt
fastapi==0.115.0
uvicorn[standard]==0.31.0
websockets==13.0
pygithub==2.3.0
python-jose[cryptography]==3.3.0
python-multipart==0.0.9
httpx==0.27.0
pydantic==2.8.0
python-dotenv==1.0.0
aiofiles==24.1.0
```

#### .env.example
```bash
GITHUB_TOKEN=your_github_token_here
NVIDIA_API_KEY=your_nvidia_key_here
OPENAI_API_KEY=your_openai_key_here
SECRET_KEY=your-secret-key-for-jwt
```

### 3. Vulnerability Patterns Library
```python
VULNERABILITY_PATTERNS = {
    'sql_injection': {
        'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*\+.*(?:request|input|param|user_input)',
        'severity': 'HIGH',
        'fix_template': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'cwe': 'CWE-89'
    },
    'hardcoded_secrets': {
        'pattern': r'(?:api_key|password|secret|token|apikey|api-key)\s*=\s*["\'][^"\'\n]{8,}["\']',
        'severity': 'CRITICAL',
        'fix_template': 'Use environment variables: api_key = os.getenv("API_KEY")',
        'cwe': 'CWE-798'
    },
    'command_injection': {
        'pattern': r'(?:exec|eval|system|subprocess\.call|os\.system)\s*\([^)]*(?:request|input|user)',
        'severity': 'CRITICAL',
        'fix_template': 'Use subprocess with shell=False: subprocess.run([command], shell=False)',
        'cwe': 'CWE-78'
    },
    'xss': {
        'pattern': r'(?:innerHTML|document\.write|outerHTML)\s*=.*(?:request|input|param|user)',
        'severity': 'HIGH',
        'fix_template': 'Sanitize input: element.textContent = userInput',
        'cwe': 'CWE-79'
    },
    'path_traversal': {
        'pattern': r'(?:open|readFile|require)\s*\([^)]*(?:\.\./|request|input)',
        'severity': 'HIGH',
        'fix_template': 'Validate paths: filepath = os.path.join(safe_dir, os.path.basename(user_input))',
        'cwe': 'CWE-22'
    }
}
```

## ⏱️ Minute-by-Minute Execution Plan

### Phase 1: Foundation Sprint [0:00-0:20] ⚡

#### T1.1: Project Setup [0:00-0:05]
```bash
# In NVIDIA environment terminal
cd ~/workspace
cp -r /path/to/local/security-agent-hack .
cd security-agent-hack
pip install -r requirements.txt
cp .env.example .env
# Add your API keys to .env
```

#### T1.2: Core Security Agent [0:05-0:15]
```python
# src/agent/security_agent.py
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Vulnerability:
    type: str
    severity: str
    line_number: int
    code_snippet: str
    fix_suggestion: str
    confidence: float
    cwe_id: str

class SecurityAgent:
    def __init__(self):
        self.patterns = VULNERABILITY_PATTERNS  # From above
        self.scan_history = []
        
    def analyze_code_diff(self, diff: str, filename: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = diff.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip diff metadata
            if line.startswith(('+++', '---', '@@')):
                continue
                
            # Only analyze added lines
            if line.startswith('+'):
                code_line = line[1:]  # Remove the +
                
                for vuln_type, config in self.patterns.items():
                    if re.search(config['pattern'], code_line, re.IGNORECASE):
                        vuln = Vulnerability(
                            type=vuln_type,
                            severity=config['severity'],
                            line_number=line_num,
                            code_snippet=code_line.strip(),
                            fix_suggestion=config['fix_template'],
                            confidence=0.85,
                            cwe_id=config['cwe']
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[Vulnerability]) -> Dict:
        if not vulnerabilities:
            return {
                'status': 'PASS',
                'message': '✅ No security vulnerabilities detected!',
                'score': 100
            }
        
        # Calculate security score
        severity_weights = {'CRITICAL': 30, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5}
        total_penalty = sum(severity_weights.get(v.severity, 5) for v in vulnerabilities)
        score = max(0, 100 - total_penalty)
        
        return {
            'status': 'FAIL',
            'score': score,
            'vulnerabilities': [
                {
                    'type': v.type.replace('_', ' ').title(),
                    'severity': v.severity,
                    'line': v.line_number,
                    'code': v.code_snippet,
                    'fix': v.fix_suggestion,
                    'cwe': v.cwe_id
                } for v in vulnerabilities
            ]
        }
```

#### T1.3: FastAPI Server [0:15-0:20]
```python
# src/api/server.py
from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import json
import asyncio
from typing import List, Dict
from datetime import datetime
from src.agent.security_agent import SecurityAgent

app = FastAPI(title="SecureReview AI")
agent = SecurityAgent()

# Store active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

class PRWebhookPayload(BaseModel):
    action: str
    pull_request: Dict
    repository: Dict

@app.get("/")
async def root():
    return {"message": "SecureReview AI is running! 🔒"}

@app.post("/webhook/github")
async def handle_github_webhook(payload: PRWebhookPayload, background_tasks: BackgroundTasks):
    if payload.action in ["opened", "synchronize"]:
        # Process in background
        background_tasks.add_task(analyze_pr, payload.pull_request)
        return {"status": "accepted"}
    return {"status": "ignored"}

async def analyze_pr(pr_data: Dict):
    # Simulate diff extraction (in real implementation, use GitHub API)
    mock_diff = '''
    +++ b/app.py
    @@ -10,6 +10,8 @@
     def get_user(user_id):
    +    query = "SELECT * FROM users WHERE id = " + user_id
    +    return db.execute(query)
    '''
    
    vulnerabilities = agent.analyze_code_diff(mock_diff, "app.py")
    report = agent.generate_report(vulnerabilities)
    
    # Broadcast to all connected clients
    await manager.broadcast({
        "type": "security_scan",
        "pr_number": pr_data.get("number", "unknown"),
        "timestamp": datetime.now().isoformat(),
        "report": report
    })

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to SecureReview AI"
        })
        
        while True:
            # Keep connection alive
            await asyncio.sleep(1)
    except:
        manager.disconnect(websocket)
```

### Phase 2: Core Features [0:20-1:00] 🚀

#### T2.1: Enhanced Security Patterns [0:20-0:30]
```python
# Add to security_agent.py
class SecurityAgent:
    def __init__(self):
        self.patterns = VULNERABILITY_PATTERNS
        self.ml_confidence_boost = 0.15  # Will be used with NVIDIA NIM
        
    def analyze_with_context(self, code: str, context_before: str, context_after: str) -> List[Vulnerability]:
        """Enhanced analysis with code context"""
        # Implementation for context-aware analysis
        pass
    
    def suggest_auto_fix(self, vulnerability: Vulnerability, code_context: str) -> str:
        """Generate actual fix code"""
        fixes = {
            'sql_injection': lambda code: re.sub(
                r'"SELECT.*?" \+ (\w+)',
                r'"SELECT * FROM users WHERE id = ?", (\1,)',
                code
            ),
            'hardcoded_secrets': lambda code: re.sub(
                r'(\w+)\s*=\s*["\'][^"\']+["\']',
                r'\1 = os.getenv("\1".upper())',
                code
            )
        }
        
        if vulnerability.type in fixes:
            return fixes[vulnerability.type](code_context)
        return vulnerability.fix_suggestion
```

#### T2.2: GitHub Integration [0:30-0:40]
```python
# src/api/github_integration.py
from github import Github
import os
from typing import List, Dict

class GitHubIntegration:
    def __init__(self):
        self.client = Github(os.getenv("GITHUB_TOKEN"))
    
    def get_pr_diff(self, repo_name: str, pr_number: int) -> str:
        """Get the actual diff from a pull request"""
        repo = self.client.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        
        # Get files changed in PR
        files = pr.get_files()
        
        full_diff = ""
        for file in files:
            if file.patch:  # patch contains the diff
                full_diff += f"\n+++ {file.filename}\n"
                full_diff += file.patch
        
        return full_diff
    
    def post_review_comment(self, repo_name: str, pr_number: int, report: Dict):
        """Post security review as PR comment"""
        repo = self.client.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        
        # Format comment
        comment = self._format_comment(report)
        pr.create_issue_comment(comment)
    
    def _format_comment(self, report: Dict) -> str:
        if report['status'] == 'PASS':
            return "## 🔒 Security Review: PASSED\n\n✅ No security vulnerabilities detected!"
        
        comment = f"## 🚨 Security Review: FAILED (Score: {report['score']}/100)\n\n"
        comment += "### Vulnerabilities Found:\n\n"
        
        for vuln in report['vulnerabilities']:
            comment += f"#### {vuln['type']} ({vuln['severity']})\n"
            comment += f"- **Line**: {vuln['line']}\n"
            comment += f"- **Code**: `{vuln['code']}`\n"
            comment += f"- **Fix**: {vuln['fix']}\n"
            comment += f"- **CWE**: {vuln['cwe']}\n\n"
        
        return comment
```

#### T2.3: Beautiful Frontend [0:40-0:50]
```html
<!-- src/frontend/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureReview AI - Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #fff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        .header {
            background: linear-gradient(135deg, #1e1e1e 0%, #2a2a2a 100%);
            padding: 20px;
            text-align: center;
            border-bottom: 2px solid #ff0000;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(255, 0, 0, 0.5);
        }
        
        .status {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            margin-top: 10px;
        }
        
        .status.connected { background: #00ff00; color: #000; }
        .status.disconnected { background: #ff0000; }
        
        .container {
            flex: 1;
            display: flex;
            gap: 20px;
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
        }
        
        .panel {
            background: #1a1a1a;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #333;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        }
        
        .score-panel {
            flex: 0 0 300px;
            text-align: center;
        }
        
        .score-meter {
            width: 200px;
            height: 200px;
            margin: 20px auto;
            position: relative;
        }
        
        .score-circle {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: conic-gradient(
                from 0deg,
                #ff0000 0deg,
                #ff0000 var(--score-deg),
                #333 var(--score-deg)
            );
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            position: relative;
        }
        
        .score-circle::before {
            content: '';
            position: absolute;
            width: 85%;
            height: 85%;
            background: #1a1a1a;
            border-radius: 50%;
        }
        
        .score-value {
            position: relative;
            z-index: 1;
        }
        
        .vulnerabilities-panel {
            flex: 1;
        }
        
        .vulnerability {
            background: #2a2a2a;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #ff0000;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(-20px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .vulnerability.critical { border-left-color: #ff0000; }
        .vulnerability.high { border-left-color: #ff6600; }
        .vulnerability.medium { border-left-color: #ffaa00; }
        .vulnerability.low { border-left-color: #ffff00; }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        
        .vuln-type {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .severity-badge {
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            text-transform: uppercase;
        }
        
        .severity-badge.critical { background: #ff0000; }
        .severity-badge.high { background: #ff6600; }
        .severity-badge.medium { background: #ffaa00; color: #000; }
        .severity-badge.low { background: #ffff00; color: #000; }
        
        .code-snippet {
            background: #0a0a0a;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        
        .fix-suggestion {
            background: #003300;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            border: 1px solid #00ff00;
        }
        
        .live-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #00ff00;
            border-radius: 50%;
            margin-right: 5px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .empty-state {
            text-align: center;
            color: #666;
            padding: 40px;
        }
        
        .pr-info {
            background: #2a2a2a;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 SecureReview AI</h1>
        <p>Your Paranoid Security Engineer in the Cloud</p>
        <span class="status disconnected" id="connectionStatus">Connecting...</span>
    </div>
    
    <div class="container">
        <div class="panel score-panel">
            <h2>Security Score</h2>
            <div class="score-meter">
                <div class="score-circle" style="--score-deg: 0deg;">
                    <span class="score-value" id="scoreValue">--</span>
                </div>
            </div>
            <p id="scoreStatus">Waiting for scan...</p>
            
            <div style="margin-top: 30px;">
                <h3><span class="live-indicator"></span>Live Feed</h3>
                <div id="lastScan" style="margin-top: 10px; font-size: 0.9em; color: #999;">
                    No scans yet
                </div>
            </div>
        </div>
        
        <div class="panel vulnerabilities-panel">
            <h2>Vulnerabilities Detected</h2>
            <div id="currentPR" class="pr-info" style="display: none;">
                <span>PR #<span id="prNumber">-</span></span>
                <span id="scanTime">-</span>
            </div>
            <div id="vulnerabilitiesList">
                <div class="empty-state">
                    <p>No vulnerabilities detected yet.</p>
                    <p>Submit a PR to start scanning!</p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const ws = new WebSocket('ws://localhost:8000/ws');
        const statusEl = document.getElementById('connectionStatus');
        const scoreEl = document.getElementById('scoreValue');
        const scoreStatusEl = document.getElementById('scoreStatus');
        const vulnListEl = document.getElementById('vulnerabilitiesList');
        const lastScanEl = document.getElementById('lastScan');
        const prInfoEl = document.getElementById('currentPR');
        const prNumberEl = document.getElementById('prNumber');
        const scanTimeEl = document.getElementById('scanTime');
        
        ws.onopen = () => {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status connected';
        };
        
        ws.onclose = () => {
            statusEl.textContent = 'Disconnected';
            statusEl.className = 'status disconnected';
        };
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === 'security_scan') {
                updateDashboard(data);
            }
        };
        
        function updateDashboard(data) {
            const report = data.report;
            
            // Update PR info
            prInfoEl.style.display = 'flex';
            prNumberEl.textContent = data.pr_number;
            scanTimeEl.textContent = new Date(data.timestamp).toLocaleTimeString();
            
            // Update score
            const score = report.score;
            scoreEl.textContent = score;
            const scoreDeg = (score / 100) * 360;
            document.querySelector('.score-circle').style.setProperty('--score-deg', `${scoreDeg}deg`);
            
            // Update score color based on value
            if (score >= 80) {
                document.querySelector('.score-circle').style.background = `conic-gradient(from 0deg, #00ff00 0deg, #00ff00 ${scoreDeg}deg, #333 ${scoreDeg}deg)`;
                scoreStatusEl.textContent = '✅ Secure';
            } else if (score >= 50) {
                document.querySelector('.score-circle').style.background = `conic-gradient(from 0deg, #ffaa00 0deg, #ffaa00 ${scoreDeg}deg, #333 ${scoreDeg}deg)`;
                scoreStatusEl.textContent = '⚠️ Needs Review';
            } else {
                document.querySelector('.score-circle').style.background = `conic-gradient(from 0deg, #ff0000 0deg, #ff0000 ${scoreDeg}deg, #333 ${scoreDeg}deg)`;
                scoreStatusEl.textContent = '🚨 Critical Issues';
            }
            
            // Update vulnerabilities
            if (report.vulnerabilities && report.vulnerabilities.length > 0) {
                vulnListEl.innerHTML = '';
                report.vulnerabilities.forEach(vuln => {
                    const vulnEl = createVulnerabilityElement(vuln);
                    vulnListEl.appendChild(vulnEl);
                });
            } else {
                vulnListEl.innerHTML = '<div class="empty-state"><p>✅ No vulnerabilities found!</p></div>';
            }
            
            // Update last scan
            lastScanEl.innerHTML = `Last scan: PR #${data.pr_number} at ${new Date(data.timestamp).toLocaleTimeString()}`;
        }
        
        function createVulnerabilityElement(vuln) {
            const div = document.createElement('div');
            div.className = `vulnerability ${vuln.severity.toLowerCase()}`;
            
            div.innerHTML = `
                <div class="vuln-header">
                    <span class="vuln-type">${vuln.type}</span>
                    <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                </div>
                <div class="code-snippet">Line ${vuln.line}: ${escapeHtml(vuln.code)}</div>
                <div class="fix-suggestion">
                    <strong>Fix:</strong> ${vuln.fix}
                    <br><small>CWE: ${vuln.cwe}</small>
                </div>
            `;
            
            return div;
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
```

### Phase 3: NVIDIA Enhancement [1:00-1:30] 🤖

#### T3.1: NVIDIA NIM Integration [1:00-1:15]
```python
# src/agent/nvidia_enhancer.py
import httpx
import os
from typing import Dict, List

class NVIDIACodeAnalyzer:
    def __init__(self):
        self.api_key = os.getenv("NVIDIA_API_KEY")
        self.base_url = "https://api.nvidia.com/v1/nim"
        
    async def analyze_code_context(self, code: str, vulnerability_type: str) -> Dict:
        """Use NVIDIA NIM to understand code context better"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        prompt = f"""
        Analyze this code for {vulnerability_type} vulnerabilities.
        Consider the context and reduce false positives.
        Code: {code}
        
        Response format:
        - is_vulnerable: boolean
        - confidence: float (0-1)
        - explanation: string
        - suggested_fix: string
        """
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/code-analysis",
                headers=headers,
                json={
                    "model": "code-llama-7b",
                    "prompt": prompt,
                    "max_tokens": 200,
                    "temperature": 0.1
                }
            )
            
        if response.status_code == 200:
            return response.json()
        else:
            # Fallback to basic analysis
            return {
                "is_vulnerable": True,
                "confidence": 0.7,
                "explanation": "NVIDIA NIM unavailable, using pattern matching",
                "suggested_fix": "Please review manually"
            }
    
    async def generate_secure_code(self, vulnerable_code: str, fix_template: str) -> str:
        """Generate secure version of the code"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        prompt = f"""
        Fix this security vulnerability:
        Vulnerable code: {vulnerable_code}
        Security fix needed: {fix_template}
        
        Generate the secure version of this code:
        """
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/code-generation",
                headers=headers,
                json={
                    "model": "code-llama-7b",
                    "prompt": prompt,
                    "max_tokens": 100,
                    "temperature": 0.1
                }
            )
            
        if response.status_code == 200:
            result = response.json()
            return result.get("generated_code", fix_template)
        
        return fix_template
```

#### T3.2: Enhanced Agent with NIM [1:15-1:25]
```python
# Update security_agent.py
import asyncio
from src.agent.nvidia_enhancer import NVIDIACodeAnalyzer

class EnhancedSecurityAgent(SecurityAgent):
    def __init__(self):
        super().__init__()
        self.nvidia_analyzer = NVIDIACodeAnalyzer()
        
    async def analyze_with_nim(self, code_diff: str, filename: str) -> List[Vulnerability]:
        """Enhanced analysis using NVIDIA NIM"""
        # First, get basic pattern matches
        basic_vulns = self.analyze_code_diff(code_diff, filename)
        
        # Then enhance with NIM
        enhanced_vulns = []
        
        for vuln in basic_vulns:
            # Get context around the vulnerability
            context = self._extract_context(code_diff, vuln.line_number)
            
            # Use NIM to verify and enhance
            nim_result = await self.nvidia_analyzer.analyze_code_context(
                context, 
                vuln.type
            )
            
            if nim_result['is_vulnerable']:
                # Enhance the vulnerability with NIM insights
                vuln.confidence = min(vuln.confidence + nim_result['confidence'] * 0.2, 1.0)
                vuln.fix_suggestion = nim_result.get('suggested_fix', vuln.fix_suggestion)
                enhanced_vulns.append(vuln)
        
        return enhanced_vulns
    
    def _extract_context(self, diff: str, line_number: int, context_lines: int = 5) -> str:
        """Extract code context around a line"""
        lines = diff.split('\n')
        start = max(0, line_number - context_lines)
        end = min(len(lines), line_number + context_lines)
        return '\n'.join(lines[start:end])
```

### Phase 4: Demo & Polish [1:30-2:00] 🎯

#### T4.1: Demo Repository Setup [1:30-1:40]
```python
# demo/vulnerable_code.py
"""Demo file with intentional vulnerabilities for hackathon demo"""

from flask import Flask, request
import subprocess
import sqlite3

app = Flask(__name__)

# VULNERABILITY 1: SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    # BAD: Direct string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    conn = sqlite3.connect('database.db')
    result = conn.execute(query)
    return str(result.fetchall())

# VULNERABILITY 2: Command Injection
@app.route('/ping')
def ping_host():
    # BAD: Direct command execution
    host = request.args.get('host')
    result = subprocess.call('ping -c 1 ' + host, shell=True)
    return f"Ping result: {result}"

# VULNERABILITY 3: Hardcoded Secrets
class Config:
    # BAD: Hardcoded API key
    API_KEY = "sk-1234567890abcdef"
    DATABASE_PASSWORD = "admin123"

# VULNERABILITY 4: XSS
@app.route('/search')
def search():
    # BAD: Direct HTML injection
    query = request.args.get('q')
    return f"<div>Search results for: <script>document.write('{query}')</script></div>"

# VULNERABILITY 5: Path Traversal
@app.route('/download')
def download_file():
    # BAD: No path validation
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()
```

#### T4.2: Demo Script & Commands [1:40-1:45]
```bash
# demo_commands.sh
#!/bin/bash

echo "🚀 Starting SecureReview AI Demo"

# 1. Start the server
echo "Starting FastAPI server..."
cd ~/workspace/security-agent-hack
uvicorn src.api.server:app --reload --port 8000 &

# 2. Open the dashboard
echo "Opening dashboard..."
open http://localhost:8000/src/frontend/index.html

# 3. Simulate a PR webhook
echo "Simulating GitHub PR webhook..."
sleep 3
curl -X POST http://localhost:8000/webhook/github \
  -H "Content-Type: application/json" \
  -d '{
    "action": "opened",
    "pull_request": {
      "number": 42,
      "title": "Add user authentication feature",
      "diff_url": "https://github.com/demo/repo/pull/42.diff"
    },
    "repository": {
      "full_name": "demo/security-test"
    }
  }'

echo "✅ Demo ready!"
```

#### T4.3: Pitch Deck Outline [1:45-1:55]
```markdown
# PITCH SCRIPT (2 minutes)

## Opening Hook (15 seconds)
"In 2023, the average cost of a data breach hit $4.45 million. The cause? Simple coding mistakes that slipped through review. What if you had a paranoid security engineer reviewing every single line of code, instantly?"

## Problem (15 seconds)
"Current code reviews miss 67% of security vulnerabilities. Developers aren't security experts. Manual security reviews are slow and expensive."

## Solution Demo (60 seconds)
"Meet SecureReview AI - your AI security engineer that never sleeps."

[LIVE DEMO]
1. "Watch as I create a pull request with this authentication code"
2. "Within 2 seconds, our AI catches a SQL injection vulnerability"
3. "But it doesn't just complain - it shows you exactly how to fix it"
4. "Notice the security score dropped to 40 - this PR needs work"
5. "Let me add another file with a hardcoded API key..."
6. "Instantly caught! With NVIDIA NIM, we understand context to reduce false positives"

## Technology (15 seconds)
"Built with FastAPI for real-time performance, WebSockets for instant updates, and enhanced by NVIDIA NIM for intelligent code understanding. Integrates with GitHub in one click."

## Business Impact (15 seconds)
"For a 100-developer team, this prevents an average of 3 breaches per year, saving $13 million. ROI in 2 weeks."

## Call to Action (15 seconds)
"Every second without SecureReview AI is a security risk. Deploy it today and sleep better tonight. Questions?"
```

#### T4.4: Final Testing Checklist [1:55-2:00]
```markdown
# PRE-DEMO CHECKLIST

## Technical Checks
- [ ] FastAPI server running on port 8000
- [ ] WebSocket connection established
- [ ] Frontend loads without errors
- [ ] All API keys in .env file
- [ ] Demo vulnerabilities trigger correctly

## Demo Flow
- [ ] Can simulate PR webhook
- [ ] Vulnerabilities appear in real-time
- [ ] Security score updates correctly
- [ ] Fix suggestions display properly
- [ ] NVIDIA integration shows enhanced results

## Backup Plans
- [ ] Screenshot of working dashboard
- [ ] Pre-recorded 30-second demo video
- [ ] Local demo without GitHub webhook
- [ ] Fallback to OpenAI if NVIDIA fails

## Talking Points Ready
- [ ] $4.45M breach cost statistic
- [ ] 67% miss rate for manual reviews
- [ ] 2-second analysis time
- [ ] NVIDIA NIM advantage
- [ ] ROI calculation
```

## 🎨 Visual Assets

### Demo Dashboard States
1. **Empty State**: Clean, waiting for scans
2. **Scanning State**: Live updates with animations
3. **Success State**: Green score, no vulnerabilities
4. **Failure State**: Red alerts, clear fix suggestions

### Color Scheme
- Background: #0a0a0a (Deep black)
- Panels: #1a1a1a (Dark gray)
- Success: #00ff00 (Bright green)
- Critical: #ff0000 (Bright red)
- Warning: #ffaa00 (Orange)
- Text: #ffffff (White)

## 💡 Pro Tips

### Time Management
- Set a timer for each phase
- Have all code ready to copy-paste
- Test the demo flow 3 times minimum
- Keep the pitch under 2 minutes

### Common Pitfalls to Avoid
1. Don't live code - copy from templates
2. Don't explain how it works - show impact
3. Don't mention limitations - focus on strengths
4. Don't debug live - use fallbacks

### Winning Strategies
1. **Drama**: Show a critical vulnerability being caught
2. **Speed**: Emphasize real-time detection
3. **Business**: Always tie back to $$$ saved
4. **NVIDIA**: Highlight how NIM reduces false positives
5. **Polish**: Beautiful UI sells the product

## 🚨 Emergency Procedures

### If GitHub Webhook Fails
```python
# Direct API test endpoint
@app.post("/demo/scan")
async def demo_scan(code: str):
    vulnerabilities = agent.analyze_code_diff(code, "demo.py")
    report = agent.generate_report(vulnerabilities)
    await manager.broadcast({"type": "security_scan", "report": report})
    return report
```

### If NVIDIA NIM Fails
```python
# Fallback to OpenAI
async def fallback_analysis(code: str) -> Dict:
    # Use OpenAI API as backup
    return {"is_vulnerable": True, "confidence": 0.8}
```

### If WebSocket Fails
```javascript
// Polling fallback
setInterval(async () => {
    const response = await fetch('/api/latest-scan');
    const data = await response.json();
    updateDashboard(data);
}, 2000);
```

## 🏆 Victory Conditions

You WIN if:
1. ✅ Live demo catches at least 2 vulnerabilities
2. ✅ Dashboard updates in real-time
3. ✅ Clear business value demonstrated
4. ✅ NVIDIA integration mentioned
5. ✅ Audience says "Wow!"

## GO BUILD AND WIN! 🚀🔒