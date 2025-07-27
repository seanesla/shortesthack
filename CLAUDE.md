# CLAUDE.md - AI Security Code Review Agent (2-Hour Hackathon)

## Kiro Spec-Driven Development Approach
**PROJECT**: AI-powered Security Code Review Agent that catches vulnerabilities in real-time during pull requests.
**TIME**: 2 hours to build, demo, and win
**METHOD**: Spec-first development using Kiro's approach - define clear requirements, design, then implement

## 1. PROJECT REQUIREMENTS SPEC

### Core Requirements
- **R1**: Agent reviews GitHub pull requests for security vulnerabilities
- **R2**: Provides real-time feedback as developers code
- **R3**: Integrates NVIDIA NIM for enhanced code understanding
- **R4**: Shows clear business value (prevents $4.45M average breach cost)

### User Stories
```gherkin
Feature: Security Code Review
  As a developer
  I want an AI agent to review my code for vulnerabilities
  So that I can fix security issues before merging

  Scenario: SQL Injection Detection
    Given a pull request with "SELECT * FROM users WHERE id = " + user_input
    When the agent reviews the code
    Then it flags SQL injection vulnerability with HIGH severity
    And suggests parameterized query fix

  Scenario: Hardcoded Secrets Detection  
    Given code containing api_key = "sk-1234567890"
    When the agent scans the diff
    Then it alerts about exposed credentials
    And recommends environment variable usage
```

### Non-Functional Requirements
- **NF1**: Process PR review in < 10 seconds
- **NF2**: < 5% false positive rate
- **NF3**: Support Python, JavaScript, Java
- **NF4**: Beautiful UI that impresses judges

## 2. SYSTEM DESIGN SPEC

### Architecture
```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  GitHub Webhook │────▶│  FastAPI Server  │────▶│  Security Agent │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                              │                          │
                              ▼                          ▼
                        ┌─────────────┐           ┌──────────────┐
                        │  WebSocket  │           │  NVIDIA NIM  │
                        │   Frontend  │           │   Enhancer   │
                        └─────────────┘           └──────────────┘
```

### Component Specifications

#### A. Security Agent Core (security_agent.py)
```python
class SecurityAgent:
    """Core agent that thinks like a paranoid security engineer"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'sql_injection': {...},
            'xss': {...},
            'command_injection': {...},
            'hardcoded_secrets': {...}
        }
        self.nvidia_nim = NIMCodeAnalyzer()  # Enhanced understanding
    
    def review_code_diff(self, diff: str) -> SecurityReport:
        """Main entry point for code review"""
        pass
```

#### B. API Server (server.py)
```python
@app.post("/webhook/github")
async def handle_pr_event(payload: dict):
    """GitHub webhook endpoint"""
    # Extract diff, run agent, post comment
    
@app.websocket("/live-review")
async def live_review(websocket: WebSocket):
    """Real-time review updates"""
    # Stream vulnerabilities as found
```

#### C. Frontend Dashboard (index.html)
- Live vulnerability feed
- Security score meter (0-100)
- Fix suggestions with copy button
- Dark theme with red security alerts

## 3. IMPLEMENTATION TASKS SPEC

### Phase 1: Foundation [0:00-0:20]
- [ ] T1.1: Create project structure and git repo
- [ ] T1.2: Setup FastAPI server with health endpoint
- [ ] T1.3: Create SecurityAgent class with pattern matching
- [ ] T1.4: Implement basic SQL injection detection

### Phase 2: Core Features [0:20-1:00]
- [ ] T2.1: Add GitHub webhook handler
- [ ] T2.2: Implement diff parsing and analysis
- [ ] T2.3: Create vulnerability detection for 4 types
- [ ] T2.4: Generate fix suggestions for each vulnerability
- [ ] T2.5: Build WebSocket for real-time updates

### Phase 3: NVIDIA Enhancement [1:00-1:30]
- [ ] T3.1: Integrate NVIDIA NIM API
- [ ] T3.2: Add contextual code understanding
- [ ] T3.3: Improve false positive reduction
- [ ] T3.4: Add severity scoring with NIM

### Phase 4: Demo & Polish [1:30-2:00]
- [ ] T4.1: Create impressive frontend dashboard
- [ ] T4.2: Prepare demo repository with vulnerabilities
- [ ] T4.3: Test full flow: PR → Review → Fix
- [ ] T4.4: Record backup demo video
- [ ] T4.5: Practice 2-minute pitch

## 4. TEST SPECIFICATIONS

### Test Scenarios
```python
# test_security_agent.py
def test_sql_injection_detection():
    """Agent catches obvious SQL injection"""
    code = 'query = "SELECT * FROM users WHERE id = " + request.params["id"]'
    result = agent.review_code_diff(code)
    assert result.vulnerabilities[0].type == "sql_injection"
    assert result.vulnerabilities[0].severity == "HIGH"

def test_nvidia_nim_enhancement():
    """NIM reduces false positives"""
    safe_code = 'query = "SELECT * FROM config"  # Static query, no injection'
    result = agent.review_code_diff(safe_code)
    assert len(result.vulnerabilities) == 0  # NIM understands context
```

### Demo Test Cases
1. **SQL Injection**: Show catching and fixing
2. **Hardcoded API Key**: Detect and suggest env var
3. **XSS Vulnerability**: Flag innerHTML usage
4. **Command Injection**: Catch exec() with user input

## 5. HACKATHON EXECUTION PLAN

### Critical Path (What MUST work)
1. Agent detects at least 2 vulnerability types
2. GitHub webhook receives and processes PR
3. Frontend shows real-time detection
4. NVIDIA integration adds clear value

### Nice-to-Have (If time permits)
- Auto-fix generation
- Multiple language support
- Historical vulnerability tracking
- Team leaderboard

### Fallback Options
- If GitHub webhook fails → File upload demo
- If NVIDIA NIM issues → Use GPT-4 API
- If frontend complex → Terminal with colors
- If WebSocket fails → Polling updates

## 6. DEMO SCRIPT

### Opening (30 seconds)
"Every 11 seconds, a security breach costs companies $4.45 million. What if an AI agent could review every line of code like your most paranoid security engineer?"

### Live Demo (1 minute)
1. "Watch as I create a pull request with a SQL injection vulnerability"
2. "Within seconds, our agent catches it" *show real-time alert*
3. "But it doesn't just find problems - it fixes them" *show suggestion*
4. "Powered by NVIDIA NIM, it understands context to reduce false positives"
5. "Let's try another - hardcoded API key" *instant detection*

### Closing (30 seconds)
"In 2 hours, we built an AI agent that could have prevented Equifax, SolarWinds, and Log4Shell. Imagine deploying this to your repos today."

## 7. SUCCESS METRICS

### Judging Criteria Alignment
- **Creativity (5/5)**: First AI paranoid security engineer
- **Functionality (5/5)**: Live demo catching real vulnerabilities  
- **Completion (5/5)**: Full pipeline works end-to-end
- **Presentation (5/5)**: Clear problem, dramatic demo, huge impact
- **NVIDIA Tools (5/5)**: NIM integration for code understanding

## 8. QUICK REFERENCE

### Key Commands
```bash
# Start server
uvicorn src.api.server:app --reload --port 8000

# Test webhook
curl -X POST http://localhost:8000/webhook/github -d @test_pr.json

# Run agent
python -m src.agent.security_agent review --pr 123
```

### Vulnerability Patterns
```python
PATTERNS = {
    'sql_injection': r'(SELECT|INSERT|UPDATE|DELETE).*\+.*(?:request|input|param)',
    'hardcoded_secrets': r'(?:api_key|password|secret|token)\s*=\s*["\'][^"\'\n]+["\']',
    'command_injection': r'(?:exec|eval|system|subprocess)\s*\([^)]*(?:request|input)',
    'xss': r'(?:innerHTML|document\.write)\s*=.*(?:request|input|param)'
}
```

### NVIDIA NIM Integration
```python
headers = {"Authorization": f"Bearer {NVIDIA_API_KEY}"}
response = requests.post(
    "https://api.nvidia.com/nim/code-analysis",
    json={"code": diff, "context": "security-review"}
)
```

## REMEMBER
- **Ship > Perfect**: Get basic detection working first
- **Demo Impact**: Practice the "wow" moment
- **Time Box**: Use timers for each phase
- **Have Fun**: You're preventing the next big breach!

## GO BUILD! 🚀