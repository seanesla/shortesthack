# 🧪 Quick Test Guide - SecureReview AI

## Method 1: Web Dashboard (Easiest)

```bash
# 1. Start the server
cd /Users/seane/Documents/GitHub/shortesthack/security-agent-hack
./run_enhanced.sh

# 2. Open browser
http://localhost:8000/dashboard

# 3. Click "Run Demo Scan" button
# This will scan vulnerable code and show results in real-time
```

## Method 2: Test Your Own Code

### Via API
```bash
# Test a code snippet
curl -X POST http://localhost:8000/demo/scan \
  -H "Content-Type: application/json" \
  -d '{
    "code": "const password = \"MySecretPass123!\"; \neval(userInput);",
    "filename": "test.js"
  }'
```

### Via Python Script
```python
# Save as test_my_code.py
import sys
sys.path.append('src')
from agent.security_agent import SecurityAgent

code = '''
const API_KEY = "sk-1234567890";
const query = `SELECT * FROM users WHERE id = ${userId}`;
exec(userCommand);
'''

agent = SecurityAgent()
vulns = agent.analyze_file(code, "myfile.js")

for v in vulns:
    print(f"[{v.severity}] {v.type}: Line {v.line_number}")
    print(f"  {v.code_snippet}")
    print(f"  Fix: {v.fix_suggestion}\n")
```

## Method 3: Test GitHub PR

### Option A: In Dashboard
```
1. Enter in the input field: owner/repo#123
   Example: facebook/react#12345
2. Click "Scan PR"
```

### Option B: Via Webhook
```bash
curl -X POST http://localhost:8000/webhook/github \
  -H "Content-Type: application/json" \
  -d '{
    "action": "opened",
    "pull_request": {
      "number": 123,
      "title": "Test PR",
      "user": {"login": "testuser"}
    },
    "repository": {
      "full_name": "owner/repo"
    }
  }'
```

## Method 4: Test Specific Vulnerabilities

### Create a test file: `vulnerable.js`
```javascript
// Test SQL Injection
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;

// Test Hardcoded Secrets
const apiKey = "sk-prod-1234567890abcdef";
const password = "SuperSecret123!";

// Test Command Injection
const cmd = `ls -la ${userInput}`;
exec(cmd);

// Test JWT Bypass
jwt.decode(token, { verify_signature: false });

// Test Eval
eval(userProvidedCode);

// Test Path Traversal
const file = `/uploads/${req.params.filename}`;
fs.readFile(file);
```

### Scan it:
```bash
curl -X POST http://localhost:8000/demo/scan \
  -H "Content-Type: application/json" \
  -d @- << EOF
{
  "code": "$(cat vulnerable.js | jq -Rs .)",
  "filename": "vulnerable.js"
}
EOF
```

## Method 5: Live Testing Scenarios

### Scenario 1: Authentication Service
```javascript
// Paste this in the dashboard demo
class AuthService {
  constructor() {
    this.JWT_SECRET = "my-secret-key-123";
    this.db_password = "admin123";
  }
  
  login(username, password) {
    // SQL injection vulnerability
    const query = `SELECT * FROM users WHERE user='${username}' AND pass='${password}'`;
    db.query(query);
  }
  
  verifyToken(token) {
    // Weak JWT verification
    return jwt.decode(token, { complete: true });
  }
}
```

### Scenario 2: File Handler
```javascript
// Test path traversal and command injection
function processFile(filename, action) {
  const path = `/data/${filename}`;
  
  if (action === 'compress') {
    exec(`tar -czf ${filename}.tar.gz ${path}`);
  }
  
  if (action === 'analyze') {
    eval(`analyze_${action}("${filename}")`);
  }
}
```

## Expected Results

### Good Detection Examples:
- ✅ `API_KEY = "sk-1234..."` → Hardcoded Secret
- ✅ `SELECT * FROM users WHERE id = ${id}` → SQL Injection
- ✅ `exec(userCommand)` → Command Injection
- ✅ `jwt.decode(token, {verify_signature: false})` → Weak JWT
- ✅ `eval(userInput)` → Code Injection

### What It Should Catch:
1. **Secrets**: API keys, passwords, tokens
2. **Injections**: SQL, Command, Code (eval)
3. **Path Issues**: Traversal vulnerabilities
4. **Crypto**: Weak algorithms, bad JWT
5. **Input Validation**: XSS, SSRF

## Troubleshooting

### Server Won't Start
```bash
# Kill existing process
lsof -ti:8000 | xargs kill -9

# Check Python version (needs 3.8+)
python --version

# Reinstall dependencies
pip install -r requirements.txt
```

### No Vulnerabilities Detected
- Check the code has actual vulnerabilities
- Ensure proper formatting (quotes, backticks)
- Try the demo scan first to verify it works

### Testing Production Code
```bash
# Clone your project
git clone your-repo
cd your-repo

# Create a test branch with vulnerabilities
git checkout -b security-test

# Add some vulnerable code
echo 'const TOKEN = "secret123";' >> app.js

# Commit and test
git add . && git commit -m "test"
git diff main > /tmp/test.diff

# Scan the diff
python test_diff.py /tmp/test.diff
```

## Performance Testing

```bash
# Test large file
time curl -X POST http://localhost:8000/demo/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "'$(cat large-file.js | base64)'", "filename": "large.js"}'
```

Should complete in <10 seconds for files up to 10,000 lines.