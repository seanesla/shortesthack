#!/usr/bin/env python3
"""Quick test of the security agent - run this to see it in action!"""

import sys
sys.path.append('src')
from agent.security_agent import SecurityAgent

# Test code with various vulnerabilities
test_code = '''
// Authentication Service
const API_KEY = "sk-prod-1234567890abcdef";
const JWT_SECRET = "SuperSecretKey2025!";

function authenticateUser(username, password) {
    // SQL Injection vulnerability
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.query(query);
    
    // Log authentication (command injection)
    const logCmd = `echo "User ${username} logged in" >> /var/log/auth.log`;
    exec(logCmd);
}

function verifyToken(token) {
    // Weak JWT verification
    return jwt.decode(token, { verify_signature: false });
}

function processUserFile(filename) {
    // Path traversal vulnerability
    const filepath = `/uploads/${filename}`;
    return fs.readFile(filepath);
}

function validateInput(userInput) {
    // Dangerous eval usage
    const validation = `userInput.length > 0 && userInput.match(/^[a-z]+$/)`;
    return eval(validation);
}

// Weak crypto
const cipher = crypto.createCipher('des', 'weak-key');
'''

print("🔍 SecureReview AI - Quick Test\n")
print("Testing vulnerability detection on sample code...\n")

# Create agent and analyze
agent = SecurityAgent()
vulnerabilities = agent.analyze_file(test_code, "test.js")
report = agent.generate_report(vulnerabilities)

# Display results
print(f"📊 Security Score: {report['score']}/100")
print(f"🚨 Vulnerabilities Found: {len(vulnerabilities)}\n")

if vulnerabilities:
    print("Detected Security Issues:")
    print("-" * 60)
    
    for i, vuln in enumerate(vulnerabilities, 1):
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(vuln.severity, '⚪')
        
        print(f"\n{i}. {severity_emoji} [{vuln.severity}] {vuln.type.replace('_', ' ').title()}")
        print(f"   Line {vuln.line_number}: {vuln.code_snippet[:60]}...")
        print(f"   Fix: {vuln.fix_suggestion}")
        print(f"   CWE: {vuln.cwe_id} | Confidence: {vuln.confidence * 100:.0f}%")

print("\n" + "=" * 60)
print("✅ Test Complete! The agent detected", len(vulnerabilities), "vulnerabilities.")
print("\nTo test with your own code:")
print("1. Run: ./run_enhanced.sh")
print("2. Open: http://localhost:8000/dashboard")
print("3. Click 'Run Demo Scan' or paste your own code")