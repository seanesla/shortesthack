#!/usr/bin/env python3
"""Test all features of SecureReview AI"""

import asyncio
import httpx
import json
from datetime import datetime

async def test_features():
    print("\n🧪 Testing SecureReview AI Features\n")
    
    # Test 1: Health Check
    print("1️⃣ Testing Health Endpoint...")
    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:8000/health")
        if response.status_code == 200:
            print("   ✅ Server is healthy")
        else:
            print("   ❌ Health check failed")
    
    # Test 2: Vulnerability Detection
    print("\n2️⃣ Testing Vulnerability Detection...")
    test_code = '''
def process_payment(user_id, amount):
    # SQL Injection vulnerability
    query = "SELECT balance FROM accounts WHERE id = " + user_id
    
    # Hardcoded secret
    stripe_key = "sk_live_1234567890abcdef"
    
    # Command injection
    os.system("log payment for " + user_id)
    
    # XSS vulnerability
    return "<div>Payment for: " + user_id + "</div>"
'''
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/demo/scan",
            json={"code": test_code, "filename": "payment.py"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Found {len(result.get('vulnerabilities', []))} vulnerabilities")
            print(f"   📊 Security Score: {result.get('score', 0)}/100")
            
            for vuln in result.get('vulnerabilities', []):
                print(f"   🚨 {vuln['type']} ({vuln['severity']})")
        else:
            print("   ❌ Scan failed")
    
    # Test 3: GitHub Webhook
    print("\n3️⃣ Testing GitHub Webhook...")
    webhook_payload = {
        "action": "opened",
        "pull_request": {
            "number": 123,
            "title": "Test PR",
            "base": {
                "repo": {
                    "full_name": "test/repo"
                }
            }
        },
        "repository": {
            "full_name": "test/repo"
        }
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/webhook/github",
            json=webhook_payload
        )
        
        if response.status_code == 200:
            print("   ✅ Webhook accepted")
        else:
            print("   ❌ Webhook failed")
    
    # Test 4: Dashboard
    print("\n4️⃣ Testing Dashboard...")
    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:8000/dashboard")
        if response.status_code == 200:
            print("   ✅ Dashboard accessible")
            print("   🌐 Open: http://localhost:8000/dashboard")
        else:
            print("   ❌ Dashboard not found")
    
    print("\n✨ Testing complete!")
    print("\n💡 Next Steps:")
    print("1. Add API keys to .env for real integrations")
    print("2. Open dashboard and click 'Run Demo Scan'")
    print("3. Practice your 3-minute pitch")
    print("4. Win the hackathon! 🏆")

if __name__ == "__main__":
    asyncio.run(test_features())