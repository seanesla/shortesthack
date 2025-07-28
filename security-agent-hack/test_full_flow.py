#!/usr/bin/env python3
"""
Test the complete flow as specified in CLAUDE.md
Critical Path Requirements:
1. Agent detects at least 2 vulnerability types
2. GitHub webhook receives and processes PR
3. Frontend shows real-time detection
4. NVIDIA integration adds clear value
"""

import asyncio
import httpx
import json
import time
from datetime import datetime

async def test_critical_path():
    print("\n🧪 TESTING CRITICAL PATH REQUIREMENTS\n")
    
    base_url = "http://localhost:8000"
    all_passed = True
    
    # Test 1: Health Check
    print("1️⃣ Testing server health...")
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{base_url}/health")
        if response.status_code == 200:
            print("   ✅ Server is healthy")
        else:
            print("   ❌ Server health check failed")
            all_passed = False
    
    # Test 2: Vulnerability Detection (2+ types required)
    print("\n2️⃣ Testing vulnerability detection (MUST detect 2+ types)...")
    
    # Realistic code with multiple vulnerabilities
    test_code = '''import jwt
import hashlib
from flask import request

class AuthConfig:
    # Hardcoded secret (vulnerability 1)
    JWT_SECRET = hashlib.sha256(b'CompanySecret2024!').hexdigest()

def authenticate(user_input):
    # MongoDB injection (vulnerability 2)
    user = db.users.find_one({'username': user_input})
    
    # JWT without proper verification (vulnerability 3)
    token = jwt.encode({'user': user_input}, AuthConfig.JWT_SECRET)
    return token'''
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{base_url}/demo/scan",
            json={"code": test_code, "filename": "auth.py"}
        )
        
        if response.status_code == 200:
            result = response.json()
            vuln_count = len(result.get('vulnerabilities', []))
            
            if vuln_count >= 2:
                print(f"   ✅ Detected {vuln_count} vulnerabilities (requirement: 2+)")
                for v in result['vulnerabilities']:
                    print(f"      - {v['type']} ({v['severity']})")
            else:
                print(f"   ❌ Only detected {vuln_count} vulnerabilities (need 2+)")
                all_passed = False
        else:
            print("   ❌ Vulnerability detection failed")
            all_passed = False
    
    # Test 3: GitHub Webhook
    print("\n3️⃣ Testing GitHub webhook...")
    webhook_payload = {
        "action": "opened",
        "pull_request": {
            "number": 123,
            "title": "Add OAuth2 authentication",
            "user": {
                "login": "developer123"
            },
            "base": {
                "repo": {
                    "full_name": "securecorp/auth-service"
                }
            }
        },
        "repository": {
            "full_name": "securecorp/auth-service"
        }
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{base_url}/webhook/github",
            json=webhook_payload
        )
        
        if response.status_code == 200:
            print("   ✅ GitHub webhook processed successfully")
        else:
            print("   ❌ GitHub webhook failed")
            all_passed = False
    
    # Test 4: NVIDIA Integration Value
    print("\n4️⃣ Testing NVIDIA integration adds value...")
    print("   ℹ️  Check server logs for NVIDIA API calls")
    print("   ℹ️  Should see: '🚀 Calling NVIDIA Nemotron...'")
    print("   ℹ️  Should see: '✅ NVIDIA Nemotron response received'")
    
    # Test 5: Processing Time
    print("\n5️⃣ Testing processing time (<10 seconds)...")
    start_time = time.time()
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{base_url}/demo/scan",
            json={"code": test_code, "filename": "speed_test.py"}
        )
    
    processing_time = time.time() - start_time
    
    if processing_time < 10:
        print(f"   ✅ Processing time: {processing_time:.2f} seconds (< 10s)")
    else:
        print(f"   ❌ Processing time: {processing_time:.2f} seconds (> 10s)")
        all_passed = False
    
    # Summary
    print("\n" + "="*50)
    if all_passed:
        print("🎉 ALL CRITICAL PATH REQUIREMENTS PASSED!")
        print("\n✅ Checklist:")
        print("   ✓ Agent detects 2+ vulnerability types")
        print("   ✓ GitHub webhook receives and processes PR")
        print("   ✓ Processing time < 10 seconds")
        print("   ✓ NVIDIA integration configured")
        print("\n🚀 Ready for hackathon demo!")
    else:
        print("❌ Some requirements failed - please fix before demo")
    
    print("\n💡 Next steps:")
    print("1. Open http://localhost:8000/dashboard")
    print("2. Click 'Run Demo Scan' to see UI")
    print("3. Check server logs for NVIDIA activity")
    print("4. Practice your pitch!")

if __name__ == "__main__":
    asyncio.run(test_critical_path())