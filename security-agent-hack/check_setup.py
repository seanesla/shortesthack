#!/usr/bin/env python3
"""Check setup status and guide through remaining steps"""

import os
from dotenv import load_dotenv
import sys

load_dotenv()

def check_setup():
    print("\n🔍 SecureReview AI Setup Checker\n")
    
    all_good = True
    
    # Check NVIDIA API Key
    nvidia_key = os.getenv("NVIDIA_API_KEY", "")
    if nvidia_key and nvidia_key != "nvapi-YOUR-KEY-HERE":
        print("✅ NVIDIA API Key configured")
    else:
        print("❌ NVIDIA API Key missing")
        print("   👉 Get it from: https://build.nvidia.com")
        print("   👉 Add to .env: NVIDIA_API_KEY=nvapi-...")
        all_good = False
    
    print()
    
    # Check GitHub Token
    github_token = os.getenv("GITHUB_TOKEN", "")
    if github_token and github_token != "your_github_token_here":
        print("✅ GitHub Token configured")
    else:
        print("❌ GitHub Token missing") 
        print("   👉 Get it from: https://github.com/settings/tokens")
        print("   👉 Add to .env: GITHUB_TOKEN=ghp_...")
        all_good = False
    
    print()
    
    # Check if server is running
    try:
        import requests
        response = requests.get("http://localhost:8000/health")
        if response.status_code == 200:
            print("✅ Server is running at http://localhost:8000")
        else:
            print("⚠️  Server is running but health check failed")
    except:
        print("❌ Server not running")
        print("   👉 Run: ./demo_script.sh")
        all_good = False
    
    print()
    
    if all_good:
        print("🎉 Everything is configured! You're ready for the hackathon!")
        print("\n📝 Quick Demo:")
        print("1. Open http://localhost:8000/dashboard")
        print("2. Click 'Run Demo Scan'")
        print("3. Watch vulnerabilities detected in real-time")
    else:
        print("⚠️  Some setup required - see above for instructions")
        print("\n💡 Demo will work with mock data even without API keys!")
    
    print("\n🚀 Hackathon Tips:")
    print("- The app works NOW with mock data")
    print("- API keys enable real GitHub/NVIDIA integration")
    print("- Focus on the demo impact, not the implementation")
    print("- Mention 'Powered by NVIDIA Nemotron-70B'")

if __name__ == "__main__":
    check_setup()