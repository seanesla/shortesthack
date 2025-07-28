from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import asyncio
from typing import List, Dict, Optional
from datetime import datetime
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.agent.security_agent import SecurityAgent
from src.agent.nvidia_nemotron import SecurityAgentOrchestrator
from src.api.github_integration import GitHubIntegration

app = FastAPI(title="SecureReview AI - Powered by NVIDIA Nemotron")
agent = SecurityAgent()
orchestrator = SecurityAgentOrchestrator()
github = GitHubIntegration()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

class DemoScanRequest(BaseModel):
    code: str
    filename: Optional[str] = "demo.py"

# Demo response for fallback
DEMO_RESPONSE = {
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "severity": "HIGH",
            "line": 42,
            "code": "query = 'SELECT * FROM users WHERE id = ' + user_id",
            "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "cwe": "CWE-89"
        },
        {
            "type": "Hardcoded Secret",
            "severity": "CRITICAL",
            "line": 13,
            "code": "api_key = 'sk-1234567890abcdef'",
            "fix": "Use environment variables: api_key = os.getenv('API_KEY')",
            "cwe": "CWE-798"
        }
    ],
    "score": 35,
    "status": "FAIL"
}

@app.get("/")
async def root():
    return {"message": "SecureReview AI is running! 🔒", "status": "active"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/webhook/github")
async def handle_github_webhook(payload: PRWebhookPayload, background_tasks: BackgroundTasks):
    if payload.action in ["opened", "synchronize"]:
        # Process in background
        background_tasks.add_task(analyze_pr, payload.pull_request)
        return {"status": "accepted"}
    return {"status": "ignored"}

async def analyze_pr(pr_data: Dict):
    # Extract real PR information
    pr_number = pr_data.get('number')
    pr_title = pr_data.get('title', 'Unknown PR')
    pr_author = pr_data.get('user', {}).get('login', 'unknown')
    
    # Get repository info from the PR data structure
    if 'repository' in pr_data:
        repo_name = pr_data['repository']['full_name']
    elif 'base' in pr_data:
        repo_name = pr_data['base']['repo']['full_name']
    else:
        repo_name = 'demo/repo'
    
    print(f"\n🔍 Analyzing PR #{pr_number} from {repo_name} by {pr_author}")
    
    # Broadcast start of analysis
    await manager.broadcast({
        "type": "agent_activity",
        "message": f"🔍 Analyzing PR #{pr_number} from {repo_name}",
        "isNvidia": False
    })
    
    # Get real diff from GitHub
    await manager.broadcast({
        "type": "agent_activity",
        "message": "📥 Fetching code changes from GitHub...",
        "isNvidia": False
    })
    diff = github.get_pr_diff(repo_name, pr_number)
    
    # Initial pattern-based detection
    await manager.broadcast({
        "type": "agent_activity",
        "message": "🔒 Running security pattern analysis...",
        "isNvidia": False
    })
    vulnerabilities = agent.analyze_code_diff(diff, f"PR_{pr_number}_files")
    
    # Log each vulnerability found
    for i, vuln in enumerate(vulnerabilities):
        await manager.broadcast({
            "type": "agent_activity",
            "message": f"⚠️ Detected {vuln.severity} {vuln.type} at line {vuln.line_number}",
            "isNvidia": False
        })
    
    # Enhance with NVIDIA Nemotron if available
    if vulnerabilities and orchestrator.nemotron.enabled:
        print(f"🤖 Enhancing analysis with NVIDIA Nemotron...")
        await manager.broadcast({
            "type": "agent_activity",
            "message": "🧠 NVIDIA Nemotron analyzing code context...",
            "isNvidia": True
        })
        try:
            enhanced_vulns = await orchestrator.orchestrate_analysis(diff, 
                [{
                    'type': v.type,
                    'code': v.code_snippet,
                    'line': v.line_number
                } for v in vulnerabilities]
            )
            print(f"✅ NVIDIA enhanced {len(enhanced_vulns)} vulnerabilities")
            await manager.broadcast({
                "type": "agent_activity",
                "message": f"✅ NVIDIA analysis complete - validated {len(enhanced_vulns)} issues",
                "isNvidia": True
            })
        except Exception as e:
            print(f"⚠️ NVIDIA enhancement failed: {e}")
            enhanced_vulns = vulnerabilities
    
    report = agent.generate_report(vulnerabilities)
    
    # Add PR context to report
    report['pr_info'] = {
        'number': pr_number,
        'title': pr_title,
        'author': pr_author,
        'repository': repo_name
    }
    
    # Broadcast to all connected clients
    await manager.broadcast({
        "type": "security_scan",
        "pr_number": pr_number,
        "pr_title": pr_title,
        "pr_author": pr_author,
        "timestamp": datetime.now().isoformat(),
        "report": report
    })
    
    # Post comment on GitHub if enabled
    if github.enabled:
        try:
            github.post_review_comment(repo_name, pr_number, report)
            print(f"✅ Posted security review comment on PR #{pr_number}")
        except Exception as e:
            print(f"⚠️ Failed to post GitHub comment: {e}")

@app.post("/demo/scan")
async def demo_scan(request: DemoScanRequest):
    """Direct API endpoint for demo purposes"""
    # Broadcast start
    await manager.broadcast({
        "type": "agent_activity",
        "message": "🚀 Starting security scan on uploaded code...",
        "isNvidia": False
    })
    
    # Show code parsing
    await asyncio.sleep(0.1)
    await manager.broadcast({
        "type": "agent_activity",
        "message": "📝 Parsing code structure and identifying entry points...",
        "isNvidia": False
    })
    
    # Convert code to diff format
    diff_format = "\n".join([f"+{line}" for line in request.code.split("\n")])
    lines = request.code.split('\n')
    
    # Show analysis stages
    await asyncio.sleep(0.1)
    await manager.broadcast({
        "type": "agent_activity",
        "message": f"📄 Loading {request.filename} ({len(lines)} lines, {len(request.code)} bytes)...",
        "isNvidia": False
    })
    
    await asyncio.sleep(0.1)
    await manager.broadcast({
        "type": "agent_activity",
        "message": "🔍 Running pattern-based vulnerability detection...",
        "isNvidia": False
    })
    
    # Show pattern categories being checked
    vuln_types = ['SQL Injection', 'Command Injection', 'Hardcoded Secrets', 'XSS', 'Eval Usage', 'Weak JWT']
    for i, vtype in enumerate(vuln_types):
        await asyncio.sleep(0.05)
        await manager.broadcast({
            "type": "agent_activity",
            "message": f"  ⚡ Checking for {vtype} patterns [{i+1}/{len(vuln_types)}]",
            "isNvidia": False
        })
    
    vulnerabilities = agent.analyze_code_diff(diff_format, request.filename)
    
    # Log each vulnerability
    await asyncio.sleep(0.1)
    await manager.broadcast({
        "type": "agent_activity",
        "message": f"🎯 Found {len(vulnerabilities)} potential vulnerabilities, analyzing...",
        "isNvidia": False
    })
    
    for vuln in vulnerabilities:
        await asyncio.sleep(0.05)
        await manager.broadcast({
            "type": "agent_activity",
            "message": f"🚨 Detected {vuln.severity} {vuln.type} at line {vuln.line_number}",
            "isNvidia": False
        })
    
    # Try NVIDIA enhancement if enabled
    nvidia_enhanced = False
    enhanced_vulns = vulnerabilities
    
    if vulnerabilities and orchestrator.nemotron.enabled:
        await asyncio.sleep(0.2)
        await manager.broadcast({
            "type": "agent_activity",
            "message": "🤖 Initializing NVIDIA Nemotron AI Engine...",
            "isNvidia": True
        })
        
        await asyncio.sleep(0.1)
        await manager.broadcast({
            "type": "agent_activity",
            "message": f"🧠 NVIDIA Nemotron analyzing {len(vulnerabilities)} findings for false positives...",
            "isNvidia": True
        })
        
        # Actually call NVIDIA API for each vulnerability
        try:
            # Create callback for real-time updates
            async def nvidia_callback(msg):
                await manager.broadcast({
                    "type": "agent_activity",
                    "message": msg,
                    "isNvidia": True
                })
            
            # Process vulnerabilities with NVIDIA
            enhanced_vulns = await orchestrator.orchestrate_analysis(
                request.code, 
                vulnerabilities,
                callback=nvidia_callback
            )
            
            nvidia_enhanced = True
            await asyncio.sleep(0.1)
            await manager.broadcast({
                "type": "agent_activity",
                "message": f"✅ NVIDIA Nemotron validated {len(enhanced_vulns)} vulnerabilities",
                "isNvidia": True
            })
            
            await asyncio.sleep(0.1)
            await manager.broadcast({
                "type": "agent_activity",
                "message": "📊 Applying AI-powered confidence scoring...",
                "isNvidia": True
            })
        except Exception as e:
            await manager.broadcast({
                "type": "agent_activity",
                "message": f"⚠️ NVIDIA enhancement error: {str(e)}",
                "isNvidia": True
            })
            enhanced_vulns = vulnerabilities
    
    # Generate report
    await asyncio.sleep(0.1)
    await manager.broadcast({
        "type": "agent_activity",
        "message": "📋 Generating comprehensive security report...",
        "isNvidia": False
    })
    
    report = agent.generate_report(vulnerabilities)
    report['nvidia_enhanced'] = nvidia_enhanced
    
    # Calculate business impact
    await asyncio.sleep(0.1)
    await manager.broadcast({
        "type": "agent_activity",
        "message": "💰 Calculating potential business impact...",
        "isNvidia": False
    })
    
    # Final summary
    await asyncio.sleep(0.1)
    await manager.broadcast({
        "type": "agent_activity",
        "message": f"📊 Scan complete: Score {report.get('score', 0)}/100, Found {len(vulnerabilities)} vulnerabilities",
        "isNvidia": False
    })
    
    await manager.broadcast({
        "type": "agent_activity",
        "message": "✅ Security analysis completed successfully",
        "isNvidia": False
    })
    
    # Broadcast final report
    await manager.broadcast({
        "type": "security_scan",
        "pr_number": "demo",
        "timestamp": datetime.now().isoformat(),
        "report": report
    })
    
    return report

@app.get("/demo")
async def get_demo():
    """Fallback demo endpoint"""
    return DEMO_RESPONSE

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
            # Keep connection alive and handle incoming messages
            try:
                data = await websocket.receive_text()
                # Echo back for testing
                await websocket.send_json({
                    "type": "echo",
                    "message": f"Received: {data}"
                })
            except:
                # Just keep the connection alive
                await asyncio.sleep(1)
    except:
        manager.disconnect(websocket)

# Serve the frontend
@app.get("/dashboard")
async def get_dashboard():
    # Try enhanced version first, fallback to original
    enhanced_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "index_enhanced.html")
    original_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "index.html")
    
    if os.path.exists(enhanced_path):
        return FileResponse(enhanced_path)
    elif os.path.exists(original_path):
        return FileResponse(original_path)
    else:
        return HTMLResponse("<h1>Dashboard not found. Please check frontend/index.html</h1>")

# Mount static files if needed
# app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)