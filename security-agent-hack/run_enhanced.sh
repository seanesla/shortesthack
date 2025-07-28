#!/bin/bash

echo "🚀 Starting SecureReview AI with Enhanced UI"
echo "==========================================="

# Kill any existing processes on port 8000
echo "Cleaning up port 8000..."
lsof -ti:8000 | xargs kill -9 2>/dev/null || true

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Start the server
echo "Starting FastAPI server with enhanced UI..."
cd /Users/seane/Documents/GitHub/shortesthack/security-agent-hack
uvicorn src.api.server:app --reload --port 8000 &

# Wait for server to start
sleep 3

# Open the dashboard
echo "Opening enhanced dashboard..."
open http://localhost:8000/dashboard

echo ""
echo "✅ Enhanced UI is ready!"
echo ""
echo "Features:"
echo "- 🔍 Real GitHub PR Scanner: Enter 'owner/repo#123' to scan any PR"
echo "- 🧠 NVIDIA NIM Activity: See real-time AI reasoning"
echo "- 💰 Business Impact: Track $ saved by preventing breaches"
echo "- 🤖 Agent Activity Feed: Watch the agent work in real-time"
echo ""
echo "Press Ctrl+C to stop the server"

# Keep the script running
wait