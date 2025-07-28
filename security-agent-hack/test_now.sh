#!/bin/bash
# One-click test script for SecureReview AI

echo "🚀 SecureReview AI - One-Click Test"
echo "=================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 1. Quick Python test
echo -e "\n${YELLOW}Step 1: Running quick vulnerability detection test...${NC}"
source venv/bin/activate 2>/dev/null || python3 -m venv venv && source venv/bin/activate
python quick_test.py

# 2. Ask if user wants to start the server
echo -e "\n${YELLOW}Step 2: Start the web dashboard?${NC}"
read -p "Would you like to start the server and open the dashboard? (y/n) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Kill any existing server
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    
    echo -e "\n${GREEN}Starting server...${NC}"
    uvicorn src.api.server:app --port 8000 > /dev/null 2>&1 &
    SERVER_PID=$!
    
    # Wait for server to start
    echo "Waiting for server to start..."
    sleep 3
    
    # Open dashboard
    echo -e "${GREEN}Opening dashboard...${NC}"
    if command -v open > /dev/null; then
        open http://localhost:8000/dashboard
    elif command -v xdg-open > /dev/null; then
        xdg-open http://localhost:8000/dashboard
    else
        echo -e "${YELLOW}Please open: http://localhost:8000/dashboard${NC}"
    fi
    
    echo -e "\n${GREEN}✅ Dashboard is ready!${NC}"
    echo "1. Click 'Run Demo Scan' to see vulnerabilities"
    echo "2. Or paste your own code"
    echo "3. Or enter a GitHub PR like: facebook/react#12345"
    echo -e "\n${RED}Press Ctrl+C to stop the server${NC}"
    
    # Keep running
    wait $SERVER_PID
else
    echo -e "\n${GREEN}✅ Test complete!${NC}"
    echo "To start the server later, run: ./run_enhanced.sh"
fi