#!/bin/bash

echo "🚀 Starting SecureReview AI Demo"
echo "================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# 2. Activate virtual environment
echo -e "${GREEN}Activating virtual environment...${NC}"
source venv/bin/activate

# 3. Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt

# 4. Copy .env file if not exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Creating .env file...${NC}"
    cp .env.example .env
    echo -e "${RED}Please edit .env file with your API keys!${NC}"
fi

# 5. Start the server
echo -e "${GREEN}Starting FastAPI server...${NC}"
cd src/api
python -m uvicorn server:app --reload --port 8000 &
SERVER_PID=$!

# Wait for server to start
sleep 3

# 6. Open the dashboard
echo -e "${GREEN}Opening dashboard...${NC}"
if command -v xdg-open > /dev/null; then
    xdg-open http://localhost:8000/dashboard
elif command -v open > /dev/null; then
    open http://localhost:8000/dashboard
else
    echo -e "${YELLOW}Please open http://localhost:8000/dashboard in your browser${NC}"
fi

# 7. Display demo instructions
echo -e "\n${GREEN}✅ Demo ready!${NC}"
echo -e "\n${YELLOW}Demo Instructions:${NC}"
echo "1. Click 'Run Demo Scan' button to see vulnerabilities"
echo "2. Or use curl to simulate a GitHub webhook:"
echo ""
echo "curl -X POST http://localhost:8000/webhook/github \\"
echo "  -H 'Content-Type: application/json' \\"
echo "  -d '{"
echo '    "action": "opened",'
echo '    "pull_request": {'
echo '      "number": 42,'
echo '      "title": "Add user authentication feature"'
echo '    },'
echo '    "repository": {'
echo '      "full_name": "demo/security-test"'
echo '    }'
echo "  }'"
echo ""
echo -e "${RED}Press Ctrl+C to stop the server${NC}"

# Wait for user to stop
wait $SERVER_PID