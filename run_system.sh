#!/bin/bash

# Advanced Network Anomaly Detection System Startup Script
# Author: Aryan Pravin Sahu | IIT Ropar

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print header
echo "================================================================"
echo "ADVANCED NETWORK ANOMALY DETECTION SYSTEM"
echo "AI-Powered Cybersecurity Research Platform"
echo "Author: Aryan Pravin Sahu | IIT Ropar"
echo "================================================================"
echo

echo -e "${BLUE}Starting system...${NC}"
echo

# Check if virtual environment exists
if [ ! -f "venv/bin/activate" ]; then
    echo -e "${RED}ERROR: Virtual environment not found!${NC}"
    echo "Please run setup.py first to install the system:"
    echo "  python setup.py"
    echo
    exit 1
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to activate virtual environment!${NC}"
    exit 1
fi

echo -e "${GREEN}Virtual environment activated successfully.${NC}"
echo

# Start the web application
echo -e "${BLUE}Starting web dashboard...${NC}"
echo -e "${GREEN}Dashboard will be available at: http://localhost:5000${NC}"
echo
echo -e "${YELLOW}Press Ctrl+C to stop the system${NC}"
echo "================================================================"
echo

# Run the application
python src/web/app.py

# If we get here, the system has stopped
echo
echo -e "${BLUE}System stopped.${NC}"