#!/bin/bash
#
# src/pep/venv_setup.sh
#
# Purpose: Setup Python virtual environment for PEP (Policy Enforcement Point)
# Context: Creates isolated Python environment and installs all required
#          dependencies for the FastAPI-based reverse proxy
#
# Usage: bash venv_setup.sh

set -e

echo "Setting up Python virtual environment for PEP..."

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}Python 3 is not installed. Please install Python 3.9 or later.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "Found Python $PYTHON_VERSION"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created${NC}"
else
    echo "Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."

# Core dependencies for FastAPI PEP
pip install \
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    httpx==0.25.1 \
    python-jose[cryptography]==3.3.0 \
    python-multipart==0.0.6 \
    pydantic==2.5.0 \
    pydantic-settings==2.1.0 \
    pyyaml==6.0.1 \
    python-dotenv==1.0.0

# Testing dependencies
pip install \
    pytest==7.4.3 \
    pytest-asyncio==0.21.1 \
    pytest-cov==4.1.0 \
    httpx==0.25.1

# Additional utilities
pip install \
    aiofiles==23.2.1 \
    websockets==12.0

echo -e "${GREEN}Dependencies installed successfully${NC}"

# Create requirements.txt for reference
echo "Generating requirements.txt..."
pip freeze > requirements.txt
echo -e "${GREEN}requirements.txt generated${NC}"

# Deactivate virtual environment
deactivate

echo -e "${GREEN}PEP virtual environment setup complete!${NC}"
echo ""
echo "To activate the virtual environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To run the PEP service:"
echo "  source venv/bin/activate"
echo "  python app.py"
echo "  # or"
echo "  uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4"
