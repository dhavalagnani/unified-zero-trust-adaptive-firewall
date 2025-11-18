#!/bin/bash
# src/correlation/venv_setup.sh
# Setup Python environment for correlation engine

set -e

echo "Setting up correlation engine virtual environment..."

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip

# Install dependencies
pip install \
    asyncio==3.4.3 \
    aiosqlite==0.19.0 \
    aiofiles==23.2.1 \
    websockets==12.0 \
    pyyaml==6.0.1 \
    pytest==7.4.3 \
    pytest-asyncio==0.21.1

pip freeze > requirements.txt

echo "Correlation engine environment setup complete!"
