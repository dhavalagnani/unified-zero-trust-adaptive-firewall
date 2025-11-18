#!/bin/bash
# src/agent/venv_setup.sh
# Setup Python environment for agent

set -e

echo "Setting up agent virtual environment..."

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip

pip install \
    asyncio==3.4.3 \
    websockets==12.0 \
    pyyaml==6.0.1 \
    pytest==7.4.3

pip freeze > requirements.txt

echo "Agent environment setup complete!"
