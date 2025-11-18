"""
src/agent/ws_client.py

Purpose: WebSocket client for communication with correlation engine
Context: Maintains persistent connection to receive rules and send events
"""

import asyncio
import logging
import json
from typing import Callable, Optional
import websockets

logger = logging.getLogger(__name__)


class WebSocketClient:
    """WebSocket client for agent-server communication"""
    
    def __init__(self, url: str, on_message: Callable):
        self.url = url
        self.on_message = on_message
        self.ws = None
        self.running = False
    
    async def connect(self):
        """Connect to WebSocket server"""
        self.running = True
        
        while self.running:
            try:
                async with websockets.connect(self.url) as websocket:
                    self.ws = websocket
                    logger.info(f"Connected to {self.url}")
                    
                    # Listen for messages
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            await self.on_message(data)
                        except json.JSONDecodeError:
                            logger.error("Invalid JSON received")
            
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                await asyncio.sleep(5)  # Retry after 5 seconds
    
    async def send(self, data: dict):
        """Send message to server"""
        if self.ws:
            try:
                await self.ws.send(json.dumps(data))
            except Exception as e:
                logger.error(f"Failed to send message: {e}")
    
    async def disconnect(self):
        """Disconnect from server"""
        self.running = False
        if self.ws:
            await self.ws.close()
    
    def is_connected(self) -> bool:
        return self.ws is not None and not self.ws.closed
