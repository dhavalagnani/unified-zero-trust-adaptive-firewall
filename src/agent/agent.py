"""
src/agent/agent.py

Purpose: Enforcement agent that manages nftables rules on endpoints
Context: Receives dynamic firewall rules from correlation engine via WebSocket
         and enforces them using nftables. Monitors local logs and reports
         suspicious activity back to correlation engine.

Architecture:
- WebSocket client for bidirectional communication
- nftables rule manager for firewall enforcement
- Local log watcher for security events
- Heartbeat mechanism for health monitoring
- Rule expiration and automatic cleanup

Components:
- WebSocket connection to correlation server
- nftables integration via nft_manager
- Local event detection and reporting
- Configuration management
"""

import asyncio
import logging
import json
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from nft_manager import NFTablesManager
from ws_client import WebSocketClient
from log_watcher import LogWatcher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UZTAFAgent:
    """
    Main UZTAF enforcement agent
    
    Context: Runs on each protected endpoint to enforce dynamic firewall
             rules and report security events
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize the UZTAF agent
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        
        # Components
        self.nft_manager = NFTablesManager(
            table=self.config.get('nftables_table', 'filter'),
            chain=self.config.get('nftables_chain', 'uztaf_quarantine')
        )
        
        self.ws_client = WebSocketClient(
            url=self.config.get('correlation_ws_url', 'ws://localhost:5000/ws'),
            on_message=self._handle_message
        )
        
        self.log_watcher = LogWatcher(
            log_paths=self.config.get('watch_logs', ['/var/log/auth.log']),
            on_event=self._handle_local_event
        )
        
        # State
        self.active_rules: Dict[str, dict] = {}
        self.running = False
        self.agent_id = self.config.get('agent_id', 'agent-001')
        
        logger.info(f"UZTAF Agent initialized (ID: {self.agent_id})")
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from file or environment"""
        if Path(config_path).exists():
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        
        # Fallback to environment variables
        import os
        return {
            'correlation_ws_url': os.getenv('CORRELATION_WS_URL', 'ws://localhost:5000/ws'),
            'nftables_table': os.getenv('NFTABLES_TABLE', 'filter'),
            'nftables_chain': os.getenv('NFTABLES_CHAIN', 'uztaf_quarantine'),
            'agent_id': os.getenv('AGENT_ID', 'agent-001'),
            'heartbeat_interval': int(os.getenv('AGENT_HEARTBEAT_INTERVAL', '30')),
            'watch_logs': ['/var/log/auth.log', '/var/log/syslog']
        }
    
    async def start(self):
        """Start the agent"""
        self.running = True
        logger.info("Starting UZTAF Agent...")
        
        # Initialize nftables
        await self.nft_manager.initialize()
        
        # Start components
        tasks = [
            asyncio.create_task(self.ws_client.connect()),
            asyncio.create_task(self.log_watcher.start()),
            asyncio.create_task(self._heartbeat_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Agent interrupted")
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop the agent gracefully"""
        logger.info("Stopping UZTAF Agent...")
        self.running = False
        
        await self.ws_client.disconnect()
        await self.log_watcher.stop()
        
        logger.info("Agent stopped")
    
    async def _handle_message(self, message: dict):
        """
        Handle message from correlation server
        
        Message types:
        - new_rules: Apply new firewall rules
        - revoke_rule: Remove a specific rule
        - update_config: Update agent configuration
        """
        msg_type = message.get('type')
        
        logger.info(f"Received message: {msg_type}")
        
        if msg_type == 'new_rules':
            await self._apply_rules(message.get('rules', []))
        
        elif msg_type == 'revoke_rule':
            await self._revoke_rule(message.get('rule_id'))
        
        elif msg_type == 'update_config':
            await self._update_config(message.get('config', {}))
        
        elif msg_type == 'ping':
            await self._send_pong()
        
        else:
            logger.warning(f"Unknown message type: {msg_type}")
    
    async def _apply_rules(self, rules: List[dict]):
        """
        Apply firewall rules received from server
        
        Args:
            rules: List of rule dictionaries
        """
        logger.info(f"Applying {len(rules)} firewall rules...")
        
        for rule_data in rules:
            rule_id = rule_data.get('rule_id')
            
            try:
                # Add rule via nftables manager
                success = await self.nft_manager.add_rule(rule_data)
                
                if success:
                    self.active_rules[rule_id] = rule_data
                    logger.info(f"Applied rule: {rule_id}")
                else:
                    logger.error(f"Failed to apply rule: {rule_id}")
            
            except Exception as e:
                logger.error(f"Error applying rule {rule_id}: {e}")
        
        # Send acknowledgment
        await self._send_ack('rules_applied', {'count': len(rules)})
    
    async def _revoke_rule(self, rule_id: str):
        """
        Remove a specific firewall rule
        
        Args:
            rule_id: ID of rule to remove
        """
        if rule_id in self.active_rules:
            rule_data = self.active_rules[rule_id]
            
            try:
                success = await self.nft_manager.remove_rule(rule_data)
                
                if success:
                    del self.active_rules[rule_id]
                    logger.info(f"Revoked rule: {rule_id}")
                else:
                    logger.error(f"Failed to revoke rule: {rule_id}")
            
            except Exception as e:
                logger.error(f"Error revoking rule {rule_id}: {e}")
        else:
            logger.warning(f"Rule not found: {rule_id}")
    
    async def _update_config(self, new_config: dict):
        """Update agent configuration"""
        self.config.update(new_config)
        logger.info("Configuration updated")
    
    async def _handle_local_event(self, event: dict):
        """
        Handle security event detected locally
        
        Args:
            event: Event dictionary from log watcher
        """
        logger.info(f"Local event detected: {event.get('event_type')}")
        
        # Send event to correlation server
        await self.ws_client.send({
            'type': 'security_event',
            'agent_id': self.agent_id,
            'event': event,
            'timestamp': datetime.now().isoformat()
        })
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeat to server"""
        interval = self.config.get('heartbeat_interval', 30)
        
        while self.running:
            try:
                await self.ws_client.send({
                    'type': 'heartbeat',
                    'agent_id': self.agent_id,
                    'active_rules': len(self.active_rules),
                    'timestamp': datetime.now().isoformat()
                })
                
                await asyncio.sleep(interval)
            
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(5)
    
    async def _cleanup_loop(self):
        """Periodically clean up expired rules"""
        while self.running:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                current_time = datetime.now()
                expired = []
                
                for rule_id, rule_data in self.active_rules.items():
                    expires_at = rule_data.get('expires_at')
                    if expires_at:
                        expires_dt = datetime.fromisoformat(expires_at)
                        if current_time >= expires_dt:
                            expired.append(rule_id)
                
                # Remove expired rules
                for rule_id in expired:
                    await self._revoke_rule(rule_id)
                    logger.info(f"Removed expired rule: {rule_id}")
            
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    async def _send_ack(self, ack_type: str, data: dict):
        """Send acknowledgment to server"""
        await self.ws_client.send({
            'type': 'ack',
            'ack_type': ack_type,
            'agent_id': self.agent_id,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
    
    async def _send_pong(self):
        """Respond to ping from server"""
        await self.ws_client.send({
            'type': 'pong',
            'agent_id': self.agent_id,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_status(self) -> dict:
        """Get agent status"""
        return {
            'agent_id': self.agent_id,
            'running': self.running,
            'active_rules': len(self.active_rules),
            'connected': self.ws_client.is_connected(),
            'nftables_ok': self.nft_manager.is_initialized()
        }


async def main():
    """Main entry point"""
    agent = UZTAFAgent()
    
    try:
        await agent.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
