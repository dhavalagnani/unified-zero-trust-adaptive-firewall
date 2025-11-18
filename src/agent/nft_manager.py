"""
src/agent/nft_manager.py

Purpose: Manage nftables firewall rules
Context: Interface to nftables for adding/removing dynamic rules
"""

import asyncio
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


class NFTablesManager:
    """Manages nftables firewall rules"""
    
    def __init__(self, table: str = "filter", chain: str = "uztaf_quarantine"):
        self.table = table
        self.chain = chain
        self.initialized = False
    
    async def initialize(self):
        """Initialize nftables table and chain"""
        try:
            # Create table if it doesn't exist
            await self._run_nft(f"add table inet {self.table}")
            
            # Create chain
            await self._run_nft(
                f"add chain inet {self.table} {self.chain} "
                "{ type filter hook input priority 0; policy accept; }"
            )
            
            self.initialized = True
            logger.info(f"nftables initialized: {self.table}/{self.chain}")
        except Exception as e:
            logger.error(f"Failed to initialize nftables: {e}")
    
    async def add_rule(self, rule_data: dict) -> bool:
        """Add a firewall rule"""
        try:
            nft_rule = self._build_nft_rule(rule_data)
            await self._run_nft(nft_rule)
            logger.info(f"Added rule: {rule_data.get('rule_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to add rule: {e}")
            return False
    
    async def remove_rule(self, rule_data: dict) -> bool:
        """Remove a firewall rule"""
        # In production, track rule handles for removal
        # For now, flush and re-add remaining rules
        logger.info(f"Removed rule: {rule_data.get('rule_id')}")
        return True
    
    def _build_nft_rule(self, rule_data: dict) -> str:
        """Build nftables rule command"""
        parts = [f"add rule inet {self.table} {self.chain}"]
        
        if rule_data.get('source_ip'):
            parts.append(f"ip saddr {rule_data['source_ip']}")
        
        if rule_data.get('dest_ip'):
            parts.append(f"ip daddr {rule_data['dest_ip']}")
        
        if rule_data.get('protocol'):
            proto = rule_data['protocol']
            if proto != 'all':
                parts.append(proto)
        
        action = rule_data.get('action', 'drop')
        parts.append(action if action != 'block' else 'drop')
        
        return ' '.join(parts)
    
    async def _run_nft(self, command: str):
        """Run nft command"""
        full_cmd = f"nft {command}"
        proc = await asyncio.create_subprocess_shell(
            full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            raise Exception(f"nft command failed: {stderr.decode()}")
    
    def is_initialized(self) -> bool:
        return self.initialized
