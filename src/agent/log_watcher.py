"""
src/agent/log_watcher.py

Purpose: Monitor local log files for security events
Context: Watches auth.log, syslog, etc. for suspicious activity
"""

import asyncio
import logging
import re
from typing import List, Callable
from pathlib import Path

logger = logging.getLogger(__name__)


class LogWatcher:
    """Watches log files for security events"""
    
    def __init__(self, log_paths: List[str], on_event: Callable):
        self.log_paths = [Path(p) for p in log_paths]
        self.on_event = on_event
        self.running = False
        
        # Patterns to detect
        self.patterns = {
            'failed_login': re.compile(r'Failed password for .* from ([\d.]+)'),
            'sudo_command': re.compile(r'sudo:.*COMMAND=(.*)'),
            'ssh_connection': re.compile(r'Accepted .* for .* from ([\d.]+)')
        }
    
    async def start(self):
        """Start watching logs"""
        self.running = True
        tasks = [self._watch_file(path) for path in self.log_paths if path.exists()]
        await asyncio.gather(*tasks)
    
    async def stop(self):
        """Stop watching logs"""
        self.running = False
    
    async def _watch_file(self, log_path: Path):
        """Watch a single log file"""
        try:
            with open(log_path, 'r') as f:
                f.seek(0, 2)  # Seek to end
                
                while self.running:
                    line = f.readline()
                    if line:
                        await self._process_line(line)
                    else:
                        await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Error watching {log_path}: {e}")
    
    async def _process_line(self, line: str):
        """Process a log line"""
        for event_type, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                event = {
                    'event_type': event_type,
                    'line': line.strip(),
                    'match': match.groups()
                }
                await self.on_event(event)
