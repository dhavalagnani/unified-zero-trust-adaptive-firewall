"""
src/correlation/ingestion/zeek_listener.py

Purpose: Ingest and normalize security events from Zeek logs
Context: Zeek (formerly Bro) produces detailed network traffic logs.
         This listener parses Zeek JSON logs and converts them into
         normalized SecurityEvents for correlation processing.

Zeek Log Types Monitored:
- conn.log: Connection summaries
- dns.log: DNS queries/responses
- http.log: HTTP transactions
- ssl.log: SSL/TLS connections
- weird.log: Unusual network activity
- notice.log: Zeek notices (alerts)

Architecture:
- Tail Zeek log files for real-time processing
- Parse JSON format logs
- Extract relevant fields
- Normalize to SecurityEvent format
- Push to correlation engine
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator, Optional
import aiofiles

logger = logging.getLogger(__name__)


class ZeekListener:
    """
    Listens to Zeek logs and generates security events
    
    Context: Monitors Zeek log directory for new entries and converts
             them to normalized security events
    """
    
    def __init__(self, log_path: str = "/var/log/zeek"):
        """
        Initialize Zeek listener
        
        Args:
            log_path: Path to Zeek log directory
        """
        self.log_path = Path(log_path)
        self.running = False
        
        # Log files to monitor
        self.monitored_logs = [
            'conn.log',
            'dns.log',
            'http.log',
            'ssl.log',
            'weird.log',
            'notice.log'
        ]
        
        logger.info(f"Zeek listener initialized for path: {log_path}")
    
    async def start(self, event_callback):
        """
        Start listening to Zeek logs
        
        Args:
            event_callback: Async function to call with each SecurityEvent
        """
        self.running = True
        logger.info("Starting Zeek log monitoring...")
        
        # Start monitoring each log file
        tasks = []
        for log_file in self.monitored_logs:
            log_path = self.log_path / log_file
            if log_path.exists():
                task = asyncio.create_task(
                    self._monitor_log_file(log_path, event_callback)
                )
                tasks.append(task)
            else:
                logger.warning(f"Zeek log file not found: {log_path}")
        
        # Wait for all monitoring tasks
        await asyncio.gather(*tasks)
    
    async def stop(self):
        """Stop the listener"""
        self.running = False
        logger.info("Stopping Zeek log monitoring...")
    
    async def _monitor_log_file(self, log_path: Path, event_callback):
        """
        Monitor a single Zeek log file
        
        Uses tail-like functionality to read new entries as they appear
        """
        logger.info(f"Monitoring Zeek log: {log_path.name}")
        
        try:
            async with aiofiles.open(log_path, 'r') as f:
                # Seek to end of file
                await f.seek(0, 2)
                
                while self.running:
                    line = await f.readline()
                    
                    if line:
                        # Parse and process the log entry
                        event = self._parse_zeek_log(log_path.name, line)
                        if event:
                            await event_callback(event)
                    else:
                        # No new data, wait a bit
                        await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.error(f"Error monitoring {log_path.name}: {e}")
    
    def _parse_zeek_log(self, log_type: str, line: str):
        """
        Parse a Zeek log line and convert to SecurityEvent
        
        Args:
            log_type: Type of log file (conn.log, dns.log, etc.)
            line: Log line to parse
        
        Returns:
            SecurityEvent or None if not relevant
        """
        # Skip comments and empty lines
        if not line.strip() or line.startswith('#'):
            return None
        
        try:
            # Zeek logs can be JSON or TSV format
            # Assuming JSON format here
            data = json.loads(line)
            
            # Route to specific parser based on log type
            if log_type == 'conn.log':
                return self._parse_conn_log(data)
            elif log_type == 'dns.log':
                return self._parse_dns_log(data)
            elif log_type == 'http.log':
                return self._parse_http_log(data)
            elif log_type == 'weird.log':
                return self._parse_weird_log(data)
            elif log_type == 'notice.log':
                return self._parse_notice_log(data)
            
            return None
        
        except json.JSONDecodeError:
            # Try TSV format
            return self._parse_tsv_format(log_type, line)
        except Exception as e:
            logger.error(f"Error parsing Zeek log: {e}")
            return None
    
    def _parse_conn_log(self, data: dict):
        """Parse Zeek connection log entry"""
        from correlation.engine import SecurityEvent
        
        # Look for suspicious connection patterns
        duration = data.get('duration', 0)
        orig_bytes = data.get('orig_bytes', 0)
        resp_bytes = data.get('resp_bytes', 0)
        
        # Detect potential issues
        event_type = 'normal_connection'
        severity = 'low'
        
        # Short-lived connections with no data transfer (scanning?)
        if duration < 1 and orig_bytes == 0 and resp_bytes == 0:
            event_type = 'suspicious_connection'
            severity = 'medium'
        
        # Large data transfer (potential exfiltration?)
        if orig_bytes > 10000000:  # > 10MB
            event_type = 'data_exfiltration'
            severity = 'high'
        
        return SecurityEvent(
            timestamp=datetime.fromtimestamp(data.get('ts', 0)),
            source_ip=data.get('id.orig_h', ''),
            dest_ip=data.get('id.resp_h', ''),
            source_port=int(data.get('id.orig_p', 0)),
            dest_port=int(data.get('id.resp_p', 0)),
            protocol=data.get('proto', 'tcp').lower(),
            event_type=event_type,
            severity=severity,
            source='zeek',
            metadata={
                'duration': duration,
                'orig_bytes': orig_bytes,
                'resp_bytes': resp_bytes,
                'conn_state': data.get('conn_state', '')
            }
        )
    
    def _parse_dns_log(self, data: dict):
        """Parse Zeek DNS log entry"""
        from correlation.engine import SecurityEvent
        
        # Detect suspicious DNS queries
        query = data.get('query', '')
        qtype_name = data.get('qtype_name', '')
        
        event_type = 'dns_query'
        severity = 'low'
        
        # Check for suspicious patterns
        if len(query) > 50:  # Unusually long domain name
            event_type = 'suspicious_dns'
            severity = 'medium'
        
        # DGA (Domain Generation Algorithm) detection (simple heuristic)
        if '-' in query or len(query.split('.')[0]) > 20:
            event_type = 'potential_dga'
            severity = 'high'
        
        return SecurityEvent(
            timestamp=datetime.fromtimestamp(data.get('ts', 0)),
            source_ip=data.get('id.orig_h', ''),
            dest_ip=data.get('id.resp_h', ''),
            source_port=int(data.get('id.orig_p', 0)),
            dest_port=int(data.get('id.resp_p', 53)),
            protocol='udp',
            event_type=event_type,
            severity=severity,
            source='zeek',
            metadata={
                'query': query,
                'qtype': qtype_name
            }
        )
    
    def _parse_http_log(self, data: dict):
        """Parse Zeek HTTP log entry"""
        from correlation.engine import SecurityEvent
        
        method = data.get('method', '')
        uri = data.get('uri', '')
        status_code = data.get('status_code', 0)
        user_agent = data.get('user_agent', '')
        
        event_type = 'http_request'
        severity = 'low'
        
        # Detect suspicious HTTP activity
        if status_code >= 400:
            event_type = 'http_error'
            severity = 'low'
        
        # SQL injection patterns in URI
        if any(pattern in uri.lower() for pattern in ['union select', 'or 1=1', 'drop table']):
            event_type = 'sql_injection_attempt'
            severity = 'critical'
        
        # Path traversal attempt
        if '../' in uri or '..\\' in uri:
            event_type = 'path_traversal_attempt'
            severity = 'high'
        
        return SecurityEvent(
            timestamp=datetime.fromtimestamp(data.get('ts', 0)),
            source_ip=data.get('id.orig_h', ''),
            dest_ip=data.get('id.resp_h', ''),
            source_port=int(data.get('id.orig_p', 0)),
            dest_port=int(data.get('id.resp_p', 80)),
            protocol='tcp',
            event_type=event_type,
            severity=severity,
            source='zeek',
            metadata={
                'method': method,
                'uri': uri,
                'status_code': status_code,
                'user_agent': user_agent
            }
        )
    
    def _parse_weird_log(self, data: dict):
        """Parse Zeek weird.log (unusual network behavior)"""
        from correlation.engine import SecurityEvent
        
        # Weird logs indicate anomalous network activity
        weird_name = data.get('name', '')
        
        return SecurityEvent(
            timestamp=datetime.fromtimestamp(data.get('ts', 0)),
            source_ip=data.get('id.orig_h', 'unknown'),
            dest_ip=data.get('id.resp_h', 'unknown'),
            source_port=int(data.get('id.orig_p', 0)),
            dest_port=int(data.get('id.resp_p', 0)),
            protocol='unknown',
            event_type='anomalous_behavior',
            severity='medium',
            source='zeek',
            metadata={
                'weird_name': weird_name,
                'notice': data.get('notice', False)
            }
        )
    
    def _parse_notice_log(self, data: dict):
        """Parse Zeek notice.log (Zeek-generated alerts)"""
        from correlation.engine import SecurityEvent
        
        note = data.get('note', '')
        msg = data.get('msg', '')
        
        # Map Zeek notice types to severity
        severity_map = {
            'Scan::Port_Scan': 'high',
            'Scan::Address_Scan': 'high',
            'SSH::Password_Guessing': 'critical',
            'SSL::Invalid_Server_Cert': 'medium',
        }
        
        severity = severity_map.get(note, 'medium')
        
        return SecurityEvent(
            timestamp=datetime.fromtimestamp(data.get('ts', 0)),
            source_ip=data.get('src', 'unknown'),
            dest_ip=data.get('dst', 'unknown'),
            source_port=int(data.get('p', 0)),
            dest_port=0,
            protocol='unknown',
            event_type=note.lower().replace('::', '_'),
            severity=severity,
            source='zeek',
            metadata={
                'notice': note,
                'message': msg
            }
        )
    
    def _parse_tsv_format(self, log_type: str, line: str):
        """Parse TSV format Zeek logs (fallback)"""
        # TODO: Implement TSV parsing if needed
        # Zeek can output in both JSON and TSV formats
        pass


if __name__ == "__main__":
    # Test the Zeek listener
    async def test_callback(event):
        print(f"Received event: {event.event_type} from {event.source_ip}")
    
    listener = ZeekListener()
    
    # In production, this would run indefinitely
    # asyncio.run(listener.start(test_callback))
