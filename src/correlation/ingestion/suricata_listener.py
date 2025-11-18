"""
src/correlation/ingestion/suricata_listener.py

Purpose: Ingest and normalize security events from Suricata IDS/IPS
Context: Suricata outputs events in EVE JSON format. This listener parses
         those events and converts them into normalized SecurityEvents.

Suricata Event Types:
- alert: IDS/IPS alerts (signature matches)
- flow: Network flow summaries
- http: HTTP transaction logs
- dns: DNS query/response logs
- tls: TLS/SSL connection details
- fileinfo: File extraction metadata
- anomaly: Protocol anomalies

Architecture:
- Tail Suricata EVE JSON log
- Parse JSON events
- Filter and normalize relevant events
- Push to correlation engine
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
import aiofiles

logger = logging.getLogger(__name__)


class SuricataListener:
    """
    Listens to Suricata EVE JSON log and generates security events
    
    Context: Monitors Suricata's eve.json output file for IDS/IPS alerts
             and other security-relevant events
    """
    
    def __init__(self, eve_log_path: str = "/var/log/suricata/eve.json"):
        """
        Initialize Suricata listener
        
        Args:
            eve_log_path: Path to Suricata EVE JSON log file
        """
        self.eve_log_path = Path(eve_log_path)
        self.running = False
        
        logger.info(f"Suricata listener initialized for: {eve_log_path}")
    
    async def start(self, event_callback):
        """
        Start listening to Suricata EVE log
        
        Args:
            event_callback: Async function to call with each SecurityEvent
        """
        self.running = True
        logger.info("Starting Suricata EVE log monitoring...")
        
        if not self.eve_log_path.exists():
            logger.error(f"Suricata EVE log not found: {self.eve_log_path}")
            return
        
        try:
            async with aiofiles.open(self.eve_log_path, 'r') as f:
                # Seek to end of file to get only new events
                await f.seek(0, 2)
                
                while self.running:
                    line = await f.readline()
                    
                    if line:
                        event = self._parse_eve_event(line)
                        if event:
                            await event_callback(event)
                    else:
                        await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.error(f"Error monitoring Suricata EVE log: {e}")
    
    async def stop(self):
        """Stop the listener"""
        self.running = False
        logger.info("Stopping Suricata EVE log monitoring...")
    
    def _parse_eve_event(self, line: str):
        """
        Parse Suricata EVE JSON event
        
        Args:
            line: JSON line from EVE log
        
        Returns:
            SecurityEvent or None
        """
        try:
            data = json.loads(line)
            event_type = data.get('event_type', '')
            
            # Route to appropriate parser based on event type
            if event_type == 'alert':
                return self._parse_alert(data)
            elif event_type == 'anomaly':
                return self._parse_anomaly(data)
            elif event_type == 'dns':
                return self._parse_dns(data)
            elif event_type == 'http':
                return self._parse_http(data)
            elif event_type == 'tls':
                return self._parse_tls(data)
            elif event_type == 'flow':
                return self._parse_flow(data)
            
            return None
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse EVE JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing EVE event: {e}")
            return None
    
    def _parse_alert(self, data: dict):
        """
        Parse Suricata alert event
        
        Alerts are triggered by signature matches (like Snort rules)
        """
        from correlation.engine import SecurityEvent
        
        alert = data.get('alert', {})
        signature = alert.get('signature', '')
        category = alert.get('category', '')
        severity = alert.get('severity', 3)
        
        # Map Suricata severity (1-4) to our severity levels
        severity_map = {
            1: 'critical',  # High priority
            2: 'high',      # Medium priority
            3: 'medium',    # Low priority
            4: 'low'        # Informational
        }
        
        # Extract IPs and ports
        src_ip = data.get('src_ip', '')
        dest_ip = data.get('dest_ip', '')
        src_port = data.get('src_port', 0)
        dest_port = data.get('dest_port', 0)
        proto = data.get('proto', '').lower()
        
        return SecurityEvent(
            timestamp=datetime.fromisoformat(data.get('timestamp', '').replace('Z', '+00:00')),
            source_ip=src_ip,
            dest_ip=dest_ip,
            source_port=int(src_port),
            dest_port=int(dest_port),
            protocol=proto,
            event_type=category.lower().replace(' ', '_'),
            severity=severity_map.get(severity, 'medium'),
            source='suricata',
            metadata={
                'signature': signature,
                'signature_id': alert.get('signature_id'),
                'category': category,
                'gid': alert.get('gid'),
                'sid': alert.get('sid')
            }
        )
    
    def _parse_anomaly(self, data: dict):
        """Parse protocol anomaly events"""
        from correlation.engine import SecurityEvent
        
        anomaly = data.get('anomaly', {})
        anomaly_type = anomaly.get('type', '')
        
        return SecurityEvent(
            timestamp=datetime.fromisoformat(data.get('timestamp', '').replace('Z', '+00:00')),
            source_ip=data.get('src_ip', ''),
            dest_ip=data.get('dest_ip', ''),
            source_port=int(data.get('src_port', 0)),
            dest_port=int(data.get('dest_port', 0)),
            protocol=data.get('proto', '').lower(),
            event_type='protocol_anomaly',
            severity='medium',
            source='suricata',
            metadata={
                'anomaly_type': anomaly_type,
                'layer': anomaly.get('layer'),
                'code': anomaly.get('code')
            }
        )
    
    def _parse_dns(self, data: dict):
        """Parse DNS event"""
        from correlation.engine import SecurityEvent
        
        dns = data.get('dns', {})
        query = dns.get('rrname', '')
        rcode = dns.get('rcode', '')
        
        # Detect suspicious DNS patterns
        event_type = 'dns_query'
        severity = 'low'
        
        # DNS tunneling detection (long subdomain names)
        if len(query) > 60:
            event_type = 'potential_dns_tunneling'
            severity = 'high'
        
        # NXDOMAIN responses could indicate DGA
        if rcode == 'NXDOMAIN':
            event_type = 'dns_nxdomain'
            severity = 'low'
        
        return SecurityEvent(
            timestamp=datetime.fromisoformat(data.get('timestamp', '').replace('Z', '+00:00')),
            source_ip=data.get('src_ip', ''),
            dest_ip=data.get('dest_ip', ''),
            source_port=int(data.get('src_port', 0)),
            dest_port=int(data.get('dest_port', 53)),
            protocol='udp',
            event_type=event_type,
            severity=severity,
            source='suricata',
            metadata={
                'query': query,
                'qtype': dns.get('rrtype'),
                'rcode': rcode
            }
        )
    
    def _parse_http(self, data: dict):
        """Parse HTTP event"""
        from correlation.engine import SecurityEvent
        
        http = data.get('http', {})
        url = http.get('url', '')
        hostname = http.get('hostname', '')
        http_method = http.get('http_method', '')
        status = http.get('status', 0)
        
        event_type = 'http_request'
        severity = 'low'
        
        # Detect suspicious HTTP patterns
        if status >= 500:
            event_type = 'http_server_error'
            severity = 'medium'
        elif status == 404:
            event_type = 'http_not_found'
            severity = 'low'
        
        # Web attack patterns
        suspicious_patterns = ['cmd=', 'exec=', '../', 'union select', '<script>']
        if any(pattern in url.lower() for pattern in suspicious_patterns):
            event_type = 'web_attack_attempt'
            severity = 'high'
        
        return SecurityEvent(
            timestamp=datetime.fromisoformat(data.get('timestamp', '').replace('Z', '+00:00')),
            source_ip=data.get('src_ip', ''),
            dest_ip=data.get('dest_ip', ''),
            source_port=int(data.get('src_port', 0)),
            dest_port=int(data.get('dest_port', 80)),
            protocol='tcp',
            event_type=event_type,
            severity=severity,
            source='suricata',
            metadata={
                'url': url,
                'hostname': hostname,
                'method': http_method,
                'status': status,
                'user_agent': http.get('http_user_agent', '')
            }
        )
    
    def _parse_tls(self, data: dict):
        """Parse TLS/SSL event"""
        from correlation.engine import SecurityEvent
        
        tls = data.get('tls', {})
        subject = tls.get('subject', '')
        issuer = tls.get('issuerdn', '')
        
        event_type = 'tls_connection'
        severity = 'low'
        
        # Self-signed certificates
        if subject == issuer:
            event_type = 'self_signed_cert'
            severity = 'medium'
        
        # Expired or invalid certificates
        if tls.get('notbefore'):
            event_type = 'invalid_cert'
            severity = 'medium'
        
        return SecurityEvent(
            timestamp=datetime.fromisoformat(data.get('timestamp', '').replace('Z', '+00:00')),
            source_ip=data.get('src_ip', ''),
            dest_ip=data.get('dest_ip', ''),
            source_port=int(data.get('src_port', 0)),
            dest_port=int(data.get('dest_port', 443)),
            protocol='tcp',
            event_type=event_type,
            severity=severity,
            source='suricata',
            metadata={
                'subject': subject,
                'issuer': issuer,
                'sni': tls.get('sni'),
                'version': tls.get('version')
            }
        )
    
    def _parse_flow(self, data: dict):
        """Parse network flow event"""
        from correlation.engine import SecurityEvent
        
        flow = data.get('flow', {})
        bytes_toserver = flow.get('bytes_toserver', 0)
        bytes_toclient = flow.get('bytes_toclient', 0)
        pkts_toserver = flow.get('pkts_toserver', 0)
        
        event_type = 'network_flow'
        severity = 'low'
        
        # Large data transfers
        if bytes_toserver > 10000000:  # > 10MB uploaded
            event_type = 'large_upload'
            severity = 'medium'
        
        # Potential DDoS (many packets, little data)
        if pkts_toserver > 1000 and bytes_toserver < 10000:
            event_type = 'potential_ddos'
            severity = 'high'
        
        return SecurityEvent(
            timestamp=datetime.fromisoformat(data.get('timestamp', '').replace('Z', '+00:00')),
            source_ip=data.get('src_ip', ''),
            dest_ip=data.get('dest_ip', ''),
            source_port=int(data.get('src_port', 0)),
            dest_port=int(data.get('dest_port', 0)),
            protocol=data.get('proto', '').lower(),
            event_type=event_type,
            severity=severity,
            source='suricata',
            metadata={
                'bytes_toserver': bytes_toserver,
                'bytes_toclient': bytes_toclient,
                'pkts_toserver': pkts_toserver,
                'pkts_toclient': flow.get('pkts_toclient', 0)
            }
        )


if __name__ == "__main__":
    # Test the Suricata listener
    async def test_callback(event):
        print(f"Received event: {event.event_type} - {event.severity} - {event.source_ip}")
    
    listener = SuricataListener()
    # asyncio.run(listener.start(test_callback))
