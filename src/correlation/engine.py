"""
src/correlation/engine.py

Purpose: Main correlation engine for real-time security event analysis
Context: This is the core of the adaptive firewall system that:
         - Receives security events from Zeek, Suricata, and other sources
         - Correlates events using temporal and behavioral patterns
         - Generates dynamic firewall rules when threats are detected
         - Distributes rules to enforcement agents via WebSocket

Architecture:
- Event-driven architecture with async processing
- Uses trie-based pattern matching for efficient correlation
- Maintains sliding time windows for temporal correlation
- Calculates anomaly scores based on multiple factors
- Integrates with rules_generator for policy creation

Components:
- Event ingestion and normalization
- Pattern matching and correlation
- Anomaly scoring
- Rule generation and distribution
- WebSocket server for agent communication

Dependencies:
- asyncio: Async event processing
- websockets: Agent communication
- sqlite3: Event storage and history
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib

from models.trie import TrieNode, PatternMatcher
from rules_generator import RuleGenerator, FirewallRule
from storage.sqlite_store import EventStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """
    Normalized security event from various sources
    
    Context: Events from Zeek, Suricata, and other sources are normalized
             into this common format for correlation processing
    """
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    event_type: str  # e.g., 'suspicious_connection', 'malware', 'port_scan'
    severity: str  # 'low', 'medium', 'high', 'critical'
    source: str  # 'zeek', 'suricata', 'ids', etc.
    metadata: Dict
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage/transmission"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data
    
    def get_key(self) -> str:
        """Generate unique key for this event"""
        key_str = f"{self.source_ip}:{self.dest_ip}:{self.event_type}"
        return hashlib.md5(key_str.encode()).hexdigest()


@dataclass
class CorrelationResult:
    """
    Result of event correlation analysis
    
    Context: When multiple related events are detected, this captures
             the correlation details and recommended actions
    """
    threat_id: str
    threat_type: str
    confidence_score: float  # 0.0 to 1.0
    involved_ips: List[str]
    events: List[SecurityEvent]
    recommended_action: str  # 'block', 'quarantine', 'alert', 'monitor'
    created_at: datetime
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'threat_id': self.threat_id,
            'threat_type': self.threat_type,
            'confidence_score': self.confidence_score,
            'involved_ips': self.involved_ips,
            'events': [e.to_dict() for e in self.events],
            'recommended_action': self.recommended_action,
            'created_at': self.created_at.isoformat()
        }


class CorrelationEngine:
    """
    Main correlation engine for security event analysis
    
    Context: This engine processes security events in real-time, identifies
             patterns and anomalies, and generates adaptive firewall rules
    """
    
    def __init__(
        self,
        correlation_threshold: int = 3,
        time_window: int = 300,  # seconds
        anomaly_threshold: float = 0.75
    ):
        """
        Initialize correlation engine
        
        Args:
            correlation_threshold: Number of related events to trigger correlation
            time_window: Time window in seconds for event correlation
            anomaly_threshold: Confidence score threshold for rule generation
        """
        self.correlation_threshold = correlation_threshold
        self.time_window = timedelta(seconds=time_window)
        self.anomaly_threshold = anomaly_threshold
        
        # Pattern matcher for efficient event correlation
        self.pattern_matcher = PatternMatcher()
        
        # Rule generator
        self.rule_generator = RuleGenerator()
        
        # Event storage
        self.event_store = EventStore()
        
        # Active correlations (threat_id -> CorrelationResult)
        self.active_correlations: Dict[str, CorrelationResult] = {}
        
        # Event tracking by IP (for temporal correlation)
        self.ip_events: Dict[str, List[SecurityEvent]] = defaultdict(list)
        
        # Connected agents (WebSocket connections)
        self.connected_agents: Set = set()
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'correlations_detected': 0,
            'rules_generated': 0,
            'false_positives': 0
        }
        
        logger.info("Correlation engine initialized")
    
    async def process_event(self, event: SecurityEvent) -> Optional[CorrelationResult]:
        """
        Process a single security event
        
        Flow:
        1. Store event in database
        2. Add to IP-based event tracking
        3. Check for temporal correlations
        4. Calculate anomaly score
        5. Generate correlation result if threshold met
        6. Generate and distribute firewall rules if needed
        
        Args:
            event: Security event to process
        
        Returns:
            CorrelationResult if correlation detected, None otherwise
        """
        self.stats['events_processed'] += 1
        
        logger.info(
            f"Processing event: {event.event_type} from {event.source_ip} "
            f"to {event.dest_ip} (severity: {event.severity})"
        )
        
        # Store event
        await self.event_store.store_event(event)
        
        # Track by source IP
        self.ip_events[event.source_ip].append(event)
        
        # Clean old events outside time window
        self._clean_old_events(event.source_ip)
        
        # Check for correlations
        correlation = await self._correlate_events(event)
        
        if correlation:
            self.stats['correlations_detected'] += 1
            logger.warning(
                f"Correlation detected: {correlation.threat_type} "
                f"(confidence: {correlation.confidence_score:.2f})"
            )
            
            # Store correlation
            self.active_correlations[correlation.threat_id] = correlation
            
            # Generate firewall rules if confidence is high enough
            if correlation.confidence_score >= self.anomaly_threshold:
                await self._generate_and_distribute_rules(correlation)
            
            return correlation
        
        return None
    
    def _clean_old_events(self, ip: str):
        """Remove events outside the correlation time window"""
        cutoff_time = datetime.now() - self.time_window
        self.ip_events[ip] = [
            e for e in self.ip_events[ip]
            if e.timestamp >= cutoff_time
        ]
    
    async def _correlate_events(self, new_event: SecurityEvent) -> Optional[CorrelationResult]:
        """
        Correlate new event with recent events
        
        Correlation rules:
        - Multiple events from same source IP
        - Related event types (e.g., port scan -> exploit attempt)
        - Escalating severity
        - Known attack patterns
        
        Args:
            new_event: New event to correlate
        
        Returns:
            CorrelationResult if correlation found
        """
        source_events = self.ip_events[new_event.source_ip]
        
        # Need at least threshold number of events
        if len(source_events) < self.correlation_threshold:
            return None
        
        # Calculate correlation score
        score = self._calculate_correlation_score(source_events)
        
        # Determine threat type and action
        threat_type = self._determine_threat_type(source_events)
        recommended_action = self._determine_action(score, threat_type)
        
        # Generate threat ID
        threat_id = self._generate_threat_id(new_event.source_ip, threat_type)
        
        # Get all involved IPs
        involved_ips = list(set([e.source_ip for e in source_events]))
        
        return CorrelationResult(
            threat_id=threat_id,
            threat_type=threat_type,
            confidence_score=score,
            involved_ips=involved_ips,
            events=source_events[-10:],  # Last 10 events
            recommended_action=recommended_action,
            created_at=datetime.now()
        )
    
    def _calculate_correlation_score(self, events: List[SecurityEvent]) -> float:
        """
        Calculate correlation confidence score
        
        Factors:
        - Number of events (more events = higher confidence)
        - Severity distribution (critical events increase score)
        - Event type diversity (multiple attack types = higher score)
        - Time clustering (rapid succession = higher score)
        
        Returns:
            Score between 0.0 and 1.0
        """
        if not events:
            return 0.0
        
        score = 0.0
        
        # Factor 1: Event count (max 0.3)
        event_count_score = min(len(events) / 10.0, 1.0) * 0.3
        score += event_count_score
        
        # Factor 2: Severity (max 0.4)
        severity_weights = {'low': 0.1, 'medium': 0.3, 'high': 0.6, 'critical': 1.0}
        avg_severity = sum(severity_weights.get(e.severity, 0.1) for e in events) / len(events)
        score += avg_severity * 0.4
        
        # Factor 3: Event type diversity (max 0.2)
        unique_types = len(set(e.event_type for e in events))
        diversity_score = min(unique_types / 5.0, 1.0) * 0.2
        score += diversity_score
        
        # Factor 4: Temporal clustering (max 0.1)
        if len(events) >= 2:
            time_diffs = []
            for i in range(1, len(events)):
                diff = (events[i].timestamp - events[i-1].timestamp).total_seconds()
                time_diffs.append(diff)
            
            avg_diff = sum(time_diffs) / len(time_diffs)
            # Shorter average time between events = higher score
            clustering_score = max(0, 1.0 - (avg_diff / 60.0)) * 0.1
            score += clustering_score
        
        return min(score, 1.0)
    
    def _determine_threat_type(self, events: List[SecurityEvent]) -> str:
        """Determine the overall threat type from events"""
        type_counts = defaultdict(int)
        for event in events:
            type_counts[event.event_type] += 1
        
        # Most common event type
        most_common = max(type_counts.items(), key=lambda x: x[1])[0]
        
        # Map to threat categories
        threat_mapping = {
            'port_scan': 'reconnaissance',
            'brute_force': 'credential_attack',
            'malware': 'malware_infection',
            'exploit': 'exploitation_attempt',
            'data_exfiltration': 'data_breach',
            'ddos': 'denial_of_service',
        }
        
        return threat_mapping.get(most_common, 'unknown_threat')
    
    def _determine_action(self, score: float, threat_type: str) -> str:
        """Determine recommended action based on score and threat type"""
        if score >= 0.9 or threat_type in ['malware_infection', 'data_breach']:
            return 'block'
        elif score >= 0.75:
            return 'quarantine'
        elif score >= 0.5:
            return 'alert'
        else:
            return 'monitor'
    
    def _generate_threat_id(self, ip: str, threat_type: str) -> str:
        """Generate unique threat ID"""
        key = f"{ip}:{threat_type}:{datetime.now().isoformat()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    async def _generate_and_distribute_rules(self, correlation: CorrelationResult):
        """
        Generate firewall rules and distribute to agents
        
        Args:
            correlation: Correlation result to generate rules for
        """
        logger.info(f"Generating rules for threat: {correlation.threat_id}")
        
        # Generate rules
        rules = await self.rule_generator.generate_rules(correlation)
        
        self.stats['rules_generated'] += len(rules)
        
        # Distribute to connected agents
        await self._distribute_rules(rules)
        
        logger.info(f"Distributed {len(rules)} rules to {len(self.connected_agents)} agents")
    
    async def _distribute_rules(self, rules: List[FirewallRule]):
        """Distribute rules to all connected agents via WebSocket"""
        if not self.connected_agents:
            logger.warning("No agents connected to receive rules")
            return
        
        # Convert rules to JSON
        rules_data = [rule.to_dict() for rule in rules]
        message = json.dumps({
            'type': 'new_rules',
            'rules': rules_data,
            'timestamp': datetime.now().isoformat()
        })
        
        # Send to all connected agents
        disconnected = set()
        for agent in self.connected_agents:
            try:
                await agent.send(message)
            except Exception as e:
                logger.error(f"Failed to send rules to agent: {e}")
                disconnected.add(agent)
        
        # Remove disconnected agents
        self.connected_agents -= disconnected
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        return {
            **self.stats,
            'active_correlations': len(self.active_correlations),
            'connected_agents': len(self.connected_agents),
            'tracked_ips': len(self.ip_events)
        }
    
    async def shutdown(self):
        """Gracefully shutdown the engine"""
        logger.info("Shutting down correlation engine...")
        await self.event_store.close()
        logger.info("Correlation engine shutdown complete")


if __name__ == "__main__":
    # Test the correlation engine
    async def main():
        engine = CorrelationEngine()
        
        # Simulate some events
        for i in range(5):
            event = SecurityEvent(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                dest_ip="10.0.0.1",
                source_port=50000 + i,
                dest_port=22,
                protocol="tcp",
                event_type="brute_force",
                severity="high",
                source="zeek",
                metadata={"attempts": i + 1}
            )
            
            result = await engine.process_event(event)
            if result:
                print(f"Correlation detected: {result}")
            
            await asyncio.sleep(1)
        
        print(f"Statistics: {engine.get_statistics()}")
        await engine.shutdown()
    
    asyncio.run(main())
