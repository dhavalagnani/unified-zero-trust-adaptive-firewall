"""
src/correlation/rules_generator.py

Purpose: Generate dynamic firewall rules based on correlation results
Context: Translates correlation results into actionable nftables rules that
         can be enforced by agents. Supports different action types (block,
         quarantine, rate-limit) and generates rules optimized for nftables.

Architecture:
- Rule generation based on threat type and confidence
- Template-based rule creation for consistency
- Support for IPv4/IPv6, TCP/UDP/ICMP protocols
- Rule expiration and automatic cleanup
- Integration with agent enforcement mechanisms

Output Format:
- nftables-compatible rule syntax
- Metadata for rule management (expiration, priority)
- Action specifications (drop, reject, quarantine)
"""

import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)


@dataclass
class FirewallRule:
    """
    Firewall rule generated from correlation analysis
    
    Context: Represents a dynamic rule to be enforced by agents
    """
    rule_id: str
    action: str  # 'block', 'drop', 'reject', 'quarantine', 'rate_limit'
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None  # 'tcp', 'udp', 'icmp', 'all'
    priority: int = 100
    expires_at: Optional[datetime] = None
    created_at: datetime = None
    metadata: Dict = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for transmission"""
        data = asdict(self)
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()
        return data
    
    def to_nftables(self) -> str:
        """
        Generate nftables rule syntax
        
        Returns:
            nftables rule command string
        """
        # Build match criteria
        criteria = []
        
        if self.source_ip:
            criteria.append(f"ip saddr {self.source_ip}")
        
        if self.dest_ip:
            criteria.append(f"ip daddr {self.dest_ip}")
        
        if self.protocol and self.protocol != 'all':
            criteria.append(self.protocol)
            
            if self.source_port:
                criteria.append(f"sport {self.source_port}")
            
            if self.dest_port:
                criteria.append(f"dport {self.dest_port}")
        
        # Build action
        action_map = {
            'block': 'drop',
            'drop': 'drop',
            'reject': 'reject',
            'quarantine': 'drop',  # Quarantine is implemented via VLAN at switch level
            'rate_limit': 'limit rate 10/minute'
        }
        
        action = action_map.get(self.action, 'drop')
        
        # Combine into nftables rule
        rule = f"add rule inet filter uztaf_quarantine {' '.join(criteria)} {action}"
        
        return rule
    
    def is_expired(self) -> bool:
        """Check if rule has expired"""
        if self.expires_at is None:
            return False
        return datetime.now() >= self.expires_at


class RuleGenerator:
    """
    Generates firewall rules from correlation results
    
    Context: Translates high-level threat correlations into specific
             firewall rules that can be enforced by agents
    """
    
    def __init__(self, default_rule_ttl: int = 3600):
        """
        Initialize rule generator
        
        Args:
            default_rule_ttl: Default time-to-live for rules in seconds
        """
        self.default_rule_ttl = default_rule_ttl
        self.generated_rules: Dict[str, FirewallRule] = {}
        
        logger.info("Rule generator initialized")
    
    async def generate_rules(self, correlation) -> List[FirewallRule]:
        """
        Generate firewall rules from correlation result
        
        Strategy:
        1. Extract threat details from correlation
        2. Determine appropriate action based on threat type
        3. Generate rules for all involved IPs
        4. Set appropriate TTL based on threat severity
        5. Add metadata for tracking and auditing
        
        Args:
            correlation: CorrelationResult object
        
        Returns:
            List of FirewallRule objects
        """
        rules = []
        
        logger.info(
            f"Generating rules for correlation: {correlation.threat_id} "
            f"(type: {correlation.threat_type}, action: {correlation.recommended_action})"
        )
        
        # Determine rule TTL based on threat type
        ttl = self._get_rule_ttl(correlation.threat_type, correlation.confidence_score)
        expires_at = datetime.now() + timedelta(seconds=ttl)
        
        # Generate rules for each involved IP
        for ip in correlation.involved_ips:
            rule = self._create_rule_for_ip(
                ip=ip,
                action=correlation.recommended_action,
                correlation=correlation,
                expires_at=expires_at
            )
            
            rules.append(rule)
            self.generated_rules[rule.rule_id] = rule
        
        # For certain threat types, also block specific ports/protocols
        if correlation.threat_type in ['port_scan', 'reconnaissance']:
            rules.extend(self._create_port_blocking_rules(correlation, expires_at))
        
        logger.info(f"Generated {len(rules)} rules")
        
        return rules
    
    def _create_rule_for_ip(
        self,
        ip: str,
        action: str,
        correlation,
        expires_at: datetime
    ) -> FirewallRule:
        """
        Create a firewall rule for a specific IP address
        
        Args:
            ip: IP address to create rule for
            action: Action to take (block, quarantine, etc.)
            correlation: Source correlation result
            expires_at: Rule expiration time
        
        Returns:
            FirewallRule object
        """
        rule_id = str(uuid.uuid4())
        
        # Determine priority based on action
        priority_map = {
            'block': 10,
            'quarantine': 20,
            'rate_limit': 30,
            'alert': 90,
            'monitor': 100
        }
        priority = priority_map.get(action, 50)
        
        rule = FirewallRule(
            rule_id=rule_id,
            action=action,
            source_ip=ip,
            dest_ip=None,  # Block traffic from this IP to anywhere
            protocol='all',
            priority=priority,
            expires_at=expires_at,
            metadata={
                'threat_id': correlation.threat_id,
                'threat_type': correlation.threat_type,
                'confidence': correlation.confidence_score,
                'reason': f"Correlated threat: {correlation.threat_type}"
            }
        )
        
        return rule
    
    def _create_port_blocking_rules(
        self,
        correlation,
        expires_at: datetime
    ) -> List[FirewallRule]:
        """
        Create additional rules to block specific ports
        
        Context: For reconnaissance/scanning attacks, block commonly
                 scanned ports temporarily
        """
        rules = []
        
        # Common target ports for scanners
        target_ports = [22, 23, 445, 3389, 5900]
        
        for ip in correlation.involved_ips:
            for port in target_ports:
                rule = FirewallRule(
                    rule_id=str(uuid.uuid4()),
                    action='drop',
                    source_ip=ip,
                    dest_port=port,
                    protocol='tcp',
                    priority=15,
                    expires_at=expires_at,
                    metadata={
                        'threat_id': correlation.threat_id,
                        'reason': 'Port blocking for scanner'
                    }
                )
                rules.append(rule)
        
        return rules
    
    def _get_rule_ttl(self, threat_type: str, confidence: float) -> int:
        """
        Determine rule time-to-live based on threat characteristics
        
        Higher confidence and more severe threats get longer TTLs
        
        Args:
            threat_type: Type of threat
            confidence: Confidence score (0.0 to 1.0)
        
        Returns:
            TTL in seconds
        """
        # Base TTL from threat type
        threat_ttls = {
            'malware_infection': 86400,  # 24 hours
            'data_breach': 86400,
            'exploitation_attempt': 7200,  # 2 hours
            'credential_attack': 3600,  # 1 hour
            'reconnaissance': 1800,  # 30 minutes
            'denial_of_service': 1800,
            'unknown_threat': 900  # 15 minutes
        }
        
        base_ttl = threat_ttls.get(threat_type, self.default_rule_ttl)
        
        # Adjust by confidence (higher confidence = longer TTL)
        adjusted_ttl = int(base_ttl * (0.5 + confidence * 0.5))
        
        return adjusted_ttl
    
    def cleanup_expired_rules(self) -> int:
        """
        Remove expired rules from tracking
        
        Returns:
            Number of rules removed
        """
        expired = [
            rule_id for rule_id, rule in self.generated_rules.items()
            if rule.is_expired()
        ]
        
        for rule_id in expired:
            del self.generated_rules[rule_id]
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired rules")
        
        return len(expired)
    
    def get_active_rules(self) -> List[FirewallRule]:
        """Get all non-expired rules"""
        return [
            rule for rule in self.generated_rules.values()
            if not rule.is_expired()
        ]
    
    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Get a specific rule by ID"""
        return self.generated_rules.get(rule_id)
    
    def revoke_rule(self, rule_id: str) -> bool:
        """
        Manually revoke a rule (e.g., for false positive)
        
        Returns:
            True if rule was found and revoked
        """
        if rule_id in self.generated_rules:
            del self.generated_rules[rule_id]
            logger.info(f"Revoked rule: {rule_id}")
            return True
        return False


# Predefined rule templates for common scenarios
RULE_TEMPLATES = {
    'block_ip': {
        'action': 'block',
        'protocol': 'all',
        'priority': 10
    },
    'rate_limit_ip': {
        'action': 'rate_limit',
        'protocol': 'all',
        'priority': 30
    },
    'block_ssh': {
        'action': 'block',
        'dest_port': 22,
        'protocol': 'tcp',
        'priority': 15
    },
    'block_rdp': {
        'action': 'block',
        'dest_port': 3389,
        'protocol': 'tcp',
        'priority': 15
    }
}


if __name__ == "__main__":
    # Test rule generation
    generator = RuleGenerator()
    
    # Create a test rule
    rule = FirewallRule(
        rule_id="test-001",
        action="block",
        source_ip="192.168.1.100",
        protocol="tcp",
        dest_port=22,
        priority=10
    )
    
    print("Generated nftables rule:")
    print(rule.to_nftables())
    print("\nRule dict:")
    print(rule.to_dict())
