"""
src/correlation/models/trie.py

Purpose: Trie data structure for efficient pattern matching in events
Context: Used by correlation engine to match event sequences and patterns
         efficiently. Supports multi-attribute matching on IP addresses,
         ports, protocols, and event types.

Architecture:
- Trie-based pattern storage for O(k) lookup (k = pattern length)
- Support for wildcard matching
- Efficient storage for large pattern databases
- Pattern metadata for correlation rules

Use Cases:
- Detect known attack patterns (e.g., port scan -> exploit -> data exfil)
- Match IOC (Indicators of Compromise) patterns
- Identify multi-stage attack sequences
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TrieNode:
    """
    Node in the pattern matching trie
    
    Context: Each node represents a state in pattern matching.
             Leaf nodes contain pattern metadata (rule/action)
    """
    children: Dict[str, 'TrieNode'] = field(default_factory=dict)
    is_end_of_pattern: bool = False
    pattern_metadata: Optional[Dict[str, Any]] = None
    
    def __repr__(self):
        return f"TrieNode(children={len(self.children)}, is_end={self.is_end_of_pattern})"


class PatternMatcher:
    """
    Trie-based pattern matcher for security event sequences
    
    Context: Efficiently matches event sequences against known attack patterns
    """
    
    def __init__(self):
        """Initialize the pattern matcher with empty root"""
        self.root = TrieNode()
        self.pattern_count = 0
        
        logger.info("Pattern matcher initialized")
    
    def add_pattern(self, pattern: List[str], metadata: Optional[Dict] = None):
        """
        Add an attack pattern to the trie
        
        Pattern format: List of event characteristics in sequence
        Example: ['port_scan', 'brute_force', 'successful_login', 'data_exfiltration']
        
        Args:
            pattern: List of pattern elements (event types, IPs, etc.)
            metadata: Additional information about the pattern (severity, name, etc.)
        """
        node = self.root
        
        for element in pattern:
            if element not in node.children:
                node.children[element] = TrieNode()
            node = node.children[element]
        
        node.is_end_of_pattern = True
        node.pattern_metadata = metadata or {}
        self.pattern_count += 1
        
        logger.debug(f"Added pattern: {' -> '.join(pattern)}")
    
    def match_sequence(self, sequence: List[str]) -> Optional[Dict]:
        """
        Match an event sequence against stored patterns
        
        Args:
            sequence: List of events to match (e.g., event types in order)
        
        Returns:
            Pattern metadata if match found, None otherwise
        """
        node = self.root
        
        for element in sequence:
            if element in node.children:
                node = node.children[element]
                
                # Check if we've completed a pattern
                if node.is_end_of_pattern:
                    logger.info(f"Pattern matched: {' -> '.join(sequence)}")
                    return node.pattern_metadata
            else:
                # Check for wildcard match
                if '*' in node.children:
                    node = node.children['*']
                    if node.is_end_of_pattern:
                        return node.pattern_metadata
                else:
                    return None
        
        return None
    
    def partial_match(self, sequence: List[str]) -> bool:
        """
        Check if sequence is a partial match (prefix of stored pattern)
        
        Useful for tracking multi-stage attacks in progress
        
        Args:
            sequence: List of events
        
        Returns:
            True if sequence is a valid prefix of any pattern
        """
        node = self.root
        
        for element in sequence:
            if element in node.children:
                node = node.children[element]
            elif '*' in node.children:
                node = node.children['*']
            else:
                return False
        
        # Valid prefix if we're not stuck at root and haven't failed
        return node != self.root
    
    def get_all_patterns(self) -> List[List[str]]:
        """
        Get all stored patterns
        
        Returns:
            List of all pattern sequences
        """
        patterns = []
        self._collect_patterns(self.root, [], patterns)
        return patterns
    
    def _collect_patterns(self, node: TrieNode, current_path: List[str], patterns: List[List[str]]):
        """Recursively collect all patterns from the trie"""
        if node.is_end_of_pattern:
            patterns.append(current_path.copy())
        
        for element, child in node.children.items():
            self._collect_patterns(child, current_path + [element], patterns)
    
    def remove_pattern(self, pattern: List[str]) -> bool:
        """
        Remove a pattern from the trie
        
        Args:
            pattern: Pattern to remove
        
        Returns:
            True if pattern was found and removed
        """
        # Navigate to the pattern's end node
        nodes = [self.root]
        node = self.root
        
        for element in pattern:
            if element not in node.children:
                return False
            node = node.children[element]
            nodes.append(node)
        
        if not node.is_end_of_pattern:
            return False
        
        # Mark as not end of pattern
        node.is_end_of_pattern = False
        node.pattern_metadata = None
        self.pattern_count -= 1
        
        # Clean up childless nodes (backtrack and remove empty nodes)
        for i in range(len(pattern) - 1, -1, -1):
            parent = nodes[i]
            element = pattern[i]
            child = nodes[i + 1]
            
            # If child has no children and is not end of another pattern, remove it
            if not child.children and not child.is_end_of_pattern:
                del parent.children[element]
            else:
                break
        
        logger.debug(f"Removed pattern: {' -> '.join(pattern)}")
        return True
    
    def clear(self):
        """Clear all patterns from the trie"""
        self.root = TrieNode()
        self.pattern_count = 0
        logger.info("Pattern matcher cleared")


# Predefined attack patterns
COMMON_ATTACK_PATTERNS = {
    'reconnaissance_to_exploit': {
        'pattern': ['port_scan', 'service_detection', 'exploit_attempt'],
        'metadata': {
            'name': 'Reconnaissance to Exploitation',
            'severity': 'high',
            'description': 'Attacker scans, identifies service, then exploits'
        }
    },
    'brute_force_to_access': {
        'pattern': ['brute_force', 'brute_force', 'successful_login'],
        'metadata': {
            'name': 'Brute Force Attack',
            'severity': 'critical',
            'description': 'Multiple brute force attempts followed by successful login'
        }
    },
    'lateral_movement': {
        'pattern': ['successful_login', 'internal_scan', 'privilege_escalation'],
        'metadata': {
            'name': 'Lateral Movement',
            'severity': 'critical',
            'description': 'Attacker moves laterally after initial compromise'
        }
    },
    'data_exfiltration': {
        'pattern': ['database_access', 'large_upload', 'external_connection'],
        'metadata': {
            'name': 'Data Exfiltration',
            'severity': 'critical',
            'description': 'Potential data theft pattern'
        }
    },
    'ransomware': {
        'pattern': ['malware', 'file_encryption', 'ransom_note'],
        'metadata': {
            'name': 'Ransomware Attack',
            'severity': 'critical',
            'description': 'Ransomware infection pattern'
        }
    }
}


def load_default_patterns(matcher: PatternMatcher):
    """
    Load common attack patterns into matcher
    
    Args:
        matcher: PatternMatcher instance to load patterns into
    """
    for pattern_name, pattern_data in COMMON_ATTACK_PATTERNS.items():
        matcher.add_pattern(
            pattern_data['pattern'],
            pattern_data['metadata']
        )
    
    logger.info(f"Loaded {len(COMMON_ATTACK_PATTERNS)} default attack patterns")


if __name__ == "__main__":
    # Test the pattern matcher
    matcher = PatternMatcher()
    
    # Load default patterns
    load_default_patterns(matcher)
    
    # Test matching
    test_sequences = [
        ['port_scan', 'service_detection', 'exploit_attempt'],
        ['brute_force', 'brute_force', 'successful_login'],
        ['normal_activity', 'nothing_suspicious'],
    ]
    
    for seq in test_sequences:
        result = matcher.match_sequence(seq)
        if result:
            print(f"Matched: {seq} -> {result['name']}")
        else:
            print(f"No match: {seq}")
    
    # Test partial matching
    partial = ['port_scan', 'service_detection']
    if matcher.partial_match(partial):
        print(f"Partial match (attack in progress): {partial}")
