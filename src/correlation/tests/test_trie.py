"""
src/correlation/tests/test_trie.py

Purpose: Unit tests for trie-based pattern matching
Context: Tests pattern insertion, matching, and removal
"""

import pytest
from models.trie import PatternMatcher, TrieNode, load_default_patterns


class TestTrieNode:
    """Test TrieNode functionality"""
    
    def test_node_creation(self):
        """Test creating a trie node"""
        node = TrieNode()
        assert node.children == {}
        assert node.is_end_of_pattern == False
        assert node.pattern_metadata is None


class TestPatternMatcher:
    """Test PatternMatcher functionality"""
    
    def test_matcher_initialization(self):
        """Test pattern matcher initialization"""
        matcher = PatternMatcher()
        assert matcher.root is not None
        assert matcher.pattern_count == 0
    
    def test_add_single_pattern(self):
        """Test adding a single pattern"""
        matcher = PatternMatcher()
        pattern = ['port_scan', 'exploit']
        metadata = {'name': 'Test Pattern', 'severity': 'high'}
        
        matcher.add_pattern(pattern, metadata)
        
        assert matcher.pattern_count == 1
    
    def test_match_exact_sequence(self):
        """Test matching an exact sequence"""
        matcher = PatternMatcher()
        pattern = ['port_scan', 'exploit', 'data_exfil']
        metadata = {'name': 'Full Attack', 'severity': 'critical'}
        
        matcher.add_pattern(pattern, metadata)
        
        result = matcher.match_sequence(pattern)
        assert result is not None
        assert result['name'] == 'Full Attack'
    
    def test_no_match_for_partial(self):
        """Test that partial sequence doesn't match"""
        matcher = PatternMatcher()
        pattern = ['port_scan', 'exploit', 'data_exfil']
        matcher.add_pattern(pattern, {})
        
        partial = ['port_scan', 'exploit']
        result = matcher.match_sequence(partial)
        assert result is None
    
    def test_partial_match_detection(self):
        """Test partial match detection"""
        matcher = PatternMatcher()
        pattern = ['port_scan', 'exploit', 'data_exfil']
        matcher.add_pattern(pattern, {})
        
        partial = ['port_scan', 'exploit']
        assert matcher.partial_match(partial) == True
    
    def test_remove_pattern(self):
        """Test removing a pattern"""
        matcher = PatternMatcher()
        pattern = ['test', 'pattern']
        matcher.add_pattern(pattern, {})
        
        assert matcher.pattern_count == 1
        result = matcher.remove_pattern(pattern)
        assert result == True
        assert matcher.pattern_count == 0
    
    def test_default_patterns(self):
        """Test loading default patterns"""
        matcher = PatternMatcher()
        load_default_patterns(matcher)
        
        assert matcher.pattern_count > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
