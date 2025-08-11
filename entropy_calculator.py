#!/usr/bin/env python3
"""
Information-Theoretic Privacy Entropy Calculator

This module implements rigorous entropy calculations for privacy budget tracking
in the LLM-based privacy filter system. It provides multiple entropy measurement
approaches based on information theory and differential privacy research.

Key Concepts:
- Shannon entropy: -∑ p(x) * log₂(p(x)) 
- Response entropy: Information content of filtered responses
- Query-response mutual information: Shared information between query and response
- Semantic entropy: Content-aware entropy using embeddings
- Cumulative privacy loss: Tracking total information revealed over time

Based on:
- Differential Privacy (Dwork et al.)
- Information-theoretic privacy (Smith, 2009)
- Semantic differential privacy (recent LLM privacy research)
"""

import asyncio
import logging
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from datetime import datetime, timedelta
import json
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class EntropyMeasurement:
    """A single entropy measurement with metadata."""
    entropy_value: float
    measurement_type: str  # "shannon", "response", "mutual_info", "semantic"
    confidence: float      # How confident we are in this measurement (0-1)
    components: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PrivacyBudgetState:
    """Current state of privacy budget for a user/session."""
    user_email: str
    session_id: Optional[str]
    document_name: str
    
    # Cumulative entropy consumed
    total_entropy_consumed: float = 0.0
    session_entropy_consumed: float = 0.0
    
    # Query tracking
    total_queries: int = 0
    session_queries: int = 0
    
    # Time tracking  
    first_query_time: Optional[datetime] = None
    last_query_time: Optional[datetime] = None
    session_start_time: Optional[datetime] = None
    
    # Similarity tracking for coordinated queries
    cumulative_similarity: float = 0.0
    query_history: List[str] = field(default_factory=list)
    response_history: List[str] = field(default_factory=list)

class EntropyCalculator:
    """
    Core entropy calculation engine for information-theoretic privacy tracking.
    
    This class implements multiple entropy measurement approaches:
    1. Shannon entropy of text content
    2. Response entropy (information revealed in responses)
    3. Query-response mutual information
    4. Semantic entropy using embeddings (when available)
    """
    
    def __init__(self):
        """Initialize entropy calculator."""
        self.word_frequencies: Optional[Dict[str, float]] = None
        self.concept_frequencies: Optional[Dict[str, float]] = None
        
        # Cache for expensive calculations
        self._entropy_cache: Dict[str, float] = {}
        self._similarity_cache: Dict[Tuple[str, str], float] = {}
        
        # Stopwords for better entropy calculation
        self.stopwords = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
            'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
            'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
            'should', 'may', 'might', 'can', 'this', 'that', 'these', 'those'
        }
    
    def calculate_shannon_entropy(self, text: str, unit: str = "chars") -> EntropyMeasurement:
        """
        Calculate Shannon entropy of text content.
        
        H(X) = -∑ p(x) * log₂(p(x))
        
        Args:
            text: Input text to calculate entropy for
            unit: "chars", "words", or "ngrams" for calculation unit
            
        Returns:
            EntropyMeasurement with Shannon entropy value
        """
        if not text or not text.strip():
            return EntropyMeasurement(
                entropy_value=0.0,
                measurement_type="shannon",
                confidence=1.0,
                metadata={"unit": unit, "length": 0}
            )
        
        # Cache key
        cache_key = f"shannon_{unit}_{hashlib.md5(text.encode()).hexdigest()[:8]}"
        if cache_key in self._entropy_cache:
            return EntropyMeasurement(
                entropy_value=self._entropy_cache[cache_key],
                measurement_type="shannon",
                confidence=1.0,
                metadata={"unit": unit, "cached": True}
            )
        
        # Get frequency distribution based on unit
        if unit == "chars":
            elements = list(text.lower())
        elif unit == "words":
            elements = re.findall(r'\b\w+\b', text.lower())
            # Filter out stopwords for better entropy measurement
            elements = [w for w in elements if w not in self.stopwords]
        elif unit == "ngrams":
            # Use character 3-grams for more nuanced entropy
            elements = [text[i:i+3] for i in range(len(text)-2)]
        else:
            raise ValueError(f"Unknown unit: {unit}")
        
        if not elements:
            entropy = 0.0
        else:
            # Calculate frequency distribution
            counter = Counter(elements)
            total = len(elements)
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in counter.values():
                probability = count / total
                if probability > 0:
                    entropy -= probability * math.log2(probability)
        
        # Cache result
        self._entropy_cache[cache_key] = entropy
        
        return EntropyMeasurement(
            entropy_value=entropy,
            measurement_type="shannon",
            confidence=1.0,
            components={
                "unique_elements": len(set(elements)),
                "total_elements": len(elements),
                "max_possible_entropy": math.log2(len(set(elements))) if elements else 0
            },
            metadata={"unit": unit, "length": len(text)}
        )
    
    def calculate_response_entropy(
        self, 
        query: str, 
        response: str, 
        protected_content: List[str]
    ) -> EntropyMeasurement:
        """
        Calculate entropy of information revealed in the response.
        
        This measures how much information about protected content
        is revealed in the response, accounting for:
        - Direct mention of protected facts
        - Indirect revelation through implications
        - Abstraction level of the response
        
        Args:
            query: Original query
            response: Filtered response 
            protected_content: List of protected facts/concepts
            
        Returns:
            EntropyMeasurement with response entropy
        """
        if not response or not response.strip():
            return EntropyMeasurement(
                entropy_value=0.0,
                measurement_type="response",
                confidence=1.0,
                metadata={"response_length": 0}
            )
        
        # Base entropy from response text
        base_entropy = self.calculate_shannon_entropy(response, "words")
        
        # Penalty for directly mentioning protected content
        protection_penalty = 0.0
        protected_mentions = 0
        
        response_lower = response.lower()
        for protected_item in protected_content:
            if protected_item.lower() in response_lower:
                # Higher penalty for exact matches
                protection_penalty += 2.0
                protected_mentions += 1
            else:
                # Check for partial matches (word overlap)
                protected_words = set(protected_item.lower().split())
                response_words = set(response_lower.split())
                overlap = protected_words.intersection(response_words)
                if overlap:
                    # Penalty proportional to word overlap
                    overlap_ratio = len(overlap) / len(protected_words)
                    protection_penalty += overlap_ratio * 1.5
                    protected_mentions += overlap_ratio
        
        # Bonus for abstract/deflected responses (lower entropy penalty)
        abstraction_keywords = {
            'general', 'abstract', 'concept', 'idea', 'principle', 'theme',
            'cannot provide', 'cannot discuss', 'not available', 'protected',
            'unable to', 'not able to', 'cannot share', 'cannot reveal'
        }
        
        abstraction_bonus = 0.0
        for keyword in abstraction_keywords:
            if keyword in response_lower:
                abstraction_bonus -= 0.5  # Larger reduction for abstract responses
        
        # Additional bonus for very short deflection responses
        if len(response.split()) < 15 and any(kw in response_lower for kw in ['cannot', 'not', 'unable']):
            abstraction_bonus -= 0.8
        
        # Calculate final response entropy
        response_entropy = base_entropy.entropy_value + protection_penalty + abstraction_bonus
        response_entropy = max(0.0, response_entropy)  # Ensure non-negative
        
        # Confidence based on response characteristics
        confidence = 1.0
        if len(response.split()) < 10:  # Very short responses harder to measure
            confidence -= 0.2
        if protected_mentions > 0:  # Direct mentions easier to measure
            confidence += 0.1
            
        confidence = max(0.1, min(1.0, confidence))
        
        return EntropyMeasurement(
            entropy_value=response_entropy,
            measurement_type="response",
            confidence=confidence,
            components={
                "base_entropy": base_entropy.entropy_value,
                "protection_penalty": protection_penalty,
                "abstraction_bonus": abstraction_bonus,
                "protected_mentions": protected_mentions
            },
            metadata={
                "response_length": len(response),
                "word_count": len(response.split()),
                "protected_items_checked": len(protected_content)
            }
        )
    
    def calculate_mutual_information(
        self, 
        query: str, 
        response: str
    ) -> EntropyMeasurement:
        """
        Calculate mutual information between query and response.
        
        I(Q;R) = H(Q) + H(R) - H(Q,R)
        
        This measures how much information the response shares with the query,
        indicating potential information leakage.
        
        Args:
            query: Original query
            response: Filtered response
            
        Returns:
            EntropyMeasurement with mutual information
        """
        if not query or not response:
            return EntropyMeasurement(
                entropy_value=0.0,
                measurement_type="mutual_info",
                confidence=0.0
            )
        
        # Calculate individual entropies
        h_query = self.calculate_shannon_entropy(query, "words")
        h_response = self.calculate_shannon_entropy(response, "words")
        
        # Calculate joint entropy H(Q,R)
        combined_text = f"{query} {response}"
        h_joint = self.calculate_shannon_entropy(combined_text, "words")
        
        # Mutual information: I(Q;R) = H(Q) + H(R) - H(Q,R)
        mutual_info = h_query.entropy_value + h_response.entropy_value - h_joint.entropy_value
        mutual_info = max(0.0, mutual_info)  # Ensure non-negative
        
        # Confidence based on text length and overlap
        query_words = set(query.lower().split())
        response_words = set(response.lower().split())
        word_overlap = len(query_words.intersection(response_words))
        
        confidence = 0.8
        if len(query.split()) < 5 or len(response.split()) < 5:
            confidence -= 0.3  # Less confident for short texts
        if word_overlap > 0:
            confidence += 0.2  # More confident when there's clear overlap
        
        confidence = max(0.1, min(1.0, confidence))
        
        return EntropyMeasurement(
            entropy_value=mutual_info,
            measurement_type="mutual_info", 
            confidence=confidence,
            components={
                "h_query": h_query.entropy_value,
                "h_response": h_response.entropy_value,
                "h_joint": h_joint.entropy_value,
                "word_overlap": word_overlap
            },
            metadata={
                "query_length": len(query),
                "response_length": len(response)
            }
        )
    
    def calculate_cumulative_similarity(
        self, 
        new_query: str,
        new_response: str,
        query_history: List[str],
        response_history: List[str],
        decay_factor: float = 0.95
    ) -> float:
        """
        Calculate cumulative similarity score across query/response history.
        
        This helps detect coordinated extraction attempts by multiple agents
        or repeated similar queries by the same agent.
        
        Args:
            new_query: Current query
            new_response: Current response
            query_history: Previous queries
            response_history: Previous responses
            decay_factor: How much to discount older queries (0-1)
            
        Returns:
            Cumulative similarity score (higher = more similar to history)
        """
        if not query_history:
            return 0.0
        
        cumulative_similarity = 0.0
        
        for i, (old_query, old_response) in enumerate(zip(query_history, response_history)):
            # Calculate query similarity (simple word overlap for now)
            query_sim = self._calculate_text_similarity(new_query, old_query)
            response_sim = self._calculate_text_similarity(new_response, old_response)
            
            # Combined similarity
            combined_sim = (query_sim + response_sim) / 2.0
            
            # Apply decay factor (more recent queries have higher weight)
            age_weight = decay_factor ** (len(query_history) - i - 1)
            weighted_similarity = combined_sim * age_weight
            
            cumulative_similarity += weighted_similarity
        
        return cumulative_similarity
    
    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two texts using word overlap.
        
        This is a simple baseline - could be enhanced with embeddings later.
        """
        if not text1 or not text2:
            return 0.0
        
        # Check cache
        cache_key = (
            hashlib.md5(text1.encode()).hexdigest()[:8],
            hashlib.md5(text2.encode()).hexdigest()[:8]
        )
        if cache_key in self._similarity_cache:
            return self._similarity_cache[cache_key]
        
        # Simple word-based similarity (Jaccard coefficient)
        words1 = set(re.findall(r'\b\w+\b', text1.lower()))
        words2 = set(re.findall(r'\b\w+\b', text2.lower()))
        
        # Filter stopwords
        words1 = words1 - self.stopwords
        words2 = words2 - self.stopwords
        
        if not words1 and not words2:
            similarity = 1.0
        elif not words1 or not words2:
            similarity = 0.0
        else:
            intersection = words1.intersection(words2)
            union = words1.union(words2)
            similarity = len(intersection) / len(union)
        
        # Cache result
        self._similarity_cache[cache_key] = similarity
        
        return similarity
    
    def calculate_composite_entropy(
        self,
        query: str,
        response: str,
        protected_content: List[str],
        weights: Optional[Dict[str, float]] = None
    ) -> EntropyMeasurement:
        """
        Calculate composite entropy combining multiple measurements.
        
        This provides a single entropy value that considers:
        - Response information content
        - Query-response mutual information  
        - Protection level violations
        
        Args:
            query: Original query
            response: Filtered response
            protected_content: List of protected facts/concepts
            weights: Custom weights for different entropy components
            
        Returns:
            EntropyMeasurement with composite entropy
        """
        # Default weights
        if weights is None:
            weights = {
                "response": 0.6,      # Primary component
                "mutual_info": 0.3,   # Secondary component
                "protection": 0.1     # Penalty component
            }
        
        # Calculate individual entropy measurements
        response_entropy = self.calculate_response_entropy(query, response, protected_content)
        mutual_info = self.calculate_mutual_information(query, response)
        
        # Additional protection penalty for high-risk responses
        protection_penalty = 0.0
        if protected_content:
            response_lower = response.lower()
            for item in protected_content:
                if item.lower() in response_lower:
                    protection_penalty += 0.5
        
        # Weighted combination
        composite_entropy = (
            weights["response"] * response_entropy.entropy_value +
            weights["mutual_info"] * mutual_info.entropy_value +
            weights["protection"] * protection_penalty
        )
        
        # Average confidence
        avg_confidence = (response_entropy.confidence + mutual_info.confidence) / 2.0
        
        return EntropyMeasurement(
            entropy_value=composite_entropy,
            measurement_type="composite",
            confidence=avg_confidence,
            components={
                "response_entropy": response_entropy.entropy_value,
                "mutual_information": mutual_info.entropy_value,
                "protection_penalty": protection_penalty,
                "weights": weights
            },
            metadata={
                "query_length": len(query),
                "response_length": len(response),
                "protected_items": len(protected_content)
            }
        )

    async def initialize(self):
        """Initialize entropy calculator with any required resources."""
        logger.info("Entropy calculator initialized")