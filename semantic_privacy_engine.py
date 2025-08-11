#!/usr/bin/env python3
"""
Semantic Privacy Engine

This module implements semantic embedding-based privacy tracking for LLMs.
Instead of statistical information theory, it measures conceptual information
leakage using semantic embeddings and contextual similarity.

Core Innovation: Measure privacy in terms of "concept revelation" rather than
text statistics, aligned with how LLMs actually process and leak information.

Key Concepts:
- Semantic Distance: How conceptually similar query-response pairs are
- Concept Revelation: How much protected conceptual information is revealed
- Contextual Privacy Budgets: Budgets based on semantic content, not text length
- Embedding-based Similarity: Using vector embeddings for true semantic comparison
"""

import asyncio
import logging
import numpy as np
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from datetime import datetime
import json
import hashlib
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

@dataclass
class SemanticConcept:
    """Represents a protected semantic concept with embedding."""
    name: str
    description: str
    protection_level: str  # "low", "medium", "high", "absolute"
    embedding: Optional[np.ndarray] = None
    related_terms: List[str] = field(default_factory=list)
    context_keywords: List[str] = field(default_factory=list)

@dataclass
class ConceptRevelation:
    """Measures how much of a concept is revealed in a response."""
    concept: SemanticConcept
    revelation_score: float  # 0.0-1.0, how much of the concept is revealed
    confidence: float       # 0.0-1.0, confidence in the measurement
    revelation_type: str    # "direct", "indirect", "contextual", "implicational"
    evidence: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SemanticPrivacyMeasurement:
    """Complete semantic privacy measurement for a query-response pair."""
    query_embedding: Optional[np.ndarray]
    response_embedding: Optional[np.ndarray]
    semantic_distance: float  # How semantically similar query and response are
    concept_revelations: List[ConceptRevelation]
    total_privacy_cost: float  # Combined semantic privacy cost
    risk_level: str  # "low", "medium", "high", "critical"
    metadata: Dict[str, Any] = field(default_factory=dict)

class EmbeddingProvider(ABC):
    """Abstract interface for embedding providers (sentence-transformers, OpenAI, etc)."""
    
    @abstractmethod
    async def get_embedding(self, text: str) -> np.ndarray:
        """Get embedding vector for text."""
        pass
    
    @abstractmethod
    async def get_similarity(self, text1: str, text2: str) -> float:
        """Get semantic similarity between two texts."""
        pass

class LocalEmbeddingProvider(EmbeddingProvider):
    """Local embedding provider using sentence-transformers (when available)."""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = None
        self._embedding_cache: Dict[str, np.ndarray] = {}
        
    async def initialize(self):
        """Initialize the embedding model."""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info(f"Loaded sentence transformer model: {self.model_name}")
        except ImportError:
            logger.warning("sentence-transformers not available, using fallback embeddings")
            self.model = None
    
    async def get_embedding(self, text: str) -> np.ndarray:
        """Get embedding vector for text."""
        # Cache check
        text_hash = hashlib.md5(text.encode()).hexdigest()
        if text_hash in self._embedding_cache:
            return self._embedding_cache[text_hash]
        
        if self.model is None:
            # Fallback: simple TF-IDF style embedding
            embedding = self._create_fallback_embedding(text)
        else:
            # Use sentence transformer
            embedding = self.model.encode(text, convert_to_numpy=True)
        
        # Cache result
        self._embedding_cache[text_hash] = embedding
        return embedding
    
    async def get_similarity(self, text1: str, text2: str) -> float:
        """Get semantic similarity between two texts."""
        emb1 = await self.get_embedding(text1)
        emb2 = await self.get_embedding(text2)
        
        # Cosine similarity
        dot_product = np.dot(emb1, emb2)
        norm1 = np.linalg.norm(emb1)
        norm2 = np.linalg.norm(emb2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        similarity = dot_product / (norm1 * norm2)
        return float(similarity)
    
    def _create_fallback_embedding(self, text: str, dim: int = 384) -> np.ndarray:
        """Create simple fallback embedding when sentence-transformers unavailable."""
        # Simple hash-based embedding for consistent results
        words = text.lower().split()
        
        # Create embedding based on word hashes
        embedding = np.zeros(dim)
        for i, word in enumerate(words[:50]):  # Limit to 50 words
            word_hash = hash(word) % dim
            embedding[word_hash] += 1.0 / (i + 1)  # Position weighting
        
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        
        return embedding

class SemanticPrivacyEngine:
    """
    Core semantic privacy engine that measures conceptual information leakage.
    
    This engine measures privacy in terms of semantic concepts rather than
    statistical text patterns, providing LLM-native privacy protection.
    """
    
    def __init__(self, embedding_provider: Optional[EmbeddingProvider] = None):
        """Initialize semantic privacy engine."""
        self.embedding_provider = embedding_provider or LocalEmbeddingProvider()
        
        # Protected concepts registry
        self.protected_concepts: Dict[str, SemanticConcept] = {}
        
        # Semantic privacy thresholds
        self.similarity_thresholds = {
            "low": 0.3,
            "medium": 0.5, 
            "high": 0.7,
            "absolute": 0.8
        }
        
        # Privacy cost weights
        self.privacy_weights = {
            "direct_revelation": 1.0,
            "indirect_revelation": 0.7,
            "contextual_revelation": 0.5,
            "implicational_revelation": 0.3
        }
    
    async def initialize(self):
        """Initialize the semantic privacy engine."""
        await self.embedding_provider.initialize()
        logger.info("Semantic privacy engine initialized")
    
    def register_protected_concept(
        self, 
        name: str,
        description: str,
        protection_level: str,
        related_terms: Optional[List[str]] = None,
        context_keywords: Optional[List[str]] = None
    ) -> SemanticConcept:
        """Register a new protected concept."""
        concept = SemanticConcept(
            name=name,
            description=description,
            protection_level=protection_level,
            related_terms=related_terms or [],
            context_keywords=context_keywords or []
        )
        
        self.protected_concepts[name] = concept
        return concept
    
    async def analyze_semantic_privacy(
        self,
        query: str,
        response: str,
        protected_concepts: Optional[List[str]] = None
    ) -> SemanticPrivacyMeasurement:
        """
        Analyze semantic privacy of a query-response pair.
        
        Args:
            query: User's query
            response: System's response
            protected_concepts: List of concept names to check (None = all)
            
        Returns:
            Complete semantic privacy measurement
        """
        # Get embeddings
        query_embedding = await self.embedding_provider.get_embedding(query)
        response_embedding = await self.embedding_provider.get_embedding(response)
        
        # Calculate semantic distance between query and response
        semantic_distance = await self.embedding_provider.get_similarity(query, response)
        
        # Analyze concept revelations
        concepts_to_check = protected_concepts or list(self.protected_concepts.keys())
        concept_revelations = []
        
        for concept_name in concepts_to_check:
            if concept_name in self.protected_concepts:
                concept = self.protected_concepts[concept_name]
                revelation = await self._analyze_concept_revelation(
                    query, response, concept, query_embedding, response_embedding
                )
                if revelation.revelation_score > 0.1:  # Only include significant revelations
                    concept_revelations.append(revelation)
        
        # Calculate total privacy cost
        total_cost = self._calculate_total_privacy_cost(
            semantic_distance, concept_revelations
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(total_cost, concept_revelations)
        
        return SemanticPrivacyMeasurement(
            query_embedding=query_embedding,
            response_embedding=response_embedding,
            semantic_distance=semantic_distance,
            concept_revelations=concept_revelations,
            total_privacy_cost=total_cost,
            risk_level=risk_level,
            metadata={
                "num_concepts_checked": len(concepts_to_check),
                "num_revelations": len(concept_revelations),
                "timestamp": datetime.now().isoformat()
            }
        )
    
    async def _analyze_concept_revelation(
        self,
        query: str,
        response: str,
        concept: SemanticConcept,
        query_embedding: np.ndarray,
        response_embedding: np.ndarray
    ) -> ConceptRevelation:
        """Analyze how much of a protected concept is revealed."""
        
        # Ensure concept has embedding
        if concept.embedding is None:
            concept.embedding = await self.embedding_provider.get_embedding(
                f"{concept.name}: {concept.description}"
            )
        
        # Calculate concept-response similarity
        concept_response_similarity = np.dot(concept.embedding, response_embedding) / (
            np.linalg.norm(concept.embedding) * np.linalg.norm(response_embedding)
        )
        
        # Calculate concept-query similarity
        concept_query_similarity = np.dot(concept.embedding, query_embedding) / (
            np.linalg.norm(concept.embedding) * np.linalg.norm(query_embedding)
        )
        
        # Determine revelation type and score
        revelation_score = 0.0
        revelation_type = "none"
        confidence = 0.8
        evidence = {}
        
        # Direct revelation: response directly discusses the concept
        if concept_response_similarity > self.similarity_thresholds[concept.protection_level]:
            revelation_score = concept_response_similarity
            revelation_type = "direct"
            evidence["concept_response_similarity"] = float(concept_response_similarity)
        
        # Indirect revelation: response discusses related concepts
        elif concept_response_similarity > 0.4:
            # Check if response mentions related terms
            related_mentions = self._count_related_mentions(response, concept)
            if related_mentions > 0:
                revelation_score = concept_response_similarity * 0.7
                revelation_type = "indirect"
                evidence["related_mentions"] = related_mentions
                evidence["concept_response_similarity"] = float(concept_response_similarity)
        
        # Contextual revelation: response provides context that could lead to concept
        elif concept_query_similarity > 0.6:
            # Query asks about concept, response provides related information
            contextual_score = min(concept_query_similarity * 0.5, concept_response_similarity * 2)
            if contextual_score > 0.2:
                revelation_score = contextual_score
                revelation_type = "contextual"
                evidence["concept_query_similarity"] = float(concept_query_similarity)
                evidence["contextual_score"] = contextual_score
        
        # Implicational revelation: response allows inference of concept
        else:
            # Look for patterns that might allow inference
            inference_score = self._calculate_inference_risk(query, response, concept)
            if inference_score > 0.1:
                revelation_score = inference_score
                revelation_type = "implicational"
                evidence["inference_score"] = inference_score
        
        return ConceptRevelation(
            concept=concept,
            revelation_score=revelation_score,
            confidence=confidence,
            revelation_type=revelation_type,
            evidence=evidence
        )
    
    def _count_related_mentions(self, text: str, concept: SemanticConcept) -> int:
        """Count mentions of concept-related terms in text."""
        text_lower = text.lower()
        mentions = 0
        
        # Check related terms
        for term in concept.related_terms:
            if term.lower() in text_lower:
                mentions += 1
        
        # Check context keywords
        for keyword in concept.context_keywords:
            if keyword.lower() in text_lower:
                mentions += 0.5  # Weight context keywords less
        
        return int(mentions)
    
    def _calculate_inference_risk(
        self, 
        query: str, 
        response: str, 
        concept: SemanticConcept
    ) -> float:
        """Calculate risk that response allows inference of protected concept."""
        # Simple heuristic: if response provides detailed information
        # about topics related to the concept, there's inference risk
        
        risk_score = 0.0
        
        # Check for detailed explanations
        detail_indicators = [
            "specifically", "in detail", "the method", "the process", 
            "the technique", "how it works", "the way that"
        ]
        
        for indicator in detail_indicators:
            if indicator in response.lower():
                risk_score += 0.1
        
        # Check for concept-adjacent information
        adjacent_terms = concept.context_keywords
        adjacent_mentions = sum(1 for term in adjacent_terms if term.lower() in response.lower())
        
        if adjacent_mentions >= 2:  # Multiple adjacent concepts mentioned
            risk_score += adjacent_mentions * 0.05
        
        return min(risk_score, 0.5)  # Cap at 0.5 for inference risk
    
    def _calculate_total_privacy_cost(
        self,
        semantic_distance: float,
        concept_revelations: List[ConceptRevelation]
    ) -> float:
        """Calculate total privacy cost from all revelations."""
        total_cost = 0.0
        
        # Base cost from semantic distance
        total_cost += semantic_distance * 0.3
        
        # Add costs from concept revelations
        for revelation in concept_revelations:
            weight = self.privacy_weights.get(
                f"{revelation.revelation_type}_revelation", 0.5
            )
            
            # Scale by protection level
            protection_multiplier = {
                "low": 1.0,
                "medium": 1.5,
                "high": 2.0,
                "absolute": 3.0
            }.get(revelation.concept.protection_level, 1.0)
            
            revelation_cost = (
                revelation.revelation_score * 
                weight * 
                protection_multiplier * 
                revelation.confidence
            )
            
            total_cost += revelation_cost
        
        return total_cost
    
    def _determine_risk_level(
        self,
        total_cost: float,
        concept_revelations: List[ConceptRevelation]
    ) -> str:
        """Determine overall risk level based on privacy cost and revelations."""
        
        # Check for absolute protection violations
        absolute_violations = [
            r for r in concept_revelations 
            if r.concept.protection_level == "absolute" and r.revelation_score > 0.3
        ]
        
        if absolute_violations:
            return "critical"
        
        # Check for high protection violations
        high_violations = [
            r for r in concept_revelations
            if r.concept.protection_level == "high" and r.revelation_score > 0.5
        ]
        
        if high_violations or total_cost > 2.0:
            return "high"
        
        if total_cost > 1.0:
            return "medium"
        
        return "low"
    
    async def compare_semantic_similarity(
        self,
        text1: str,
        text2: str,
        similarity_threshold: float = 0.7
    ) -> Dict[str, Any]:
        """Compare semantic similarity between two texts."""
        similarity = await self.embedding_provider.get_similarity(text1, text2)
        
        return {
            "similarity_score": similarity,
            "above_threshold": similarity > similarity_threshold,
            "threshold_used": similarity_threshold,
            "risk_level": (
                "high" if similarity > 0.8 else
                "medium" if similarity > 0.6 else
                "low"
            )
        }
    
    def get_concept_summary(self) -> Dict[str, Any]:
        """Get summary of all protected concepts."""
        return {
            "total_concepts": len(self.protected_concepts),
            "concepts_by_level": {
                level: len([
                    c for c in self.protected_concepts.values() 
                    if c.protection_level == level
                ])
                for level in ["low", "medium", "high", "absolute"]
            },
            "concept_names": list(self.protected_concepts.keys())
        }