#!/usr/bin/env python3
"""
Privacy Rule Matcher

Implements the core logic for matching user queries against privacy rules
and generating appropriate filtered responses. This is Phase 1.4 of the
privacy filter system.

Key responsibilities:
- Analyze incoming queries to classify their intent
- Match queries against protected facts and themes  
- Apply response strategies based on privacy instructions
- Track privacy budget consumption
- Generate filtered responses that respect privacy constraints
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from privacy_instructions import PrivacyInstructions, ProtectionLevel, ProtectedFact, ProtectedTheme
from syftbox_integration import SyftBoxPrivacyManager
from entropy_calculator import EntropyCalculator, EntropyMeasurement
from budget_tracker import PrivacyBudgetTracker, BudgetCheckResult
from ollama_privacy_engine import OllamaPrivacyEngine, OllamaConfig

logger = logging.getLogger(__name__)

class QueryType(Enum):
    """Types of queries we can identify."""
    DIRECT_FACT = "direct_fact"  # "What is X?", "Who is Y?"
    ANALYTICAL = "analytical"     # "Why did X happen?", "How does Y work?"
    CREATIVE = "creative"         # "Write a story about...", "Imagine if..."
    EXTRACTION = "extraction"     # Obvious attempts to get raw content
    SUMMARY = "summary"          # "Summarize this", "What's the main point?"
    COMPARISON = "comparison"     # "How is X different from Y?"
    UNKNOWN = "unknown"          # Couldn't classify

class ResponseStrategy(Enum):
    """How to respond to different query types."""
    ALLOW = "allow"              # Provide full information
    PARTIAL = "partial"          # Provide limited information
    ABSTRACT = "abstract"        # Provide abstract/generalized information
    DEFLECT = "deflect"          # Redirect to related but safe topics
    REFUSE = "refuse"            # Decline to answer

@dataclass
class QueryAnalysis:
    """Analysis of a user query."""
    query: str
    query_type: QueryType
    confidence: float  # How confident we are in the classification
    detected_entities: List[str]  # Entities mentioned in query
    detected_concepts: List[str]  # Concepts mentioned in query
    detected_themes: List[str]    # Themes the query relates to
    extraction_risk: float        # How likely this is an extraction attempt (0-1)
    complexity_score: float       # How complex/detailed the query is (0-1)

@dataclass
class ProtectionMatch:
    """A match between query content and protected content."""
    protection_type: str  # "fact", "theme", "entity", etc.
    matched_item: str     # What was matched
    protection_level: ProtectionLevel
    confidence: float     # How confident we are in the match
    query_overlap: float  # How much of the query overlaps with protected content

@dataclass
class FilteredResponse:
    """Result of filtering a query."""
    success: bool
    response: Optional[str] = None
    error_message: Optional[str] = None
    
    # Privacy tracking information
    entropy_consumed: float = 0.0
    budget_remaining: float = 0.0
    similarity_score: float = 0.0
    query_type: Optional[str] = None
    response_strategy: Optional[str] = None
    
    # Protection information
    protections_triggered: List[ProtectionMatch] = None
    abstraction_level: Optional[str] = None

class RuleMatcher:
    """Core rule matching and query filtering logic."""
    
    def __init__(self, privacy_manager: SyftBoxPrivacyManager, storage_path: Optional[Path] = None, ollama_config: Optional[OllamaConfig] = None):
        """Initialize rule matcher with privacy manager and Ollama engine."""
        self.privacy_manager = privacy_manager
        self.entropy_calculator = EntropyCalculator()
        self.budget_tracker = PrivacyBudgetTracker(storage_path)
        self.ollama_engine = OllamaPrivacyEngine(ollama_config or OllamaConfig())
        
        # Query classification patterns
        self.query_patterns = {
            QueryType.DIRECT_FACT: [
                r"what\s+is\s+",
                r"who\s+is\s+",
                r"where\s+is\s+",
                r"when\s+did\s+",
                r"how\s+much\s+",
                r"tell\s+me\s+about\s+",
                r"define\s+",
                r"explain\s+"
            ],
            QueryType.EXTRACTION: [
                r"give\s+me\s+the\s+full\s+",
                r"show\s+me\s+all\s+",
                r"list\s+everything\s+",
                r"copy\s+",
                r"extract\s+",
                r"dump\s+",
                r"verbatim\s+",
                r"word\s+for\s+word\s+"
            ],
            QueryType.ANALYTICAL: [
                r"why\s+",
                r"how\s+does\s+",
                r"what\s+caused\s+",
                r"analyze\s+",
                r"compare\s+",
                r"evaluate\s+"
            ],
            QueryType.CREATIVE: [
                r"write\s+a\s+story\s+",
                r"imagine\s+",
                r"create\s+",
                r"generate\s+",
                r"compose\s+"
            ],
            QueryType.SUMMARY: [
                r"summarize\s+",
                r"main\s+points?\s+",
                r"overview\s+",
                r"key\s+takeaways?\s+",
                r"in\s+summary\s+"
            ]
        }
        
        # Entity extraction patterns
        self.entity_patterns = [
            r"[A-Z][a-z]+\s+[A-Z][a-z]+",  # Person names
            r"\b\d{4}\b",                    # Years
            r"\$\d+",                        # Money amounts
            r"\b[A-Z][a-z]+\s+(?:Inc|Corp|LLC|Ltd)\b"  # Company names
        ]
        
    async def initialize(self):
        """Initialize the rule matcher with all components."""
        await self.entropy_calculator.initialize()
        await self.budget_tracker.initialize()
        
        try:
            await self.ollama_engine.initialize()
            logger.info("Rule matcher initialized with Ollama privacy engine")
        except Exception as e:
            logger.warning(f"Ollama engine initialization failed: {e}")
            logger.warning("Falling back to traditional rule matching")
        
        logger.info("Rule matcher initialization completed")
        
    async def filter_query(
        self,
        query: str,
        document_name: str,
        user_email: str,
        session_id: Optional[str],
        privacy_instructions: PrivacyInstructions
    ) -> FilteredResponse:
        """
        Main filtering method - analyze query and generate filtered response.
        
        Args:
            query: User's question about the document
            document_name: Name of document being queried
            user_email: Email of requesting user
            session_id: Session identifier for tracking
            privacy_instructions: Privacy rules for the document
            
        Returns:
            FilteredResponse with filtered content or error
        """
        try:
            logger.info(f"Filtering query: '{query[:100]}...' for document: {document_name}")
            
            # Step 1: Check privacy budget constraints FIRST
            budget_check = await self.budget_tracker.check_budget_constraints(
                user_email=user_email,
                document_name=document_name,
                query=query,
                estimated_response_length=200,
                session_id=session_id,
                privacy_instructions=privacy_instructions
            )
            
            if not budget_check.allowed:
                return FilteredResponse(
                    success=False,
                    error_message=budget_check.reason,
                    budget_remaining=budget_check.remaining_budget
                )
            
            # Step 2: Try Ollama-based semantic privacy analysis
            try:
                filtered_response = await self._filter_with_ollama(
                    query, privacy_instructions, document_name
                )
                
                # Calculate privacy metrics from Ollama analysis
                privacy_analysis = filtered_response.get("privacy_analysis")
                semantic_privacy_cost = privacy_analysis.privacy_cost if privacy_analysis else 1.0
                
                # Record semantic privacy consumption
                entropy_measurement = EntropyMeasurement(
                    entropy_value=semantic_privacy_cost,
                    measurement_type="semantic",
                    confidence=0.9
                )
                
                await self.budget_tracker.record_entropy_consumption(
                    user_email=user_email,
                    document_name=document_name,
                    query=query,
                    response=filtered_response["response"],
                    entropy_measurement=entropy_measurement,
                    session_id=session_id
                )
                
                return FilteredResponse(
                    success=True,
                    response=filtered_response["response"],
                    entropy_consumed=semantic_privacy_cost,
                    budget_remaining=budget_check.remaining_budget - semantic_privacy_cost,
                    similarity_score=privacy_analysis.semantic_similarity if privacy_analysis else 0.0,
                    query_type="semantic_analysis",
                    response_strategy=privacy_analysis.overall_risk if privacy_analysis else "unknown",
                    protections_triggered=[], # Ollama handles this internally
                    abstraction_level="semantic"
                )
                
            except Exception as ollama_error:
                logger.warning(f"Ollama filtering failed: {ollama_error}")
                logger.info("Falling back to traditional rule matching")
                
                # Fallback to traditional approach
                return await self._filter_with_traditional_rules(
                    query, user_email, document_name, session_id, privacy_instructions, budget_check
                )
            
        except Exception as e:
            logger.error(f"Error filtering query: {e}")
            return FilteredResponse(
                success=False,
                error_message=f"Error processing query: {str(e)}"
            )
    
    async def _analyze_query(self, query: str, privacy_instructions: PrivacyInstructions) -> QueryAnalysis:
        """Analyze a query to understand its intent and content."""
        query_lower = query.lower()
        
        # Classify query type
        query_type, confidence = self._classify_query_type(query_lower)
        
        # Extract entities mentioned in query
        detected_entities = self._extract_entities(query)
        
        # Extract concepts mentioned in query
        detected_concepts = self._extract_concepts(query, privacy_instructions)
        
        # Extract themes
        detected_themes = self._extract_themes(query, privacy_instructions)
        
        # Calculate extraction risk
        extraction_risk = self._calculate_extraction_risk(query_lower)
        
        # Calculate complexity score
        complexity_score = self._calculate_complexity_score(query)
        
        return QueryAnalysis(
            query=query,
            query_type=query_type,
            confidence=confidence,
            detected_entities=detected_entities,
            detected_concepts=detected_concepts,
            detected_themes=detected_themes,
            extraction_risk=extraction_risk,
            complexity_score=complexity_score
        )
    
    def _classify_query_type(self, query_lower: str) -> Tuple[QueryType, float]:
        """Classify the type of query based on patterns."""
        max_confidence = 0.0
        best_type = QueryType.UNKNOWN
        
        for query_type, patterns in self.query_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    # Simple confidence based on pattern specificity
                    confidence = len(pattern) / 100.0  # Longer patterns = more specific
                    if confidence > max_confidence:
                        max_confidence = confidence
                        best_type = query_type
        
        return best_type, max_confidence
    
    def _extract_entities(self, query: str) -> List[str]:
        """Extract entity references from query."""
        entities = []
        
        for pattern in self.entity_patterns:
            matches = re.findall(pattern, query)
            entities.extend(matches)
        
        return entities
    
    def _extract_concepts(self, query: str, privacy_instructions: PrivacyInstructions) -> List[str]:
        """Extract concept references from query by matching against protected concepts."""
        concepts = []
        query_lower = query.lower()
        
        for fact in privacy_instructions.protected_facts:
            if fact.category == "concepts":
                for concept in fact.items:
                    # Simple substring matching - could be enhanced with semantic similarity
                    concept_lower = concept.lower()
                    if concept_lower in query_lower:
                        concepts.append(concept)
        
        return concepts
    
    def _extract_themes(self, query: str, privacy_instructions: PrivacyInstructions) -> List[str]:
        """Extract theme references from query."""
        themes = []
        query_lower = query.lower()
        
        for theme in privacy_instructions.protected_themes:
            # Check if theme keywords appear in query
            theme_lower = theme.theme.lower()
            if theme_lower in query_lower:
                themes.append(theme.theme)
        
        return themes
    
    def _calculate_extraction_risk(self, query_lower: str) -> float:
        """Calculate how likely this query is an extraction attempt."""
        extraction_keywords = [
            "full", "complete", "entire", "all", "everything", "verbatim",
            "exact", "copy", "duplicate", "reproduce", "show me the",
            "give me the", "list all", "dump", "extract", "tell me everything",
            "full text", "whole document", "raw content"
        ]
        
        risk_score = 0.0
        for keyword in extraction_keywords:
            if keyword in query_lower:
                # Some keywords are stronger indicators
                if keyword in ["give me the", "full text", "dump", "extract", "everything"]:
                    risk_score += 0.4
                else:
                    risk_score += 0.2
        
        return min(risk_score, 1.0)
    
    def _calculate_complexity_score(self, query: str) -> float:
        """Calculate query complexity based on length and structure."""
        # Simple complexity based on word count and question marks
        word_count = len(query.split())
        question_marks = query.count('?')
        
        # Normalize to 0-1 scale
        complexity = (word_count / 50.0) + (question_marks * 0.1)
        return min(complexity, 1.0)
    
    async def _find_protection_matches(
        self, 
        analysis: QueryAnalysis, 
        privacy_instructions: PrivacyInstructions
    ) -> List[ProtectionMatch]:
        """Find matches between query content and protected content."""
        matches = []
        query_lower = analysis.query.lower()
        
        # Check for protected fact matches
        for fact in privacy_instructions.protected_facts:
            for item in fact.items:
                item_lower = item.lower()
                
                # Check for substring match first (most direct)
                if item_lower in query_lower:
                    matches.append(ProtectionMatch(
                        protection_type="fact",
                        matched_item=item,
                        protection_level=fact.protection_level,
                        confidence=1.0,  # Direct substring match
                        query_overlap=len(item_lower) / len(query_lower)
                    ))
                else:
                    # Check for word overlap (handles partial matches)
                    overlap = self._calculate_text_overlap(query_lower, item_lower)
                    if overlap > 0.2:  # Lower threshold for partial matches
                        matches.append(ProtectionMatch(
                            protection_type="fact",
                            matched_item=item,
                            protection_level=fact.protection_level,
                            confidence=overlap,
                            query_overlap=overlap
                        ))
        
        # Check for protected theme matches  
        for theme in privacy_instructions.protected_themes:
            theme_desc_lower = theme.description.lower()
            theme_name_lower = theme.theme.lower()
            
            # Check if theme name appears in query
            if theme_name_lower in query_lower:
                matches.append(ProtectionMatch(
                    protection_type="theme",
                    matched_item=theme.theme,
                    protection_level=ProtectionLevel.HIGH,
                    confidence=1.0,
                    query_overlap=len(theme_name_lower) / len(query_lower)
                ))
            else:
                # Check description overlap
                theme_overlap = self._calculate_text_overlap(query_lower, theme_desc_lower)
                if theme_overlap > 0.15:  # Lower threshold for themes
                    matches.append(ProtectionMatch(
                        protection_type="theme",
                        matched_item=theme.theme,
                        protection_level=ProtectionLevel.HIGH,
                        confidence=theme_overlap,
                        query_overlap=theme_overlap
                    ))
        
        return matches
    
    def _calculate_text_overlap(self, text1: str, text2: str) -> float:
        """Calculate overlap between two text strings based on word overlap."""
        words1 = set(text1.split())
        words2 = set(text2.split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        
        # Use minimum length for better overlap detection
        min_length = min(len(words1), len(words2))
        if min_length == 0:
            return 0.0
        
        return len(intersection) / min_length
    
    async def _determine_response_strategy(
        self,
        analysis: QueryAnalysis,
        protection_matches: List[ProtectionMatch],
        privacy_instructions: PrivacyInstructions
    ) -> ResponseStrategy:
        """Determine how to respond based on query analysis and protection matches."""
        
        # High extraction risk = refuse
        if analysis.extraction_risk > 0.6:
            return ResponseStrategy.REFUSE
        
        # Check highest protection level triggered
        highest_protection = ProtectionLevel.LOW
        protection_hierarchy = {
            ProtectionLevel.LOW: 0,
            ProtectionLevel.MEDIUM: 1,
            ProtectionLevel.HIGH: 2,
            ProtectionLevel.ABSOLUTE: 3
        }
        
        for match in protection_matches:
            if protection_hierarchy[match.protection_level] > protection_hierarchy[highest_protection]:
                highest_protection = match.protection_level
        
        # Apply strategy based on protection level and query type
        if highest_protection == ProtectionLevel.ABSOLUTE:
            return ResponseStrategy.REFUSE
        elif highest_protection == ProtectionLevel.HIGH:
            if analysis.query_type in [QueryType.DIRECT_FACT, QueryType.EXTRACTION]:
                return ResponseStrategy.DEFLECT
            else:
                return ResponseStrategy.ABSTRACT
        elif highest_protection == ProtectionLevel.MEDIUM:
            if analysis.query_type == QueryType.EXTRACTION:
                return ResponseStrategy.REFUSE
            elif analysis.query_type == QueryType.DIRECT_FACT:
                return ResponseStrategy.PARTIAL
            else:
                return ResponseStrategy.ABSTRACT
        else:
            # Low protection or no matches
            return ResponseStrategy.ALLOW
    
    async def _filter_with_ollama(
        self, 
        query: str, 
        privacy_instructions: PrivacyInstructions, 
        document_name: str
    ) -> Dict[str, Any]:
        """Filter query using Ollama semantic privacy analysis."""
        
        # Register protected concepts with Ollama engine
        for fact in privacy_instructions.protected_facts:
            for item in fact.items:
                self.ollama_engine.register_protected_concept(
                    name=f"{fact.category}_{item.lower().replace(' ', '_')}",
                    description=f"{fact.category}: {item}",
                    protection_level=fact.protection_level.value,
                    related_terms=fact.items
                )
        
        for theme in privacy_instructions.protected_themes:
            self.ollama_engine.register_protected_concept(
                name=f"theme_{theme.theme.lower().replace(' ', '_')}",
                description=theme.description,
                protection_level="high",  # Themes are generally high protection
                related_terms=[theme.theme]
            )
        
        # Generate initial response (placeholder - would be from actual document)
        initial_response = f"Based on the document '{document_name}', here is information about your query regarding: {query}"
        
        # Analyze privacy of initial response
        privacy_analysis = await self.ollama_engine.analyze_privacy(
            query=query,
            response=initial_response
        )
        
        # Determine strategy based on risk level
        strategy_map = {
            "low": "allow",
            "medium": "partial", 
            "high": "deflect",
            "critical": "refuse"
        }
        strategy = strategy_map.get(privacy_analysis.overall_risk, "deflect")
        
        # Generate filtered response
        filtered_response = await self.ollama_engine.generate_filtered_response(
            query=query,
            original_response=initial_response,
            privacy_analysis=privacy_analysis,
            strategy=strategy,
            protection_level=privacy_instructions.fallback_config.default_protection_level.value,
            violation_response=privacy_instructions.fallback_config.protection_violation_response
        )
        
        return {
            "response": filtered_response,
            "privacy_analysis": privacy_analysis,
            "strategy": strategy
        }
    
    async def _filter_with_traditional_rules(
        self,
        query: str,
        user_email: str, 
        document_name: str,
        session_id: Optional[str],
        privacy_instructions: PrivacyInstructions,
        budget_check: BudgetCheckResult
    ) -> FilteredResponse:
        """Fallback to traditional rule-based filtering."""
        
        # Traditional analysis pipeline
        analysis = await self._analyze_query(query, privacy_instructions)
        protection_matches = await self._find_protection_matches(analysis, privacy_instructions)
        strategy = await self._determine_response_strategy(analysis, protection_matches, privacy_instructions)
        
        # Generate traditional filtered response
        filtered_response = await self._generate_filtered_response(
            query, analysis, protection_matches, strategy, privacy_instructions, document_name
        )
        
        # Calculate traditional entropy
        protected_content = []
        for fact in privacy_instructions.protected_facts:
            protected_content.extend(fact.items)
        
        entropy_measurement = self.entropy_calculator.calculate_composite_entropy(
            query=query,
            response=filtered_response,
            protected_content=protected_content
        )
        
        # Record consumption
        await self.budget_tracker.record_entropy_consumption(
            user_email=user_email,
            document_name=document_name,
            query=query,
            response=filtered_response,
            entropy_measurement=entropy_measurement,
            session_id=session_id
        )
        
        similarity_score = self._calculate_similarity_score(query, filtered_response)
        
        return FilteredResponse(
            success=True,
            response=filtered_response,
            entropy_consumed=entropy_measurement.entropy_value,
            budget_remaining=budget_check.remaining_budget - entropy_measurement.entropy_value,
            similarity_score=similarity_score,
            query_type=analysis.query_type.value,
            response_strategy=strategy.value,
            protections_triggered=protection_matches,
            abstraction_level=self._get_abstraction_level(strategy, privacy_instructions)
        )
    
    async def _generate_filtered_response(
        self,
        query: str,
        analysis: QueryAnalysis,
        protection_matches: List[ProtectionMatch],
        strategy: ResponseStrategy,
        privacy_instructions: PrivacyInstructions,
        document_name: str
    ) -> str:
        """Generate the actual filtered response based on the strategy."""
        
        fallback_config = privacy_instructions.fallback_config
        
        if strategy == ResponseStrategy.REFUSE:
            return fallback_config.protection_violation_response
        
        elif strategy == ResponseStrategy.DEFLECT:
            # Redirect to safe topics from shareable content
            if privacy_instructions.shareable_content.open_topics:
                safe_topic = privacy_instructions.shareable_content.open_topics[0]
                return f"I can discuss {safe_topic} related to this document, but cannot provide specific details you're asking about."
            else:
                return "I can provide general information about this topic, but cannot share specific details."
        
        elif strategy == ResponseStrategy.ABSTRACT:
            # Provide abstract, high-level response
            return self._generate_abstract_response(query, analysis, privacy_instructions)
        
        elif strategy == ResponseStrategy.PARTIAL:
            # Provide limited information
            return self._generate_partial_response(query, analysis, privacy_instructions)
        
        else:  # ALLOW
            # In Phase 1.4, we'll return a placeholder
            # In Phase 4, this would call the actual LLM to generate response
            return f"[This would be a full response about {document_name} - LLM integration pending]"
    
    def _generate_abstract_response(self, query: str, analysis: QueryAnalysis, privacy_instructions: PrivacyInstructions) -> str:
        """Generate an abstract response that doesn't reveal specifics."""
        if analysis.query_type == QueryType.DIRECT_FACT:
            return "This document contains information related to your question, but I can only provide general thematic discussion rather than specific details."
        elif analysis.query_type == QueryType.ANALYTICAL:
            return "The document explores concepts that relate to your question at a high level, focusing on general principles rather than specific implementations."
        else:
            return "I can discuss the general themes and concepts in this document, but cannot provide detailed specifics."
    
    def _generate_partial_response(self, query: str, analysis: QueryAnalysis, privacy_instructions: PrivacyInstructions) -> str:
        """Generate a partial response with limited information."""
        return f"I can provide some general information about this topic from the document, while keeping specific details private as requested."
    
    # Old _calculate_entropy_consumption method removed - now using EntropyCalculator
    
    def _calculate_similarity_score(self, query: str, response: str) -> float:
        """Calculate similarity between query and response."""
        return self._calculate_text_overlap(query.lower(), response.lower())
    
    def _get_abstraction_level(self, strategy: ResponseStrategy, privacy_instructions: PrivacyInstructions) -> str:
        """Get the abstraction level for the response strategy."""
        if strategy == ResponseStrategy.REFUSE:
            return "none"
        elif strategy == ResponseStrategy.DEFLECT:
            return "redirect"
        elif strategy == ResponseStrategy.ABSTRACT:
            return "high"
        elif strategy == ResponseStrategy.PARTIAL:
            return "medium"
        else:
            return "low"