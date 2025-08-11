#!/usr/bin/env python3
"""
Ollama Privacy Engine

Unified LLM-based privacy analysis engine that uses Ollama for:
- Semantic similarity analysis
- Concept revelation detection  
- Privacy risk assessment
- Filtered response generation

This consolidates Phases 2-4 into a single coherent system that uses
native LLM semantic understanding instead of mathematical approximations.
"""

import asyncio
import aiohttp
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import re

logger = logging.getLogger(__name__)

@dataclass
class OllamaConfig:
    """Configuration for Ollama API connection."""
    base_url: str = "http://localhost:11434"
    model_name: str = "llama3.2"
    timeout: int = 30
    max_retries: int = 3

@dataclass
class ConceptAnalysis:
    """Analysis of how much a concept is revealed in a response."""
    concept_name: str
    revelation_score: float  # 0.0-1.0
    revelation_type: str    # "none", "indirect", "partial", "significant", "complete"
    explanation: str
    confidence: float
    risk_level: str  # "low", "medium", "high", "critical"

@dataclass
class PrivacyAnalysis:
    """Complete privacy analysis of a query-response pair."""
    query: str
    response: str
    overall_risk: str  # "low", "medium", "high", "critical"
    semantic_similarity: float  # 0.0-1.0
    concept_analyses: List[ConceptAnalysis]
    privacy_cost: float  # 0.0-10.0 scale
    recommendations: List[str]
    explanation: str
    metadata: Dict[str, Any] = field(default_factory=dict)

class OllamaPrivacyEngine:
    """
    Unified privacy engine using Ollama LLM for semantic privacy analysis.
    
    This engine uses natural language processing via Ollama to:
    1. Analyze semantic similarity between queries and responses
    2. Detect concept revelation in responses
    3. Assess privacy risks
    4. Generate privacy-filtered responses
    """
    
    def __init__(self, config: Optional[OllamaConfig] = None):
        """Initialize Ollama privacy engine."""
        self.config = config or OllamaConfig()
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Protected concepts registry
        self.protected_concepts: Dict[str, Dict[str, Any]] = {}
        
        # Analysis prompts
        self.prompts = {
            "similarity": """Analyze the semantic similarity between this query and response.

Query: "{query}"
Response: "{response}"

Rate their semantic similarity on a scale of 0.0 to 1.0:
- 0.0 = Completely unrelated topics
- 0.3 = Somewhat related concepts  
- 0.6 = Closely related topics
- 0.9 = Nearly identical meaning
- 1.0 = Identical meaning

Provide only the numerical score (e.g., 0.7):""",

            "concept_revelation": """Analyze how much information about the concept "{concept_name}" is revealed in this response.

Concept Description: {concept_description}
Protection Level: {protection_level}
Query: "{query}"
Response: "{response}"

Analyze the revelation level:
- NONE (0.0): No information about the concept revealed
- INDIRECT (0.3): General or tangentially related information  
- PARTIAL (0.6): Some specific details about the concept
- SIGNIFICANT (0.8): Major details or direct discussion
- COMPLETE (1.0): Full revelation of protected information

Rate from 0.0 to 1.0 and classify the revelation level.

Respond in this exact format:
SCORE: [0.0-1.0]
TYPE: [none|indirect|partial|significant|complete]  
EXPLANATION: [Brief explanation]
CONFIDENCE: [0.0-1.0]
RISK: [low|medium|high|critical]""",

            "privacy_assessment": """Assess the overall privacy risk of this query-response interaction.

Query: "{query}"
Response: "{response}"
Protected Concepts: {concepts}
Concept Analyses: {concept_analyses}

Consider:
- How much protected information was revealed?
- Could this response enable inference of protected concepts?
- What is the cumulative privacy cost?
- Are there patterns that suggest coordinated extraction?

Assess the privacy risk level and cost.

Respond in this exact format:
RISK: [low|medium|high|critical]
COST: [0.0-10.0]
EXPLANATION: [Detailed explanation]
RECOMMENDATIONS: [Recommendation 1; Recommendation 2; Recommendation 3]""",

            "filter_response": """Generate a privacy-filtered response to this query based on the privacy instructions.

Query: "{query}"
Original Response: "{original_response}"
Protected Concepts: {protected_concepts}
Privacy Analysis: {privacy_analysis}
Strategy: {strategy}

Privacy Instructions:
- Protect concepts at {protection_level} level
- Use {strategy} strategy (refuse/deflect/abstract/partial/allow)
- Violation response: "{violation_response}"

Generate an appropriate filtered response that:
1. Follows the specified strategy
2. Protects the concepts appropriately  
3. Provides helpful information when possible
4. Maintains natural conversational tone

Filtered Response:"""
        }
    
    async def initialize(self):
        """Initialize the Ollama privacy engine."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
        )
        
        # Test connection to Ollama
        try:
            await self._test_ollama_connection()
            logger.info(f"Ollama privacy engine initialized with model: {self.config.model_name}")
        except Exception as e:
            logger.error(f"Failed to connect to Ollama: {e}")
            raise
    
    async def close(self):
        """Clean up resources."""
        if self.session:
            await self.session.close()
    
    def register_protected_concept(
        self,
        name: str,
        description: str,
        protection_level: str,
        related_terms: Optional[List[str]] = None
    ):
        """Register a protected concept for analysis."""
        self.protected_concepts[name] = {
            "name": name,
            "description": description,
            "protection_level": protection_level,
            "related_terms": related_terms or []
        }
        logger.debug(f"Registered protected concept: {name} ({protection_level})")
    
    async def analyze_semantic_similarity(self, query: str, response: str) -> float:
        """Analyze semantic similarity between query and response using LLM."""
        prompt = self.prompts["similarity"].format(query=query, response=response)
        
        try:
            llm_response = await self._call_ollama(prompt)
            
            # Extract numerical score from response
            score = self._extract_similarity_score(llm_response)
            return max(0.0, min(1.0, score))  # Clamp to 0-1
            
        except Exception as e:
            logger.error(f"Error analyzing similarity: {e}")
            return 0.0
    
    async def analyze_concept_revelation(
        self, 
        query: str, 
        response: str, 
        concept_name: str
    ) -> ConceptAnalysis:
        """Analyze how much of a protected concept is revealed."""
        if concept_name not in self.protected_concepts:
            raise ValueError(f"Unknown concept: {concept_name}")
        
        concept = self.protected_concepts[concept_name]
        
        prompt = self.prompts["concept_revelation"].format(
            concept_name=concept_name,
            concept_description=concept["description"],
            protection_level=concept["protection_level"],
            query=query,
            response=response
        )
        
        try:
            llm_response = await self._call_ollama(prompt)
            analysis_data = self._parse_structured_response(llm_response)
            
            return ConceptAnalysis(
                concept_name=concept_name,
                revelation_score=float(analysis_data.get("score", 0.0)),
                revelation_type=analysis_data.get("type", "none"),
                explanation=analysis_data.get("explanation", ""),
                confidence=float(analysis_data.get("confidence", 0.8)),
                risk_level=analysis_data.get("risk", "low")
            )
            
        except Exception as e:
            logger.error(f"Error analyzing concept revelation for {concept_name}: {e}")
            return ConceptAnalysis(
                concept_name=concept_name,
                revelation_score=0.0,
                revelation_type="none",
                explanation=f"Analysis failed: {str(e)}",
                confidence=0.0,
                risk_level="low"
            )
    
    async def assess_privacy_risk(
        self,
        query: str,
        response: str,
        concept_analyses: List[ConceptAnalysis]
    ) -> Dict[str, Any]:
        """Assess overall privacy risk using LLM analysis."""
        
        # Format concept analyses for prompt
        concept_summary = {
            concept.concept_name: {
                "revelation_score": concept.revelation_score,
                "revelation_type": concept.revelation_type,
                "risk_level": concept.risk_level
            }
            for concept in concept_analyses
        }
        
        protected_concepts = list(self.protected_concepts.keys())
        
        prompt = self.prompts["privacy_assessment"].format(
            query=query,
            response=response,
            concepts=protected_concepts,
            concept_analyses=json.dumps(concept_summary, indent=2)
        )
        
        try:
            llm_response = await self._call_ollama(prompt)
            analysis_data = self._parse_structured_response(llm_response)
            return {
                "overall_risk": analysis_data.get("risk", "low"),
                "privacy_cost": float(analysis_data.get("cost", 0.0)),
                "explanation": analysis_data.get("explanation", ""),
                "recommendations": analysis_data.get("recommendations", "").split(";") if analysis_data.get("recommendations") else []
            }
            
        except Exception as e:
            logger.error(f"Error assessing privacy risk: {e}")
            return {
                "overall_risk": "low",
                "privacy_cost": 0.0,
                "explanation": f"Assessment failed: {str(e)}",
                "recommendations": []
            }
    
    async def analyze_privacy(
        self,
        query: str,
        response: str,
        concepts_to_check: Optional[List[str]] = None
    ) -> PrivacyAnalysis:
        """Complete privacy analysis of query-response pair."""
        
        # Determine which concepts to analyze
        if concepts_to_check is None:
            concepts_to_check = list(self.protected_concepts.keys())
        
        # Analyze semantic similarity
        similarity = await self.analyze_semantic_similarity(query, response)
        
        # Analyze concept revelations
        concept_analyses = []
        for concept_name in concepts_to_check:
            if concept_name in self.protected_concepts:
                analysis = await self.analyze_concept_revelation(query, response, concept_name)
                concept_analyses.append(analysis)
        
        # Assess overall privacy risk
        risk_assessment = await self.assess_privacy_risk(query, response, concept_analyses)
        
        return PrivacyAnalysis(
            query=query,
            response=response,
            overall_risk=risk_assessment.get("overall_risk", "low"),
            semantic_similarity=similarity,
            concept_analyses=concept_analyses,
            privacy_cost=risk_assessment.get("privacy_cost", 0.0),
            recommendations=risk_assessment.get("recommendations", []),
            explanation=risk_assessment.get("explanation", ""),
            metadata={
                "timestamp": datetime.now().isoformat(),
                "model_used": self.config.model_name,
                "concepts_analyzed": len(concept_analyses)
            }
        )
    
    async def generate_filtered_response(
        self,
        query: str,
        original_response: str,
        privacy_analysis: PrivacyAnalysis,
        strategy: str = "deflect",
        protection_level: str = "medium",
        violation_response: str = "This information is protected."
    ) -> str:
        """Generate privacy-filtered response using LLM."""
        
        # Format protected concepts for prompt
        protected_concepts = [
            f"{name}: {info['description']} ({info['protection_level']})"
            for name, info in self.protected_concepts.items()
        ]
        
        prompt = self.prompts["filter_response"].format(
            query=query,
            original_response=original_response,
            protected_concepts=protected_concepts,
            privacy_analysis=privacy_analysis.explanation,
            strategy=strategy,
            protection_level=protection_level,
            violation_response=violation_response
        )
        
        try:
            filtered_response = await self._call_ollama(prompt)
            return filtered_response.strip()
            
        except Exception as e:
            logger.error(f"Error generating filtered response: {e}")
            # Fallback to violation response
            return violation_response
    
    async def _call_ollama(self, prompt: str) -> str:
        """Make API call to Ollama."""
        if not self.session:
            raise RuntimeError("Session not initialized - call initialize() first")
        
        payload = {
            "model": self.config.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for consistent analysis
                "top_p": 0.9,
                "repeat_penalty": 1.1
            }
        }
        
        for attempt in range(self.config.max_retries):
            try:
                async with self.session.post(
                    f"{self.config.base_url}/api/generate",
                    json=payload
                ) as response:
                    response.raise_for_status()
                    data = await response.json()
                    return data.get("response", "")
                    
            except Exception as e:
                logger.warning(f"Ollama call attempt {attempt + 1} failed: {e}")
                if attempt == self.config.max_retries - 1:
                    raise
                await asyncio.sleep(1)  # Brief delay before retry
    
    async def _test_ollama_connection(self):
        """Test connection to Ollama server."""
        try:
            test_response = await self._call_ollama("Test connection. Respond with 'OK'.")
            if "ok" not in test_response.lower():
                logger.warning(f"Unexpected test response: {test_response}")
        except Exception as e:
            raise RuntimeError(f"Cannot connect to Ollama at {self.config.base_url}: {e}")
    
    def _extract_similarity_score(self, response: str) -> float:
        """Extract numerical similarity score from LLM response."""
        # Look for decimal numbers in response
        matches = re.findall(r'\b\d*\.?\d+\b', response)
        if matches:
            try:
                score = float(matches[0])
                if 0.0 <= score <= 1.0:
                    return score
            except ValueError:
                pass
        
        # Fallback: look for common patterns
        response_lower = response.lower()
        if any(word in response_lower for word in ["identical", "same", "exact"]):
            return 0.9
        elif any(word in response_lower for word in ["similar", "close", "related"]):
            return 0.6
        elif any(word in response_lower for word in ["somewhat", "partially"]):
            return 0.3
        elif any(word in response_lower for word in ["different", "unrelated", "no"]):
            return 0.1
        
        return 0.0
    
    def _parse_structured_response(self, response: str) -> Dict[str, Any]:
        """Parse structured text response from LLM."""
        result = {}
        
        # Parse each field from the structured format
        patterns = {
            "score": r"SCORE:\s*([0-9]*\.?[0-9]+)",
            "type": r"TYPE:\s*(\w+)",
            "explanation": r"EXPLANATION:\s*(.+?)(?=\n[A-Z]+:|$)",
            "confidence": r"CONFIDENCE:\s*([0-9]*\.?[0-9]+)", 
            "risk": r"RISK:\s*(\w+)",
            "cost": r"COST:\s*([0-9]*\.?[0-9]+)",
            "recommendations": r"RECOMMENDATIONS:\s*(.+?)(?=\n[A-Z]+:|$)"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
            if match:
                result[key] = match.group(1).strip()
        
        return result
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response from LLM, with fallback handling."""
        try:
            # Try to find JSON in the response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # No JSON found, create fallback response
                return {"error": "No JSON found in response", "raw_response": response}
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            return {"error": "JSON parse error", "raw_response": response}
    
    def get_concept_summary(self) -> Dict[str, Any]:
        """Get summary of registered protected concepts."""
        return {
            "total_concepts": len(self.protected_concepts),
            "concepts": [
                {
                    "name": concept["name"],
                    "protection_level": concept["protection_level"],
                    "description": concept["description"][:100] + "..." if len(concept["description"]) > 100 else concept["description"]
                }
                for concept in self.protected_concepts.values()
            ]
        }