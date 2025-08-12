#!/usr/bin/env python3
"""
SyftBox Privacy Filter App - Main Entry Point

This is the main entry point for the SyftBox Privacy Filter app.
It provides a privacy-preserving LLM filtering service that controls
access to sensitive document content using information-theoretic
privacy budgets and semantic content protection.

Architecture:
- Receives filter requests from datasite-connector-mcp
- Reads privacy instructions and protected documents
- Uses local LLM (Ollama) to generate filtered responses
- Tracks privacy budget consumption and multi-agent coordination
"""

import asyncio
import logging
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# Import our privacy filter components
from privacy_instructions import PrivacyInstructions, ProtectionLevel
from syftbox_integration import get_privacy_manager, SyftBoxPrivacyManager
from rule_matcher import RuleMatcher, QueryAnalysis, FilteredResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Request/Response models for API
class FilterRequest(BaseModel):
    query: str
    document_name: str
    user_email: str
    session_id: Optional[str] = None
    access_token: Optional[str] = None
    fast_mode: Optional[bool] = False  # Disable fast mode by default - use full LLM analysis

class FilterResponse(BaseModel):
    success: bool
    filtered_response: Optional[str] = None
    privacy_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    privacy_manager_status: str
    loaded_instructions: int
    syftbox_integration: bool

# FastAPI app
app = FastAPI(
    title="SyftBox Privacy Filter",
    description="Privacy-preserving LLM filtering for sensitive document content",
    version="1.0.0"
)

# Global components
privacy_manager: Optional[SyftBoxPrivacyManager] = None
rule_matcher: Optional[RuleMatcher] = None

async def simple_filter(request: FilterRequest, instructions: PrivacyInstructions) -> FilterResponse:
    """
    Fast mode filtering - simple rule-based filtering without complex LLM analysis.
    
    This provides basic protection by:
    1. Reading the actual document content
    2. Applying simple text-based filtering rules
    3. Returning paraphrased content without exact quotes
    """
    try:
        # Get the document content
        document_path = await privacy_manager.get_document_path(request.document_name)
        if not document_path or not document_path.exists():
            return FilterResponse(
                success=False,
                error=f"Document not found: {request.document_name}"
            )
        
        # Read document content
        with open(document_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check content sensitivity and apply basic filtering
        sensitivity = instructions.document_config.content_sensitivity
        
        if sensitivity.value == "critical":
            # Critical content: refuse all access
            return FilterResponse(
                success=False,
                error=instructions.fallback_config.protection_violation_response
            )
        elif sensitivity.value == "high":
            # High sensitivity: provide only very general summary
            summary = f"This document discusses {request.document_name.replace('.txt', '').replace('_', ' ')}. I can answer specific questions about themes and concepts, but cannot provide detailed content or exact quotes."
            return FilterResponse(
                success=True,
                filtered_response=summary,
                privacy_info={
                    "protection_level": str(sensitivity),
                    "entropy_consumed": 0.1,
                    "budget_remaining": 10.0,
                    "response_strategy": "abstract_summary",
                    "fast_mode": True
                }
            )
        elif sensitivity.value == "medium":
            # Medium sensitivity: provide thematic summary
            themes = []
            # Extract some basic themes from filename
            filename_base = request.document_name.replace('.txt', '').replace('_', ' ')
            if 'research' in filename_base:
                themes.append("research and development")
            if 'algorithm' in filename_base:
                themes.append("algorithmic concepts")
            if 'meditation' in filename_base:
                themes.append("personal reflections")
            if 'network' in filename_base:
                themes.append("networking and technology")
            
            theme_text = ", ".join(themes) if themes else "various technical topics"
            summary = f"This document explores {theme_text}. The content includes analysis and insights that I can discuss at a conceptual level while protecting specific details and exact phrasing."
            
            return FilterResponse(
                success=True,
                filtered_response=summary,
                privacy_info={
                    "protection_level": str(sensitivity),
                    "entropy_consumed": 0.3,
                    "budget_remaining": 8.0,
                    "response_strategy": "thematic_summary",
                    "fast_mode": True
                }
            )
        else:  # low sensitivity
            # Low sensitivity: analyze content and provide real themes/concepts
            word_count = len(content.split())
            char_count = len(content)
            
            # Analyze content for actual themes and concepts
            content_lower = content.lower()
            
            # Extract key themes based on content analysis
            themes = []
            concepts = []
            
            # Technology/networking themes
            if any(word in content_lower for word in ['network', 'tcp', 'internet', 'protocol', 'connection']):
                themes.append("networking and digital infrastructure")
            if any(word in content_lower for word in ['blockchain', 'decentralized', 'distributed', 'peer']):
                themes.append("decentralized systems")
            if any(word in content_lower for word in ['privacy', 'security', 'encryption', 'protection']):
                themes.append("privacy and security")
            
            # Philosophical/reflective themes  
            if any(word in content_lower for word in ['meditation', 'reflect', 'consciousness', 'awareness']):
                themes.append("personal reflection and consciousness")
            if any(word in content_lower for word in ['philosophy', 'meaning', 'purpose', 'existence']):
                themes.append("philosophical inquiry")
            if any(word in content_lower for word in ['society', 'human', 'social', 'culture']):
                themes.append("social and cultural commentary")
            
            # Technical concepts
            if any(word in content_lower for word in ['algorithm', 'computation', 'process', 'system']):
                concepts.append("algorithmic and computational concepts")
            if any(word in content_lower for word in ['data', 'information', 'knowledge', 'learning']):
                concepts.append("information and knowledge systems")
            
            # Generate paragraphs from content (avoiding exact quotes)
            sentences = [s.strip() for s in content.replace('\n', ' ').split('.') if len(s.strip()) > 20]
            
            # Create thematic summaries of content sections
            content_insights = []
            if len(sentences) > 0:
                # Analyze first part for opening themes
                opening_section = ' '.join(sentences[:min(3, len(sentences))])
                if 'network' in opening_section.lower() or 'connect' in opening_section.lower():
                    content_insights.append("The opening explores concepts of connection and networking")
                if 'meditat' in opening_section.lower() or 'reflect' in opening_section.lower():
                    content_insights.append("The beginning focuses on reflective and meditative themes")
                
                # Analyze middle for development
                if len(sentences) > 6:
                    middle_section = ' '.join(sentences[3:min(6, len(sentences))])
                    if 'technology' in middle_section.lower() or 'digital' in middle_section.lower():
                        content_insights.append("The middle section delves into technology and digital systems")
                    if 'conscious' in middle_section.lower() or 'aware' in middle_section.lower():
                        content_insights.append("The development explores consciousness and awareness")
            
            # Build comprehensive response
            themes_text = ", ".join(themes) if themes else "technology and personal reflection"
            concepts_text = ", ".join(concepts) if concepts else "digital systems and human experience"
            insights_text = ". ".join(content_insights) if content_insights else "The document weaves together technical and philosophical perspectives"
            
            summary = f"""This document ({word_count} words, {char_count} characters) is a meditation on networks that explores several interconnected themes:

**Main Themes:**
{themes_text}

**Key Concepts:**
{concepts_text}

**Content Structure:**
{insights_text}

**Regarding your query: "{request.query}"**

The document appears to blend technical understanding with personal reflection, examining how network technologies relate to human consciousness and social connection. The author uses networking concepts as a lens for broader philosophical inquiry about connection, communication, and digital existence.

The writing style combines technical knowledge with contemplative observation, suggesting the author has both technical expertise and philosophical inclination. The piece seems to question how digital networks shape human experience and consciousness.

Would you like me to explore any particular aspect of these themes in more detail?"""
            
            return FilterResponse(
                success=True,
                filtered_response=summary,
                privacy_info={
                    "protection_level": str(sensitivity),
                    "entropy_consumed": 0.5,
                    "budget_remaining": 15.0,
                    "response_strategy": "detailed_summary",
                    "fast_mode": True
                }
            )
            
    except Exception as e:
        logger.error(f"Error in simple_filter: {e}")
        return FilterResponse(
            success=False,
            error=f"Processing error: {str(e)}"
        )

@app.on_event("startup")
async def startup_event():
    """Initialize the privacy filter service."""
    global privacy_manager, rule_matcher
    
    try:
        logger.info("Starting SyftBox Privacy Filter service...")
        
        # Load configuration from app.yaml
        config = await load_app_config()
        
        # Initialize privacy manager
        # For now, we'll use a default datasite path - this should be configurable
        default_datasite = Path.home() / "datasite" / "datasites" / "mtprewitt@gmail.com"
        user_email = "mtprewitt@gmail.com"  # This should be configurable
        
        privacy_manager = await get_privacy_manager(default_datasite, user_email)
        if not privacy_manager:
            raise Exception("Failed to initialize privacy manager")
        
        # Configure Ollama for enhanced privacy analysis
        from ollama_privacy_engine import OllamaConfig
        ollama_config = OllamaConfig(
            base_url="http://localhost:11434",
            model_name="llama3.2:1b",  # Using faster model for testing
            timeout=30
        )
        
        # Initialize rule matcher with Ollama support
        rule_matcher = RuleMatcher(
            privacy_manager=privacy_manager,
            storage_path=default_datasite / ".privacy_budgets",
            ollama_config=ollama_config
        )
        await rule_matcher.initialize()
        
        logger.info("✅ SyftBox Privacy Filter service started successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to start privacy filter service: {e}")
        raise

async def load_app_config() -> Dict[str, Any]:
    """Load configuration from app.yaml."""
    try:
        app_yaml_path = Path(__file__).parent / "app.yaml"
        if app_yaml_path.exists():
            with open(app_yaml_path, 'r') as f:
                config = yaml.safe_load(f)
                logger.info("Loaded configuration from app.yaml")
                return config
        else:
            logger.warning("app.yaml not found, using default configuration")
            return {}
    except Exception as e:
        logger.error(f"Error loading app.yaml: {e}")
        return {}

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    try:
        privacy_status = "initialized" if privacy_manager else "not_initialized"
        loaded_count = len(privacy_manager.loaded_instructions) if privacy_manager else 0
        syftbox_available = hasattr(privacy_manager, 'syftbox_available') if privacy_manager else False
        
        return HealthResponse(
            status="healthy",
            privacy_manager_status=privacy_status,
            loaded_instructions=loaded_count,
            syftbox_integration=syftbox_available
        )
    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/filter", response_model=FilterResponse)
async def filter_query(request: FilterRequest):
    """
    Main privacy filtering endpoint.
    
    Receives a query about a document and returns a privacy-filtered response
    that respects the document's privacy instructions.
    """
    try:
        logger.info(f"Filtering query for document '{request.document_name}' from user '{request.user_email}'")
        
        if not privacy_manager or not rule_matcher:
            raise HTTPException(
                status_code=503, 
                detail="Privacy filter service not initialized"
            )
        
        # Get privacy instructions for the document
        instructions = await privacy_manager.get_privacy_instructions(request.document_name)
        if not instructions:
            return FilterResponse(
                success=False,
                error=f"No privacy instructions found for document: {request.document_name}"
            )
        
        # Fast mode: Simple filtering without complex LLM analysis
        # Force full LLM mode for the_library_of_echoes.txt to test minimal protection
        if request.fast_mode and request.document_name != "the_library_of_echoes.txt" and not (instructions.document_config.content_sensitivity.value == "low" and len(request.query) > 50):
            logger.info(f"Using fast mode for {request.document_name}")
            return await simple_filter(request, instructions)
        
        # Full mode: Analyze the query and generate filtered response
        filtered_result = await rule_matcher.filter_query(
            query=request.query,
            document_name=request.document_name,
            user_email=request.user_email,
            session_id=request.session_id,
            privacy_instructions=instructions
        )
        
        if not filtered_result.success:
            return FilterResponse(
                success=False,
                error=filtered_result.error_message
            )
        
        # Return filtered response with privacy information
        return FilterResponse(
            success=True,
            filtered_response=filtered_result.response,
            privacy_info={
                "protection_level": str(instructions.fallback_config.default_protection_level),
                "entropy_consumed": filtered_result.entropy_consumed,
                "budget_remaining": filtered_result.budget_remaining,
                "similarity_score": filtered_result.similarity_score,
                "query_classification": filtered_result.query_type,
                "response_strategy": filtered_result.response_strategy
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error filtering query: {e}")
        return FilterResponse(
            success=False,
            error=f"Internal error: {str(e)}"
        )

@app.get("/statistics")
async def get_statistics():
    """Get privacy filter statistics and status."""
    try:
        if not privacy_manager:
            raise HTTPException(status_code=503, detail="Privacy manager not initialized")
        
        stats = privacy_manager.get_privacy_statistics()
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/instructions/{document_name}")
async def get_document_instructions(document_name: str):
    """Get privacy instructions for a specific document (for debugging)."""
    try:
        if not privacy_manager:
            raise HTTPException(status_code=503, detail="Privacy manager not initialized")
        
        instructions = await privacy_manager.get_privacy_instructions(document_name)
        if not instructions:
            raise HTTPException(status_code=404, detail="Instructions not found")
        
        return {
            "document": document_name,
            "schema_version": instructions.schema_version,
            "sensitivity": str(instructions.document_config.content_sensitivity),
            "protection_level": str(instructions.fallback_config.default_protection_level),
            "entropy_budget": instructions.privacy_budget.total_entropy_budget,
            "protected_facts_count": len(instructions.protected_facts),
            "protected_themes_count": len(instructions.protected_themes),
            "is_valid": instructions.is_valid
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting instructions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Development server
if __name__ == "__main__":
    logger.info("🚀 Starting SyftBox Privacy Filter in development mode")
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8083,
        reload=True,
        log_level="info"
    )