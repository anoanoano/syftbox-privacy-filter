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
        
        # Initialize rule matcher
        rule_matcher = RuleMatcher(privacy_manager)
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
        
        # Analyze the query and generate filtered response
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