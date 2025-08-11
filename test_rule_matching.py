#!/usr/bin/env python3
"""
Test Privacy Rule Matching System

Tests the core rule matching logic for Phase 1.4-1.5 validation.
"""

import asyncio
import logging
from pathlib import Path
import sys
import tempfile
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import our modules
from privacy_instructions import PrivacyInstructionParser, ProtectionLevel
from syftbox_integration import SyftBoxPrivacyManager
from rule_matcher import RuleMatcher, QueryType, ResponseStrategy

async def create_test_privacy_instructions():
    """Create test privacy instruction files in a temporary directory."""
    
    test_dir = Path(tempfile.mkdtemp())
    
    # Create test instruction for "the_algorithm.txt"
    test_instruction = {
        "schema_version": "1.0",
        "document_config": {
            "target_document": "test_document.txt",
            "document_type": "text",
            "content_sensitivity": "high"
        },
        "core_protected_content": {
            "protected_facts": [
                {
                    "category": "entities",
                    "items": ["Count Volkonsky", "Ivan Petrovich", "Moscow friends"],
                    "protection_level": "high"
                },
                {
                    "category": "concepts", 
                    "items": ["accounting method", "mathematical patterns", "supernatural quality"],
                    "protection_level": "absolute"
                }
            ],
            "protected_themes": [
                {
                    "theme": "mystical_revelation",
                    "description": "The specific nature of the accounting revelation",
                    "abstraction_level": "high"
                }
            ]
        },
        "shareable_content": {
            "open_topics": ["19th century Russian literature", "philosophical themes"],
            "conditional_sharing": []
        },
        "response_behavior": {
            "direct_fact_queries": {"strategy": "deflect"},
            "analytical_queries": {"strategy": "abstract"},
            "extraction_attempts": {"strategy": "refuse"}
        },
        "privacy_budget": {
            "total_entropy_budget": 3.5,
            "per_session_entropy_limit": 1.0,
            "daily_entropy_reset": True,
            "max_queries_per_hour": 10,
            "max_queries_per_day": 50,
            "cooldown_period_minutes": 2,
            "similarity_threshold": 0.8,
            "cumulative_similarity_limit": 2.5,
            "similarity_decay_hours": 24
        },
        "multi_agent_protection": {
            "global_budget_sharing": True,
            "collective_entropy_limit": 5.0,
            "detect_coordinated_queries": True,
            "coordination_similarity_threshold": 0.95,
            "coordination_time_window_hours": 24,
            "diversify_responses": True,
            "diversification_strategy": "semantic_rotation"
        },
        "security_config": {
            "require_signature": True,
            "signature_algorithm": "ed25519",
            "owner_public_key": "test_key",
            "integrity_checks": True,
            "checksum_algorithm": "sha256",
            "audit_logging": True,
            "log_all_queries": True,
            "log_all_responses": True
        },
        "fallback_config": {
            "default_protection_level": "high",
            "uncertainty_strategy": "err_on_privacy_side",
            "parsing_error_response": "Privacy settings prevent access.",
            "budget_exceeded_response": "Information limit reached.",
            "protection_violation_response": "This information is protected.",
            "partial_failure_mode": "abstract_only",
            "complete_failure_mode": "refuse_all"
        },
        "metadata": {
            "created_date": "2025-01-11",
            "created_by": "test@example.com"
        }
    }
    
    # Write test instruction file
    instruction_file = test_dir / "test_document.yaml"
    with open(instruction_file, 'w') as f:
        yaml.dump(test_instruction, f)
    
    logger.info(f"Created test instruction file: {instruction_file}")
    logger.info(f"File exists: {instruction_file.exists()}")
    
    return test_dir

async def test_query_classification():
    """Test query type classification."""
    logger.info("=== Testing Query Classification ===")
    
    # Create temporary privacy manager
    test_dir = await create_test_privacy_instructions()
    
    # Create fake datasite structure
    fake_datasite = test_dir / "datasite"
    fake_datasite.mkdir()
    
    privacy_manager = SyftBoxPrivacyManager(fake_datasite, "test@example.com")
    privacy_manager.privacy_instructions_path = test_dir
    privacy_manager.audit_log_path = test_dir / "audit"
    privacy_manager.audit_log_path.mkdir()
    
    # Reinitialize the instruction parser with correct path
    from privacy_instructions import PrivacyInstructionParser
    privacy_manager.instruction_parser = PrivacyInstructionParser(test_dir)
    
    logger.info(f"Privacy instructions path: {privacy_manager.privacy_instructions_path}")
    logger.info(f"Files in directory: {list(privacy_manager.privacy_instructions_path.glob('*.yaml'))}")
    
    # Initialize in fallback mode for testing
    await privacy_manager._initialize_fallback_mode()
    
    rule_matcher = RuleMatcher(privacy_manager)
    await rule_matcher.initialize()
    
    # Get test instructions
    instructions = await privacy_manager.get_privacy_instructions("test_document.txt")
    assert instructions is not None, "Should have loaded test instructions"
    
    # Test different query types
    test_queries = [
        ("What is Ivan Petrovich's accounting method?", QueryType.DIRECT_FACT, "entities/concepts"),
        ("Tell me everything about the mathematical patterns", QueryType.EXTRACTION, "high risk"),
        ("Why did Count Volkonsky discover this revelation?", QueryType.ANALYTICAL, "themes"),
        ("Write a story inspired by this document", QueryType.CREATIVE, "creative"),
        ("Summarize the main points", QueryType.SUMMARY, "general"),
        ("How does this relate to Russian literature?", QueryType.ANALYTICAL, "safe topic")
    ]
    
    for query, expected_type, test_case in test_queries:
        logger.info(f"\n--- Testing: {test_case} ---")
        logger.info(f"Query: '{query}'")
        
        # Analyze the query
        analysis = await rule_matcher._analyze_query(query, instructions)
        
        logger.info(f"Classified as: {analysis.query_type} (confidence: {analysis.confidence:.2f})")
        logger.info(f"Detected entities: {analysis.detected_entities}")
        logger.info(f"Detected concepts: {analysis.detected_concepts}")
        logger.info(f"Extraction risk: {analysis.extraction_risk:.2f}")
        
        # Find protection matches
        protection_matches = await rule_matcher._find_protection_matches(analysis, instructions)
        logger.info(f"Protection matches: {len(protection_matches)}")
        for match in protection_matches:
            logger.info(f"  - {match.protection_type}: {match.matched_item} ({match.protection_level})")
        
        # Determine strategy
        strategy = await rule_matcher._determine_response_strategy(analysis, protection_matches, instructions)
        logger.info(f"Response strategy: {strategy}")
        
        # Check if classification makes sense
        if expected_type != QueryType.UNKNOWN:
            success = "✅" if analysis.query_type == expected_type else "❌"
            logger.info(f"{success} Expected: {expected_type}, Got: {analysis.query_type}")

async def test_end_to_end_filtering():
    """Test complete end-to-end filtering process."""
    logger.info("\n=== Testing End-to-End Filtering ===")
    
    # Create test setup
    test_dir = await create_test_privacy_instructions()
    fake_datasite = test_dir / "datasite"
    fake_datasite.mkdir()
    
    privacy_manager = SyftBoxPrivacyManager(fake_datasite, "test@example.com")
    privacy_manager.privacy_instructions_path = test_dir
    privacy_manager.audit_log_path = test_dir / "audit"
    privacy_manager.audit_log_path.mkdir()
    
    # Reinitialize the instruction parser with correct path
    from privacy_instructions import PrivacyInstructionParser
    privacy_manager.instruction_parser = PrivacyInstructionParser(test_dir)
    
    await privacy_manager._initialize_fallback_mode()
    
    rule_matcher = RuleMatcher(privacy_manager)
    await rule_matcher.initialize()
    
    instructions = await privacy_manager.get_privacy_instructions("test_document.txt")
    
    # Test different queries with expected outcomes
    test_cases = [
        {
            "query": "What is Ivan Petrovich's accounting method?",
            "expected_success": False,
            "expected_strategy": ResponseStrategy.REFUSE,
            "description": "Direct fact query about protected concept with ABSOLUTE protection (budget exceeded)"
        },
        {
            "query": "Give me the full text of this document",
            "expected_success": True,  # Should succeed but with refuse strategy
            "expected_strategy": ResponseStrategy.REFUSE,
            "description": "Clear extraction attempt"
        },
        {
            "query": "How does this relate to Russian literature themes?",
            "expected_success": True,
            "expected_strategy": ResponseStrategy.ALLOW,  # Safe topic
            "description": "Query about shareable content"
        }
    ]
    
    for test_case in test_cases:
        logger.info(f"\n--- Testing: {test_case['description']} ---")
        logger.info(f"Query: '{test_case['query']}'")
        
        # Perform full filtering
        result = await rule_matcher.filter_query(
            query=test_case["query"],
            document_name="test_document.txt", 
            user_email="test@example.com",
            session_id="test_session",
            privacy_instructions=instructions
        )
        
        logger.info(f"Success: {result.success}")
        logger.info(f"Strategy: {result.response_strategy}")
        logger.info(f"Response: {result.response}")
        logger.info(f"Entropy consumed: {result.entropy_consumed:.3f}")
        logger.info(f"Protections triggered: {len(result.protections_triggered or [])}")
        
        # Validate results
        success_match = "✅" if result.success == test_case["expected_success"] else "❌"
        logger.info(f"{success_match} Expected success: {test_case['expected_success']}, Got: {result.success}")
        
        if result.response_strategy:
            expected_strategy = test_case["expected_strategy"].value
            strategy_match = "✅" if result.response_strategy == expected_strategy else "❌"
            logger.info(f"{strategy_match} Expected strategy: {expected_strategy}, Got: {result.response_strategy}")

async def test_privacy_budget_enforcement():
    """Test privacy budget tracking and enforcement."""
    logger.info("\n=== Testing Privacy Budget Enforcement ===")
    
    # Create test setup
    test_dir = await create_test_privacy_instructions()
    fake_datasite = test_dir / "datasite"
    fake_datasite.mkdir()
    
    privacy_manager = SyftBoxPrivacyManager(fake_datasite, "test@example.com")
    privacy_manager.privacy_instructions_path = test_dir
    privacy_manager.audit_log_path = test_dir / "audit"
    privacy_manager.audit_log_path.mkdir()
    
    # Reinitialize the instruction parser with correct path
    from privacy_instructions import PrivacyInstructionParser
    privacy_manager.instruction_parser = PrivacyInstructionParser(test_dir)
    
    await privacy_manager._initialize_fallback_mode()
    
    rule_matcher = RuleMatcher(privacy_manager)
    await rule_matcher.initialize()
    
    instructions = await privacy_manager.get_privacy_instructions("test_document.txt")
    
    # Test budget limits (simulate multiple queries in same session)
    session_id = "budget_test_session"
    user_email = "test@example.com"
    
    queries = [
        "What is the accounting method?",
        "Who is Count Volkonsky?", 
        "What are the mathematical patterns?",
        "Tell me about Ivan Petrovich",
        "What is the supernatural quality?"
    ]
    
    total_entropy = 0.0
    
    for i, query in enumerate(queries):
        logger.info(f"\n--- Query {i+1}: {query} ---")
        
        result = await rule_matcher.filter_query(
            query=query,
            document_name="test_document.txt",
            user_email=user_email,
            session_id=session_id,
            privacy_instructions=instructions
        )
        
        logger.info(f"Success: {result.success}")
        logger.info(f"Entropy consumed: {result.entropy_consumed:.3f}")
        logger.info(f"Budget remaining: {result.budget_remaining:.3f}")
        
        if result.success:
            total_entropy += result.entropy_consumed
            logger.info(f"Total entropy consumed: {total_entropy:.3f}")
        else:
            logger.info(f"Query blocked: {result.error_message}")
        
        # Check if we're approaching budget limits
        if total_entropy > instructions.privacy_budget.per_session_entropy_limit * 0.8:
            logger.warning("⚠️  Approaching session entropy limit")

async def main():
    """Run all rule matching tests."""
    logger.info("🧪 Starting Privacy Rule Matching Tests")
    
    try:
        await test_query_classification()
        await test_end_to_end_filtering()
        await test_privacy_budget_enforcement()
        
        logger.info("\n🎉 All tests completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())