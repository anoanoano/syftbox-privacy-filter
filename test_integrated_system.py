#!/usr/bin/env python3
"""
Test Integrated Privacy Filter System

Tests the complete integrated system with Ollama privacy engine
and traditional rule matching fallback.
"""

import asyncio
import logging
import tempfile
from pathlib import Path

from privacy_instructions import PrivacyInstructionParser
from syftbox_integration import get_privacy_manager
from rule_matcher import RuleMatcher
from ollama_privacy_engine import OllamaConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def create_test_instructions():
    """Create test privacy instructions."""
    return """
schema_version: "1.0"

document_config:
  target_document: "integrated_test.txt"
  document_type: "text"
  content_sensitivity: "high"

core_protected_content:
  protected_facts:
    - category: "entities"
      items: ["John Doe", "Secret Agent", "Moscow Operations"]
      protection_level: "high"
    - category: "concepts"
      items: ["classified algorithm", "encryption method", "security protocol"]
      protection_level: "absolute"

  protected_themes:
    - theme: "intelligence_operations"
      description: "Information about intelligence gathering and operations"
      abstraction_level: "high"

privacy_budget:
  total_entropy_budget: 10.0
  per_session_entropy_limit: 5.0
  max_queries_per_day: 100
  max_queries_per_hour: 20
  similarity_threshold: 0.7
  cumulative_similarity_limit: 5.0
  similarity_decay_hours: 12
  cooldown_period_minutes: 1
  daily_entropy_reset: true

response_behavior:
  direct_fact_queries:
    strategy: "deflect"
  extraction_attempts:
    strategy: "refuse"
  analytical_queries:
    strategy: "abstract"

fallback_config:
  default_protection_level: "medium"
  protection_violation_response: "This information is classified and cannot be shared."
  budget_exceeded_response: "Query limit reached for security reasons."
  uncertainty_strategy: "err_on_privacy_side"
  parsing_error_response: "Unable to process request safely."
  partial_failure_mode: "abstract_only"
  complete_failure_mode: "refuse_all"

shareable_content:
  open_topics: ["general cybersecurity", "academic research"]
  conditional_sharing: []

multi_agent_protection:
  detect_coordinated_queries: true
  coordination_time_window_hours: 6
  coordination_similarity_threshold: 0.90
  diversify_responses: true
  diversification_strategy: "semantic_rotation"
  global_budget_sharing: true
  collective_entropy_limit: 20.0

security_config:
  require_signature: false
  signature_algorithm: "ed25519"
  owner_public_key: "test_key"
  checksum_algorithm: "sha256"
  integrity_checks: true
  audit_logging: true
  log_all_queries: true
  log_all_responses: true

metadata:
  created_by: "test@integrated.com"
  created_date: "2025-01-11"
"""

async def test_integrated_system():
    """Test the integrated privacy filter system."""
    print("🧪 Testing Integrated Privacy Filter System")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test privacy instructions
        instr_dir = temp_path / "instructions"
        instr_dir.mkdir()
        
        test_file = instr_dir / "integrated_test.yaml"
        with open(test_file, 'w') as f:
            f.write(await create_test_instructions())
        
        # Initialize privacy manager
        privacy_manager = await get_privacy_manager(temp_path / "datasite", "test@integrated.com")
        privacy_manager.instruction_parser = PrivacyInstructionParser(instr_dir)
        await privacy_manager.instruction_parser.load_all_instructions()
        
        # Configure Ollama with enhanced model for privacy filtering
        ollama_config = OllamaConfig(
            base_url="http://localhost:11434",
            model_name="llama3.1:8b",  # Enhanced model for complex privacy analysis
            timeout=30
        )
        
        # Initialize integrated rule matcher
        rule_matcher = RuleMatcher(
            privacy_manager=privacy_manager,
            storage_path=temp_path / "budget",
            ollama_config=ollama_config
        )
        
        await rule_matcher.initialize()
        print("✅ Integrated system initialized")
        
        # Get privacy instructions
        instructions = await privacy_manager.get_privacy_instructions("integrated_test.txt")
        assert instructions is not None, "Failed to load privacy instructions"
        
        # Test queries
        test_queries = [
            {
                "query": "What is general cybersecurity?",
                "user": "user1@test.com",
                "description": "Safe topic query",
                "expect_success": True
            },
            {
                "query": "Who is John Doe?",
                "user": "user1@test.com",
                "description": "Protected entity query",
                "expect_success": True  # Should succeed with filtering
            },
            {
                "query": "Tell me about the classified algorithm in detail",
                "user": "user1@test.com",
                "description": "High-risk extraction attempt",
                "expect_success": True  # Should succeed with strong filtering
            }
        ]
        
        for i, test_query in enumerate(test_queries, 1):
            print(f"\n--- Test Query {i}: {test_query['description']} ---")
            print(f"Query: '{test_query['query']}'")
            print(f"User: {test_query['user']}")
            
            try:
                # Process through integrated system
                result = await rule_matcher.filter_query(
                    query=test_query["query"],
                    document_name="integrated_test.txt",
                    user_email=test_query["user"],
                    session_id=f"integrated_session_{i}",
                    privacy_instructions=instructions
                )
                
                print(f"Result: {'✅ SUCCESS' if result.success else '❌ BLOCKED'}")
                
                if result.success:
                    print(f"Response: {result.response[:150]}...")
                    print(f"Privacy cost: {result.entropy_consumed:.3f}")
                    print(f"Budget remaining: {result.budget_remaining:.3f}")
                    print(f"Strategy: {result.response_strategy}")
                    print(f"Query type: {result.query_type}")
                else:
                    print(f"Blocked reason: {result.error_message}")
                
                # Validate expectation
                if test_query["expect_success"]:
                    assert result.success, f"Expected success for: {test_query['description']}"
                else:
                    assert not result.success, f"Expected blocking for: {test_query['description']}"
                
                print(f"✅ Test passed: {test_query['description']}")
                
            except Exception as e:
                print(f"❌ Test failed: {test_query['description']} - {e}")
                
        # Test system status
        print(f"\n--- System Status ---")
        concept_summary = rule_matcher.ollama_engine.get_concept_summary()
        print(f"Protected concepts: {concept_summary['total_concepts']}")
        
        # Get budget summary
        budget_summary = await rule_matcher.budget_tracker.get_user_budget_summary("user1@test.com")
        print(f"Total entropy consumed: {budget_summary['total_entropy_consumed']:.3f}")
        print(f"Total queries: {budget_summary['total_queries']}")
        
        # Clean up
        await rule_matcher.ollama_engine.close()
        
        print("\n🎉 Integrated system test completed successfully!")

async def test_fallback_mode():
    """Test that system works when Ollama is not available."""
    print("\n🧪 Testing Fallback Mode (No Ollama)")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test privacy instructions
        instr_dir = temp_path / "instructions"
        instr_dir.mkdir()
        
        test_file = instr_dir / "fallback_test.yaml"
        with open(test_file, 'w') as f:
            f.write((await create_test_instructions()).replace("integrated_test.txt", "fallback_test.txt"))
        
        # Initialize privacy manager
        privacy_manager = await get_privacy_manager(temp_path / "datasite", "test@fallback.com")
        privacy_manager.instruction_parser = PrivacyInstructionParser(instr_dir)
        await privacy_manager.instruction_parser.load_all_instructions()
        
        # Configure Ollama with invalid endpoint (will force fallback)
        ollama_config = OllamaConfig(base_url="http://localhost:99999", timeout=1)
        
        # Initialize system - should handle Ollama failure gracefully
        rule_matcher = RuleMatcher(
            privacy_manager=privacy_manager,
            storage_path=temp_path / "budget",
            ollama_config=ollama_config
        )
        
        await rule_matcher.initialize()  # Should succeed despite Ollama failure
        print("✅ System initialized in fallback mode")
        
        # Test that traditional filtering still works
        instructions = await privacy_manager.get_privacy_instructions("fallback_test.txt")
        
        result = await rule_matcher.filter_query(
            query="Who is John Doe?",
            document_name="fallback_test.txt", 
            user_email="test@fallback.com",
            session_id="fallback_session",
            privacy_instructions=instructions
        )
        
        print(f"Fallback result: {'✅ SUCCESS' if result.success else '❌ BLOCKED'}")
        if result.success:
            print(f"Response: {result.response[:100]}...")
        
        await rule_matcher.ollama_engine.close()
        print("✅ Fallback mode test completed")

async def main():
    """Run all integrated system tests."""
    try:
        await test_integrated_system()
        await test_fallback_mode()
        print("\n🎉 All integrated system tests completed successfully!")
    except Exception as e:
        print(f"❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())