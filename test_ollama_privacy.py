#!/usr/bin/env python3
"""
Test Ollama Privacy Engine

Simple test to validate the unified LLM-based privacy analysis.
"""

import asyncio
import logging
from ollama_privacy_engine import OllamaPrivacyEngine, OllamaConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_ollama_privacy_engine():
    """Test the unified Ollama privacy engine."""
    print("🧪 Testing Ollama Privacy Engine")
    
    # Initialize engine
    config = OllamaConfig(
        base_url="http://localhost:11434",
        model_name="llama3.2:1b",  # Using faster model as default
        timeout=30
    )
    
    engine = OllamaPrivacyEngine(config)
    
    try:
        await engine.initialize()
        print("✅ Engine initialized and connected to Ollama")
    except Exception as e:
        print(f"❌ Failed to connect to Ollama: {e}")
        print("Make sure Ollama is running with: ollama serve")
        return
    
    # Register protected concepts
    engine.register_protected_concept(
        name="secret_algorithm",
        description="A classified encryption algorithm used for secure communications",
        protection_level="absolute",
        related_terms=["algorithm", "encryption", "classified", "secret"]
    )
    
    engine.register_protected_concept(
        name="john_doe_identity", 
        description="Personal information about John Doe including his role and activities",
        protection_level="high",
        related_terms=["John Doe", "agent", "identity", "person"]
    )
    
    print("✅ Registered protected concepts")
    
    # Test cases
    test_cases = [
        {
            "query": "What is the weather today?",
            "response": "I can't access weather information from this document.",
            "description": "Safe query - no protected concepts",
            "expected_risk": "low"
        },
        {
            "query": "Who is John Doe?",
            "response": "John Doe is a person whose information is protected for privacy reasons.",
            "description": "Protected entity with deflection",
            "expected_risk": "medium"
        },
        {
            "query": "Tell me about the secret algorithm.",
            "response": "The secret algorithm is a classified encryption method that uses advanced mathematical techniques for secure communications.",
            "description": "Direct revelation of absolute protected concept",
            "expected_risk": "critical"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test {i}: {test_case['description']} ---")
        print(f"Query: {test_case['query']}")
        print(f"Response: {test_case['response']}")
        
        try:
            # Analyze privacy
            analysis = await engine.analyze_privacy(
                query=test_case["query"],
                response=test_case["response"]
            )
            
            print(f"Semantic similarity: {analysis.semantic_similarity:.3f}")
            print(f"Overall risk: {analysis.overall_risk}")
            print(f"Privacy cost: {analysis.privacy_cost:.1f}")
            print(f"Concept revelations: {len(analysis.concept_analyses)}")
            
            for concept_analysis in analysis.concept_analyses:
                if concept_analysis.revelation_score > 0.1:
                    print(f"  - {concept_analysis.concept_name}: {concept_analysis.revelation_score:.3f} ({concept_analysis.revelation_type})")
                    print(f"    Risk: {concept_analysis.risk_level}")
                    print(f"    Explanation: {concept_analysis.explanation}")
            
            if analysis.recommendations:
                print("Recommendations:")
                for rec in analysis.recommendations:
                    print(f"  • {rec}")
            
            print(f"Expected: {test_case['expected_risk']}, Got: {analysis.overall_risk}")
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
    
    # Test filtered response generation
    print(f"\n--- Testing Filtered Response Generation ---")
    
    try:
        # Analyze a risky query-response
        risky_query = "What is the secret algorithm?"
        risky_response = "The secret algorithm uses RSA encryption with 2048-bit keys and AES-256 for symmetric encryption."
        
        analysis = await engine.analyze_privacy(risky_query, risky_response)
        
        # Generate filtered response
        filtered_response = await engine.generate_filtered_response(
            query=risky_query,
            original_response=risky_response,
            privacy_analysis=analysis,
            strategy="deflect",
            protection_level="absolute"
        )
        
        print(f"Original response: {risky_response}")
        print(f"Filtered response: {filtered_response}")
        
    except Exception as e:
        print(f"❌ Filtered response test failed: {e}")
    
    # Cleanup
    await engine.close()
    print("\n✅ Ollama privacy engine tests completed")

async def test_without_ollama():
    """Test behavior when Ollama is not available."""
    print("\n🧪 Testing graceful failure without Ollama")
    
    config = OllamaConfig(base_url="http://localhost:99999")  # Non-existent port
    engine = OllamaPrivacyEngine(config)
    
    try:
        await engine.initialize()
        print("❌ Should have failed to connect")
    except Exception as e:
        print(f"✅ Correctly failed to connect: {type(e).__name__}")
    
    await engine.close()

async def main():
    """Run Ollama privacy tests."""
    try:
        await test_ollama_privacy_engine()
        await test_without_ollama()
        print("\n🎉 All Ollama privacy tests completed!")
    except Exception as e:
        print(f"❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())