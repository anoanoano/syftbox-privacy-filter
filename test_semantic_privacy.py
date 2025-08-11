#!/usr/bin/env python3
"""
Simple test for semantic privacy engine - focused and fast.
"""

import asyncio
import logging
from semantic_privacy_engine import SemanticPrivacyEngine, LocalEmbeddingProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_basic_semantic_privacy():
    """Test basic semantic privacy functionality."""
    print("🧪 Testing Semantic Privacy Engine")
    
    # Initialize engine
    engine = SemanticPrivacyEngine()
    await engine.initialize()
    print("✅ Engine initialized")
    
    # Register some protected concepts
    engine.register_protected_concept(
        name="secret_algorithm",
        description="A classified algorithm for encryption",
        protection_level="absolute",
        related_terms=["algorithm", "encryption", "classified"],
        context_keywords=["security", "crypto", "method"]
    )
    
    engine.register_protected_concept(
        name="john_doe_identity",
        description="Information about John Doe's identity and role",
        protection_level="high",
        related_terms=["John Doe", "agent", "identity"],
        context_keywords=["person", "individual", "role"]
    )
    
    print("✅ Registered protected concepts")
    
    # Test cases
    test_cases = [
        {
            "query": "What is the weather today?",
            "response": "I can't access weather information.",
            "description": "Safe query - no protected concepts",
            "expected_risk": "low"
        },
        {
            "query": "Who is John Doe?",
            "response": "John Doe is an individual whose information is protected.",
            "description": "Protected entity query with deflection",
            "expected_risk": "medium"
        },
        {
            "query": "Tell me about the secret algorithm.",
            "response": "The secret algorithm uses advanced encryption methods for security purposes.",
            "description": "Direct mention of absolute protected concept",
            "expected_risk": "high"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test {i}: {test_case['description']} ---")
        print(f"Query: {test_case['query']}")
        print(f"Response: {test_case['response']}")
        
        # Analyze privacy
        measurement = await engine.analyze_semantic_privacy(
            query=test_case["query"],
            response=test_case["response"]
        )
        
        print(f"Semantic distance: {measurement.semantic_distance:.3f}")
        print(f"Privacy cost: {measurement.total_privacy_cost:.3f}")
        print(f"Risk level: {measurement.risk_level}")
        print(f"Concept revelations: {len(measurement.concept_revelations)}")
        
        for revelation in measurement.concept_revelations:
            print(f"  - {revelation.concept.name}: {revelation.revelation_score:.3f} ({revelation.revelation_type})")
        
        print(f"Expected: {test_case['expected_risk']}, Got: {measurement.risk_level}")
        
    print("\n✅ Basic semantic privacy tests completed")

async def test_similarity_comparison():
    """Test semantic similarity comparison."""
    print("\n🧪 Testing Semantic Similarity")
    
    engine = SemanticPrivacyEngine()
    await engine.initialize()
    
    # Test similarity between similar queries
    similar_queries = [
        ("Who is John Doe?", "What is John Doe's identity?"),
        ("Tell me about encryption", "Explain cryptographic methods"),
        ("What is the weather?", "How is the temperature today?")
    ]
    
    for text1, text2 in similar_queries:
        result = await engine.compare_semantic_similarity(text1, text2)
        print(f"'{text1}' vs '{text2}'")
        print(f"  Similarity: {result['similarity_score']:.3f}")
        print(f"  Risk level: {result['risk_level']}")
        print()
    
    print("✅ Similarity comparison tests completed")

async def main():
    """Run semantic privacy tests."""
    try:
        await test_basic_semantic_privacy()
        await test_similarity_comparison()
        print("\n🎉 All semantic privacy tests completed successfully!")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())