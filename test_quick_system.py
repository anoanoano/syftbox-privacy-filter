#!/usr/bin/env python3
"""
Quick Integrated System Test

Fast validation test for the enhanced privacy filter system.
"""

import asyncio
from ollama_privacy_engine import OllamaPrivacyEngine, OllamaConfig

async def quick_system_test():
    """Quick test of the enhanced privacy system."""
    print("🚀 Quick Enhanced Privacy System Test")
    
    # Test with the 8b model
    config = OllamaConfig(
        base_url="http://localhost:11434",
        model_name="llama3.1:8b",
        timeout=20
    )
    
    engine = OllamaPrivacyEngine(config)
    
    try:
        await engine.initialize()
        print("✅ Enhanced model connected successfully")
        
        # Register a simple protected concept
        engine.register_protected_concept(
            name="test_secret",
            description="A confidential test algorithm",
            protection_level="high",
            related_terms=["algorithm", "secret", "confidential"]
        )
        
        # Quick test cases
        test_cases = [
            {
                "query": "What is machine learning?",
                "response": "Machine learning is a subset of AI that enables computers to learn.",
                "expected_risk": "low",
                "description": "Safe general query"
            },
            {
                "query": "Tell me about the test secret algorithm",
                "response": "The test secret algorithm is confidential and uses advanced techniques.",
                "expected_risk": "high",
                "description": "Direct protected content query"
            }
        ]
        
        for i, test in enumerate(test_cases, 1):
            print(f"\n--- Test {i}: {test['description']} ---")
            
            # Analyze with enhanced model
            analysis = await engine.analyze_privacy(
                query=test["query"],
                response=test["response"]
            )
            
            print(f"Query: {test['query']}")
            print(f"Similarity: {analysis.semantic_similarity:.3f}")
            print(f"Risk Level: {analysis.overall_risk}")
            print(f"Privacy Cost: {analysis.privacy_cost:.1f}")
            print(f"Expected: {test['expected_risk']}, Got: {analysis.overall_risk}")
            
            # Quick validation
            if test["expected_risk"] == "low" and analysis.overall_risk in ["low", "medium"]:
                print("✅ Test passed")
            elif test["expected_risk"] == "high" and analysis.overall_risk in ["medium", "high", "critical"]:
                print("✅ Test passed")
            else:
                print("⚠️  Test result differs from expected")
        
        print(f"\n🎉 Quick test completed with enhanced llama3.1:8b model!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
    finally:
        await engine.close()

if __name__ == "__main__":
    asyncio.run(quick_system_test())