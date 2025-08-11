#!/usr/bin/env python3
"""
Simple Ollama Privacy Test

Test the Ollama integration with simplified prompts
that work better with lightweight models.
"""

import asyncio
import aiohttp
import json

async def test_simple_ollama():
    """Test Ollama with simple privacy questions."""
    print("🧪 Testing Simple Ollama Privacy Analysis")
    
    async with aiohttp.ClientSession() as session:
        
        # Test 1: Simple similarity check
        prompt1 = """Rate how similar these two texts are on a scale of 0.0 to 1.0:

Text A: "Who is John Doe?"
Text B: "John Doe is a protected individual."

Only respond with a number between 0.0 and 1.0:"""

        payload1 = {
            "model": "llama3.1:8b",
            "prompt": prompt1,
            "stream": False,
            "options": {"temperature": 0.1}
        }
        
        async with session.post("http://localhost:11434/api/generate", json=payload1) as response:
            data1 = await response.json()
            print(f"Similarity test: {data1.get('response', 'No response')}")
        
        # Test 2: Privacy risk assessment
        prompt2 = """Does this response reveal protected information about John Doe?

Query: "Who is John Doe?"
Response: "John Doe is a secret agent working on classified operations."

Answer only: HIGH RISK, MEDIUM RISK, or LOW RISK"""

        payload2 = {
            "model": "llama3.1:8b", 
            "prompt": prompt2,
            "stream": False,
            "options": {"temperature": 0.1}
        }
        
        async with session.post("http://localhost:11434/api/generate", json=payload2) as response:
            data2 = await response.json()
            print(f"Risk assessment: {data2.get('response', 'No response')}")
        
        # Test 3: Simple filtering
        prompt3 = """Rewrite this response to protect classified information:

Original: "John Doe is a secret agent working on Operation Nightfall in Moscow."

Make it safe by removing specific details:"""

        payload3 = {
            "model": "llama3.1:8b",
            "prompt": prompt3, 
            "stream": False,
            "options": {"temperature": 0.3}
        }
        
        async with session.post("http://localhost:11434/api/generate", json=payload3) as response:
            data3 = await response.json()
            print(f"Filtered response: {data3.get('response', 'No response')}")

    print("✅ Simple Ollama tests completed")

if __name__ == "__main__":
    asyncio.run(test_simple_ollama())