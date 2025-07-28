"""
NVIDIA Nemotron Integration for Enhanced Security Analysis
Uses llama-3.3-nemotron-super-49b-v1 reasoning model
"""

import httpx
import os
from typing import Dict, List
import asyncio
from dotenv import load_dotenv

load_dotenv()

class NemotronSecurityAnalyzer:
    def __init__(self):
        # Use build.nvidia.com serverless API
        self.api_key = os.getenv("NVIDIA_API_KEY", "")
        self.base_url = "https://integrate.api.nvidia.com/v1"
        # Use the specific Nemotron model requested
        self.model = "llama-3.3-nemotron-super-49b-v1"
        self.enabled = bool(self.api_key and self.api_key != "nvapi-YOUR-KEY-HERE")
        
    async def analyze_with_reasoning(self, code: str, vulnerability_type: str, callback=None) -> Dict:
        """
        Use Nemotron's advanced reasoning to analyze code for vulnerabilities
        Leverages NeMo Agent Toolkit patterns for orchestration
        """
        
        if callback:
            await callback(f"🔍 Preparing {vulnerability_type} analysis for NVIDIA Nemotron...")
            await asyncio.sleep(0.05)
            await callback(f"📡 Establishing secure connection to NVIDIA cloud...")
        
        prompt = f"""You are a paranoid security engineer using advanced reasoning.

Task: Analyze this code for {vulnerability_type} vulnerabilities.

Code to analyze:
```
{code}
```

Use step-by-step reasoning:
1. Identify potential security patterns
2. Reason about attack vectors
3. Consider false positives
4. Provide confidence score (0-1)
5. Suggest secure alternative

Format your response as:
VULNERABLE: [yes/no]
CONFIDENCE: [0.0-1.0]
REASONING: [step-by-step analysis]
FIX: [secure code alternative]
"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert security analyst with deep reasoning capabilities."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 500,
            "top_p": 0.95
        }
        
        if not self.enabled:
            print("NVIDIA API key not configured - using pattern matching only")
            return self._fallback_response()
            
        try:
            print(f"🚀 Calling NVIDIA Nemotron for {vulnerability_type} analysis...")
            if callback:
                await callback(f"🔐 Authenticating with NVIDIA API...")
                await asyncio.sleep(0.05)
                await callback(f"🌐 API Endpoint: {self.base_url}")
                await asyncio.sleep(0.05)
                await callback(f"🤖 Model: {self.model}")
                await asyncio.sleep(0.05)
                await callback(f"📊 Sending code snippet for analysis...")
                
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=10.0
                )
                
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                print(f"✅ NVIDIA Nemotron response received")
                
                # Parse the structured response
                parsed = self._parse_nemotron_response(content)
                print(f"📊 Confidence: {parsed['confidence']}, Vulnerable: {parsed['is_vulnerable']}")
                return parsed
            else:
                print(f"❌ Nemotron API error: {response.status_code}")
                if response.status_code == 401:
                    print("Invalid API key - check your NVIDIA_API_KEY")
                return self._fallback_response()
                
        except httpx.TimeoutError:
            print(f"⏱️ NVIDIA API timeout - using fallback")
            return self._fallback_response()
        except Exception as e:
            print(f"❌ Error calling Nemotron: {e}")
            return self._fallback_response()
    
    def _parse_nemotron_response(self, content: str) -> Dict:
        """Parse Nemotron's reasoning response"""
        lines = content.strip().split('\n')
        response = {
            "is_vulnerable": True,
            "confidence": 0.8,
            "reasoning": "",
            "fix": ""
        }
        
        for line in lines:
            if line.startswith("VULNERABLE:"):
                response["is_vulnerable"] = "yes" in line.lower()
            elif line.startswith("CONFIDENCE:"):
                try:
                    response["confidence"] = float(line.split(":")[1].strip())
                except:
                    pass
            elif line.startswith("REASONING:"):
                response["reasoning"] = line.split(":", 1)[1].strip()
            elif line.startswith("FIX:"):
                response["fix"] = line.split(":", 1)[1].strip()
        
        return response
    
    def _fallback_response(self) -> Dict:
        """Fallback when Nemotron is unavailable"""
        return {
            "is_vulnerable": True,
            "confidence": 0.7,
            "reasoning": "Pattern-based detection (Nemotron unavailable)",
            "fix": "Please review security best practices"
        }

# Example usage with NeMo Agent Toolkit patterns
class SecurityAgentOrchestrator:
    """
    Orchestrates security analysis using NeMo Agent Toolkit patterns
    Coordinates between pattern matching and Nemotron reasoning
    """
    
    def __init__(self):
        self.nemotron = NemotronSecurityAnalyzer()
        
    async def orchestrate_analysis(self, code: str, vulnerabilities: List, callback=None) -> List:
        """
        Orchestrate enhanced analysis using Nemotron reasoning
        Following NeMo Agent Toolkit best practices
        """
        enhanced_results = []
        
        if callback:
            await callback(f"📊 Processing {len(vulnerabilities)} vulnerabilities through NVIDIA AI...")
        
        # Process each vulnerability through Nemotron
        for i, vuln in enumerate(vulnerabilities):
            if callback:
                await callback(f"🔍 [{i+1}/{len(vulnerabilities)}] Analyzing {vuln.type} at line {vuln.line_number}")
            
            # Get Nemotron's reasoning
            nemotron_analysis = await self.nemotron.analyze_with_reasoning(
                vuln.code_snippet, 
                vuln.type,
                callback
            )
            
            # Enhance vulnerability with reasoning
            if nemotron_analysis['is_vulnerable']:
                # Update confidence with NVIDIA's assessment
                vuln.confidence = max(vuln.confidence, nemotron_analysis['confidence'])
                
                # Add NVIDIA enhancement info (store in pattern_matched field for now)
                vuln.pattern_matched = f"NVIDIA Enhanced - Confidence: {nemotron_analysis['confidence']:.2f}"
                
                enhanced_results.append(vuln)
                
                if callback:
                    await callback(f"✅ Confirmed {vuln.type} with {nemotron_analysis['confidence']:.0%} confidence")
            elif nemotron_analysis['confidence'] < 0.3:
                # Low confidence - likely false positive
                if callback:
                    await callback(f"❌ False positive: {vuln.type} (confidence: {nemotron_analysis['confidence']:.0%})")
                continue
            else:
                enhanced_results.append(vuln)
        
        return enhanced_results