"""
Gemini AI Service
"""
import requests
from typing import Optional
from app.config import Config
from app.utils.logger import setup_logger

logger = setup_logger()


class GeminiService:
    """Service for interacting with Gemini API"""
    
    def __init__(self):
        self.api_key = Config.GEMINI_API_KEY
        self.api_url = Config.GEMINI_API_URL
        self._cybersecurity_keywords = {
            "cyber", "security", "malware", "ransomware", "vulnerability",
            "threat", "phishing", "breach", "incident", "xss", "sql injection",
            "ddos", "cve", "exploit", "payload", "forensic", "forensics", "pentest",
            "penetration", "harden", "firewall", "ids", "ips", "log analysis",
            "encryption", "hash", "credential", "zero-day", "botnet", "command and control",
            "stego", "steganography", "osint", "threat hunting"
        }
        self._suspicious_keywords = {
            "exploit", "payload", "reverse shell", "ransomware", "ddos",
            "distributed denial", "backdoor", "keylogger", "trojan", "worm",
            "botnet", "c2", "command and control", "malware", "evil", "hack",
            "shellcode", "privilege escalation", "buffer overflow",
        }
    
    def generate_response(self, message: str, system_instruction: Optional[str] = None) -> str:
        """
        Generate a response from Gemini API
        
        Args:
            message: User message
            system_instruction: Optional system instruction
            
        Returns:
            Generated response text
        """
        normalized_message = message.lower()

        if not self._is_cybersecurity_related(normalized_message):
            return (
                "I’m CyberRegis Assistant and can only help with cybersecurity topics. "
                "Please rephrase your request so it relates to cyber defense, threat analysis, "
                "secure coding, incident response, or similar security work."
            )

        if not system_instruction:
            system_instruction = self._build_system_instruction(normalized_message)
        
        full_prompt = f"{system_instruction}\n\nUser question: {message}"
        
        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": self.api_key
        }
        
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": full_prompt
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 512
            }
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            
            response_data = response.json()
            
            if "candidates" in response_data and len(response_data["candidates"]) > 0:
                return response_data["candidates"][0]["content"]["parts"][0]["text"].strip()
            else:
                raise Exception("No response from Gemini API")
                
        except requests.RequestException as e:
            logger.error(f"Gemini API request error: {e}")
            error_message = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_message = error_detail.get("error", {}).get("message", str(e))
                except:
                    error_message = e.response.text if hasattr(e.response, 'text') else str(e)
            raise Exception(f"Gemini API error: {error_message}")

    def _is_cybersecurity_related(self, normalized_message: str) -> bool:
        """Simple heuristic to verify the prompt is within the cybersecurity domain."""
        return any(keyword in normalized_message for keyword in self._cybersecurity_keywords)

    def _is_high_risk_request(self, normalized_message: str) -> bool:
        """Detect potentially offensive or dual-use requests."""
        return any(keyword in normalized_message for keyword in self._suspicious_keywords)

    def _build_system_instruction(self, normalized_message: str) -> str:
        """Create a system instruction tailored to the request risk level."""
        base_instruction = (
            "You are CyberRegis Assistant, a cybersecurity expert. "
            "Answer only cybersecurity-related questions. "
            "Provide accurate, concise, and well-structured guidance focused on defensive, "
            "educational, or research purposes. "
            "Whenever you share code or command examples, wrap them in triple backticks with an appropriate "
            "language hint (for example ```bash) so the user can copy them from a terminal-style block. "
            "Use simple Markdown: bullet points with '-', headings with '##' only when helpful, "
            "and avoid excessive bold text."
        )

        if self._is_high_risk_request(normalized_message):
            caution_clause = (
                "Before presenting any potentially harmful or dual-use content, emit an advisory prefixed with "
                "'Advisory:' that stresses lawful, authorized, and controlled-environment usage. "
                "If code is requested, provide only minimal proof-of-concept snippets that support defensive "
                "testing, include inline comments noting safety precautions, and conclude with a reminder about "
                "strictly controlled lab deployment."
            )
            return f"{base_instruction} {caution_clause}"

        safe_clause = (
            "If a question drifts outside cybersecurity, politely decline and request a relevant topic instead. "
            "For benign security utilities (e.g., steganography, encryption demos), provide functional code or commands "
            "in the requested style while reinforcing responsible use."
        )
        return f"{base_instruction} {safe_clause}"

