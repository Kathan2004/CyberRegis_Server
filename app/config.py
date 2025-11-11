"""
Configuration module for loading environment variables
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration"""
    
    # API Keys
    SAFE_BROWSING_KEY = os.getenv('SAFE_BROWSING_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    # Gemini API Configuration
    GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    
    # Server Configuration
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    PORT = int(os.getenv('PORT', 4000))
    
    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000').split(',')
    
    # Rate Limiting
    RATE_LIMIT_PER_DAY = int(os.getenv('RATE_LIMIT_PER_DAY', 100))
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 10))
    
    # Cache Configuration
    CACHE_MAX_SIZE = int(os.getenv('CACHE_MAX_SIZE', 1000))
    CACHE_TTL = int(os.getenv('CACHE_TTL', 3600))
    
    # Logging Configuration
    LOG_FILE = os.getenv('LOG_FILE', 'security_checker.log')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Upload Directory
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    
    @staticmethod
    def validate():
        """Validate that required API keys are present"""
        required_keys = [
            'SAFE_BROWSING_KEY',
            'ABUSEIPDB_API_KEY',
            'GEMINI_API_KEY'
        ]
        missing_keys = []
        for key in required_keys:
            if not getattr(Config, key):
                missing_keys.append(key)
        
        if missing_keys:
            raise ValueError(f"Missing required API keys: {', '.join(missing_keys)}")
        
        return True

