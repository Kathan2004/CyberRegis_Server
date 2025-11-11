# CyberRegis Server - Modular Architecture

This project has been refactored into a modular architecture for better maintainability and organization.

## Project Structure

```
CyberRegis_Server/
├── app/
│   ├── __init__.py          # Flask app initialization
│   ├── config.py            # Configuration and environment variables
│   ├── routes/              # API route blueprints
│   │   ├── __init__.py
│   │   ├── url_routes.py
│   │   ├── ip_routes.py
│   │   ├── chat_routes.py
│   │   ├── pcap_routes.py
│   │   ├── domain_routes.py
│   │   ├── security_routes.py
│   │   └── health_routes.py
│   ├── services/            # Business logic services
│   │   ├── __init__.py
│   │   ├── gemini_service.py
│   │   ├── telegram_service.py
│   │   ├── url_service.py
│   │   └── ip_service.py
│   ├── models/              # Data models
│   │   ├── __init__.py
│   │   ├── response_formatter.py
│   │   └── analysis_report.py
│   └── utils/               # Utility functions
│       ├── __init__.py
│       ├── logger.py
│       ├── cache.py
│       └── validators.py
├── .env                      # Environment variables (API keys)
├── .env.example              # Template for environment variables
├── .gitignore               # Git ignore file
├── run.py                    # Application entry point
├── requirements.txt          # Python dependencies
└── KALE.py                   # Legacy file (can be removed)

```

## Setup Instructions

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables**
   - Copy `.env.example` to `.env`
   - Fill in your API keys in the `.env` file:
     ```
     SAFE_BROWSING_KEY=your_key_here
     ABUSEIPDB_API_KEY=your_key_here
     GEMINI_API_KEY=your_key_here
     VIRUSTOTAL_API_KEY=your_key_here
     TELEGRAM_BOT_TOKEN=your_token_here
     TELEGRAM_CHAT_ID=your_chat_id_here
     ```

3. **Run the Application**
   ```bash
   python run.py
   ```
   Or use the legacy entry point:
   ```bash
   python KALE.py
   ```

## Key Features

### Modular Architecture
- **Routes**: Separated by functionality (URL, IP, Chat, PCAP, Domain, Security, Health)
- **Services**: Business logic separated from routes
- **Models**: Data models and formatters
- **Utils**: Reusable utility functions

### Environment Configuration
- All API keys moved to `.env` file
- Configuration loaded via `python-dotenv`
- Easy to manage different environments (dev, staging, prod)

### Benefits
1. **Maintainability**: Easy to locate and modify specific functionality
2. **Testability**: Services can be tested independently
3. **Scalability**: Easy to add new features without affecting existing code
4. **Security**: API keys not hardcoded in source files
5. **Organization**: Clear separation of concerns

## API Endpoints

All endpoints are prefixed with `/api`:

- `/api/check-url` - URL security check
- `/api/check-ip` - IP reputation check
- `/api/chat` - Chat with CyberRegis Assistant (Gemini AI)
- `/api/analyze-pcap` - PCAP file analysis
- `/api/analyze-domain` - Domain security analysis
- `/api/scan-ports` - Port scanning
- `/api/vulnerability-scan` - Vulnerability scanning
- `/api/ssl-analysis` - SSL/TLS analysis
- `/api/security-headers` - Security headers scan
- `/api/email-security` - Email security scan
- `/api/health` - Health check
- `/api/status` - System status
- `/api/monitoring-results` - Monitoring data

## Migration Notes

The old `KALE.py` file is still present for reference but can be removed once you've verified the new modular structure works correctly. All functionality has been migrated to the new structure.

