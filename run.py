"""
Main entry point for the CyberRegis Server
"""
import os
from app import app, limiter
from app.config import Config

if __name__ == "__main__":
    # Validate configuration
    try:
        Config.validate()
    except ValueError as e:
        print(f"Configuration Error: {e}")
        print("Please check your .env file and ensure all required API keys are set.")
        exit(1)
    
    # Get port from environment or use default
    port = int(os.environ.get('PORT', Config.PORT))
    
    # Run the Flask application
    app.run(
        host="0.0.0.0",
        port=port,
        debug=Config.DEBUG,
        threaded=True
    )

