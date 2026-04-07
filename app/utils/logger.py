"""
Logging utility module
"""
import logging
import os
from app.config import Config


def setup_logger():
    """Setup and configure logger"""
    logging.basicConfig(
        filename=Config.LOG_FILE,
        level=getattr(logging, Config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    return logging.getLogger(__name__)

