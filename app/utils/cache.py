"""
Cache utility module
"""
from cachetools import TTLCache
from app.config import Config


def setup_cache():
    """Setup and configure cache"""
    return TTLCache(maxsize=Config.CACHE_MAX_SIZE, ttl=Config.CACHE_TTL)

