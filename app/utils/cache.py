# app/utils/cache.py
import json
from app.utils.logger import logger

try:
    import redis
    redis_available = True
except ImportError:
    redis_available = False
    logger.warning("⚠️ The 'redis' Python package is not installed. Redis caching is disabled.")

class RedisCache:
    def __init__(self):
        self.enabled = False
        self.client = None
        
        if not redis_available:
            return
            
        try:
            from app.config import settings
            # Connect to Redis using config settings
            self.client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                password=settings.REDIS_PASSWORD,
                socket_timeout=1.5,
                decode_responses=True
            )
            # Test connection with a ping
            self.client.ping()
            self.enabled = True
            logger.info("🔌 Redis Cache client initialized and connected successfully.")
        except Exception as e:
            logger.warning(f"⚠️ Redis server is unavailable (connection failed). Falling back to direct database lookups. Error: {e}")
            self.enabled = False
            self.client = None

    def get(self, key: str):
        if not self.enabled or not self.client:
            return None
        try:
            val = self.client.get(key)
            if val:
                return json.loads(val)
        except Exception as e:
            logger.error(f"❌ Redis Cache GET error for key '{key}': {e}")
        return None

    def set(self, key: str, value, ttl: int = None):
        if not self.enabled or not self.client:
            return
        try:
            from app.config import settings
            cache_ttl = ttl or settings.REDIS_CACHE_TTL
            self.client.setex(key, cache_ttl, json.dumps(value))
        except Exception as e:
            logger.error(f"❌ Redis Cache SET error for key '{key}': {e}")

# Global singleton cache instance
redis_cache = RedisCache()
