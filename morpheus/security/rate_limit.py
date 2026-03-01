import os
from datetime import datetime, timedelta
import asyncio
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Prevent abuse through rate limiting using Redis (with in-memory fallback)
    """
    
    def __init__(self):
        self.limits = {
            "scan": {"count": 100, "period": timedelta(hours=1)},
            "finding": {"count": 1000, "period": timedelta(hours=1)},
            "api": {"count": 1000, "period": timedelta(minutes=1)}
        }
        
        self.redis_url = os.environ.get("REDIS_URL")
        self.redis = None
        
        if self.redis_url:
            try:
                import redis.asyncio as redis_async
                self.redis = redis_async.from_url(self.redis_url)
                logger.info(f"Connected to Redis for rate limiting at {self.redis_url}")
            except ImportError:
                logger.warning("redis package not installed, falling back to in-memory rate limiting")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}, falling back to in-memory rate limiting")
                
        # In-memory fallback
        self._counts = {}
    
    async def check_limit(self, key: str, limit_type: str) -> bool:
        """Check if limit exceeded"""
        if limit_type not in self.limits:
            return True
            
        limit = self.limits[limit_type]
        
        if self.redis:
            return await self._check_redis_limit(key, limit_type, limit)
        else:
            return self._check_memory_limit(key, limit_type, limit)
            
    async def _check_redis_limit(self, key: str, limit_type: str, limit: dict) -> bool:
        """Check rate limits using Redis sorted sets (sliding window)"""
        redis_key = f"rate_limit:{limit_type}:{key}"
        now = datetime.now()
        window_start = now - limit["period"]
        
        try:
            # Atomic pipeline
            pipe = self.redis.pipeline()  # type: ignore
            # Remove old entries outside the window
            pipe.zremrangebyscore(redis_key, 0, window_start.timestamp())
            # Count elements inside the window
            pipe.zcard(redis_key)
            # Add current timestamp
            pipe.zadd(redis_key, {str(now.timestamp()): now.timestamp()})
            # Set expiry to the window length so it cleans up automatically
            pipe.expire(redis_key, int(limit["period"].total_seconds()))
            
            results = await pipe.execute()
            count = results[1] # Result of zcard
            
            return count < limit["count"]
        except Exception as e:
            logger.error(f"Redis rate limiting failed: {e}. Allowing request.")
            return True

    def _check_memory_limit(self, key: str, limit_type: str, limit: dict) -> bool:
        """Check rate limits using simple in-memory structure"""
        mem_key = f"{limit_type}:{key}"
        
        if mem_key not in self._counts:
            self._counts[mem_key] = []
            
        now = datetime.now()
        window_start = now - limit["period"]
        
        # Clean old timestamps
        self._counts[mem_key] = [t for t in self._counts[mem_key] if t > window_start]
        
        if len(self._counts[mem_key]) >= limit["count"]:
            return False
        
        # Increment
        self._counts[mem_key].append(now)
        
        return True
