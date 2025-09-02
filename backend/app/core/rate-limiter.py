"""
Rate Limiter Module for Fraud Detection System

This module provides comprehensive rate limiting functionality including
sliding window, token bucket, and fixed window algorithms. It supports
distributed rate limiting using Redis and includes advanced features
like burst handling, dynamic limits, and rate limit analytics.
"""

import time
import json
import math
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from functools import wraps
import asyncio
import structlog

# Local imports
from ..core import cache_manager, settings
from ..models.security import RateLimitRule, RateLimitViolation

logger = structlog.get_logger(__name__)

class RateLimitAlgorithm(Enum):
    """Rate limiting algorithms"""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"

class RateLimitScope(Enum):
    """Rate limit scopes"""
    GLOBAL = "global"
    USER = "user"
    IP = "ip"
    API_KEY = "api_key"
    ENDPOINT = "endpoint"
    CUSTOM = "custom"

class RateLimitAction(Enum):
    """Actions to take when rate limit is exceeded"""
    BLOCK = "block"
    THROTTLE = "throttle"
    LOG_ONLY = "log_only"
    CAPTCHA = "captcha"

@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    limit: int
    window: int  # seconds
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    scope: RateLimitScope = RateLimitScope.IP
    action: RateLimitAction = RateLimitAction.BLOCK
    burst_limit: Optional[int] = None
    burst_window: Optional[int] = None
    grace_period: int = 0
    enabled: bool = True
    description: str = ""

@dataclass
class RateLimitResult:
    """Rate limit check result"""
    allowed: bool
    limit: int
    remaining: int
    reset_time: datetime
    retry_after: Optional[int] = None
    current_usage: int = 0
    algorithm: str = ""
    scope: str = ""
    key: str = ""

class RateLimitError(Exception):
    """Rate limit exceeded exception"""
    
    def __init__(self, message: str, result: RateLimitResult):
        super().__init__(message)
        self.result = result

class FixedWindowRateLimiter:
    """Fixed window rate limiting implementation"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def check_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check rate limit using fixed window algorithm"""
        window_start = int(time.time() // config.window) * config.window
        cache_key = f"rate_limit:fixed:{key}:{window_start}"
        
        try:
            # Get current count
            current_count = self.redis.get(cache_key)
            current_count = int(current_count) if current_count else 0
            
            # Calculate reset time
            reset_time = datetime.fromtimestamp(window_start + config.window)
            
            # Check if limit exceeded
            if current_count >= config.limit:
                return RateLimitResult(
                    allowed=False,
                    limit=config.limit,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=int((reset_time - datetime.now()).total_seconds()),
                    current_usage=current_count,
                    algorithm=config.algorithm.value,
                    scope=config.scope.value,
                    key=key
                )
            
            # Increment counter
            pipe = self.redis.pipeline()
            pipe.incr(cache_key)
            pipe.expire(cache_key, config.window)
            results = pipe.execute()
            
            new_count = results[0]
            
            return RateLimitResult(
                allowed=True,
                limit=config.limit,
                remaining=max(0, config.limit - new_count),
                reset_time=reset_time,
                current_usage=new_count,
                algorithm=config.algorithm.value,
                scope=config.scope.value,
                key=key
            )
            
        except Exception as e:
            logger.error("Fixed window rate limit check failed", key=key, error=str(e))
            # Fail open - allow request if Redis is down
            return RateLimitResult(
                allowed=True,
                limit=config.limit,
                remaining=config.limit,
                reset_time=datetime.now() + timedelta(seconds=config.window),
                algorithm=config.algorithm.value,
                scope=config.scope.value,
                key=key
            )

class SlidingWindowRateLimiter:
    """Sliding window rate limiting implementation"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def check_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check rate limit using sliding window algorithm"""
        now = time.time()
        window_start = now - config.window
        cache_key = f"rate_limit:sliding:{key}"
        
        try:
            pipe = self.redis.pipeline()
            
            # Remove expired entries
            pipe.zremrangebyscore(cache_key, 0, window_start)
            
            # Count current entries
            pipe.zcard(cache_key)
            
            # Add current request
            pipe.zadd(cache_key, {str(now): now})
            
            # Set expiration
            pipe.expire(cache_key, config.window)
            
            results = pipe.execute()
            current_count = results[1]
            
            # Calculate reset time (when oldest entry expires)
            oldest_entries = self.redis.zrange(cache_key, 0, 0, withscores=True)
            if oldest_entries:
                oldest_time = oldest_entries[0][1]
                reset_time = datetime.fromtimestamp(oldest_time + config.window)
            else:
                reset_time = datetime.now() + timedelta(seconds=config.window)
            
            # Check if limit exceeded (including current request)
            if current_count >= config.limit:
                # Remove the request we just added since it's not allowed
                self.redis.zrem(cache_key, str(now))
                
                return RateLimitResult(
                    allowed=False,
                    limit=config.limit,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=int((reset_time - datetime.now()).total_seconds()),
                    current_usage=current_count,
                    algorithm=config.algorithm.value,
                    scope=config.scope.value,
                    key=key
                )
            
            return RateLimitResult(
                allowed=True,
                limit=config.limit,
                remaining=max(0, config.limit - current_count - 1),
                reset_time=reset_time,
                current_usage=current_count + 1,
                algorithm=config.algorithm.value,
                scope=config.scope.value,
                key=key
            )
            
        except Exception as e:
            logger.error("Sliding window rate limit check failed", key=key, error=str(e))
            # Fail open
            return RateLimitResult(
                allowed=True,
                limit=config.limit,
                remaining=config.limit,
                reset_time=datetime.now() + timedelta(seconds=config.window),
                algorithm=config.algorithm.value,
                scope=config.scope.value,
                key=key
            )

class TokenBucketRateLimiter:
    """Token bucket rate limiting implementation"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def check_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check rate limit using token bucket algorithm"""
        cache_key = f"rate_limit:token_bucket:{key}"
        now = time.time()
        
        try:
            # Get current bucket state
            bucket_data = self.redis.get(cache_key)
            
            if bucket_data:
                bucket = json.loads(bucket_data)
                tokens = bucket['tokens']
                last_refill = bucket['last_refill']
            else:
                tokens = config.limit
                last_refill = now
            
            # Calculate tokens to add based on time elapsed
            time_elapsed = now - last_refill
            refill_rate = config.limit / config.window  # tokens per second
            tokens_to_add = time_elapsed * refill_rate
            
            # Update token count (cap at limit)
            tokens = min(config.limit, tokens + tokens_to_add)
            
            # Calculate reset time (when bucket will be full)
            if tokens < config.limit:
                seconds_to_full = (config.limit - tokens) / refill_rate
                reset_time = datetime.fromtimestamp(now + seconds_to_full)
            else:
                reset_time = datetime.now()
            
            # Check if request can be allowed
            if tokens >= 1:
                # Allow request and consume token
                tokens -= 1
                
                # Update bucket state
                bucket_state = {
                    'tokens': tokens,
                    'last_refill': now
                }
                self.redis.setex(cache_key, config.window * 2, json.dumps(bucket_state))
                
                return RateLimitResult(
                    allowed=True,
                    limit=config.limit,
                    remaining=int(tokens),
                    reset_time=reset_time,
                    current_usage=config.limit - int(tokens),
                    algorithm=config.algorithm.value,
                    scope=config.scope.value,
                    key=key
                )
            else:
                # Not enough tokens
                retry_after = int(1 / refill_rate) if refill_rate > 0 else config.window
                
                return RateLimitResult(
                    allowed=False,
                    limit=config.limit,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after,
                    current_usage=config.limit,
                    algorithm=config.algorithm.value,
                    scope=config.scope.value,
                    key=key
                )
                
        except Exception as e:
            logger.error("Token bucket rate limit check failed", key=key, error=str(e))
            # Fail open
            return RateLimitResult(
                allowed=True,
                limit=config.limit,
                remaining=config.limit,
                reset_time=datetime.now() + timedelta(seconds=config.window),
                algorithm=config.algorithm.value,
                scope=config.scope.value,
                key=key
            )

class LeakyBucketRateLimiter:
    """Leaky bucket rate limiting implementation"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def check_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check rate limit using leaky bucket algorithm"""
        cache_key = f"rate_limit:leaky_bucket:{key}"
        now = time.time()
        
        try:
            # Get current bucket state
            bucket_data = self.redis.get(cache_key)
            
            if bucket_data:
                bucket = json.loads(bucket_data)
                volume = bucket['volume']
                last_leak = bucket['last_leak']
            else:
                volume = 0
                last_leak = now
            
            # Calculate volume leaked since last check
            time_elapsed = now - last_leak
            leak_rate = config.limit / config.window  # requests per second that can leak
            volume_leaked = time_elapsed * leak_rate
            
            # Update volume (can't go below 0)
            volume = max(0, volume - volume_leaked)
            
            # Check if bucket can accept new request
            if volume < config.limit:
                # Accept request
                volume += 1
                
                # Update bucket state
                bucket_state = {
                    'volume': volume,
                    'last_leak': now
                }
                self.redis.setex(cache_key, config.window * 2, json.dumps(bucket_state))
                
                # Calculate reset time (when bucket will be empty)
                if volume > 0:
                    seconds_to_empty = volume / leak_rate
                    reset_time = datetime.fromtimestamp(now + seconds_to_empty)
                else:
                    reset_time = datetime.now()
                
                return RateLimitResult(
                    allowed=True,
                    limit=config.limit,
                    remaining=max(0, config.limit - int(volume)),
                    reset_time=reset_time,
                    current_usage=int(volume),
                    algorithm=config.algorithm.value,
                    scope=config.scope.value,
                    key=key
                )
            else:
                # Bucket is full
                seconds_to_space = 1 / leak_rate if leak_rate > 0 else config.window
                retry_after = int(seconds_to_space)
                
                reset_time = datetime.fromtimestamp(now + volume / leak_rate)
                
                return RateLimitResult(
                    allowed=False,
                    limit=config.limit,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after,
                    current_usage=config.limit,
                    algorithm=config.algorithm.value,
                    scope=config.scope.value,
                    key=key
                )
                
        except Exception as e:
            logger.error("Leaky bucket rate limit check failed", key=key, error=str(e))
            # Fail open
            return RateLimitResult(
                allowed=True,
                limit=config.limit,
                remaining=config.limit,
                reset_time=datetime.now() + timedelta(seconds=config.window),
                algorithm=config.algorithm.value,
                scope=config.scope.value,
                key=key
            )

class AdvancedRateLimiter:
    """Advanced rate limiter with multiple algorithms and features"""
    
    def __init__(self):
        self.redis = cache_manager.redis_client
        self.algorithms = {
            RateLimitAlgorithm.FIXED_WINDOW: FixedWindowRateLimiter(self.redis),
            RateLimitAlgorithm.SLIDING_WINDOW: SlidingWindowRateLimiter(self.redis),
            RateLimitAlgorithm.TOKEN_BUCKET: TokenBucketRateLimiter(self.redis),
            RateLimitAlgorithm.LEAKY_BUCKET: LeakyBucketRateLimiter(self.redis)
        }
        
        # Default configurations for different scopes
        self.default_configs = {
            "api_general": RateLimitConfig(
                limit=1000,
                window=3600,  # 1 hour
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.IP
            ),
            "api_auth": RateLimitConfig(
                limit=5,
                window=300,  # 5 minutes
                algorithm=RateLimitAlgorithm.FIXED_WINDOW,
                scope=RateLimitScope.IP,
                action=RateLimitAction.BLOCK
            ),
            "transaction_processing": RateLimitConfig(
                limit=100,
                window=60,  # 1 minute
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
                scope=RateLimitScope.USER,
                burst_limit=10,
                burst_window=10
            ),
            "fraud_analysis": RateLimitConfig(
                limit=50,
                window=60,
                algorithm=RateLimitAlgorithm.LEAKY_BUCKET,
                scope=RateLimitScope.GLOBAL
            )
        }
    
    def check_rate_limit(self, identifier: str, config_name: str = "api_general", 
                        custom_config: Optional[RateLimitConfig] = None) -> RateLimitResult:
        """Check rate limit for given identifier"""
        
        # Get configuration
        if custom_config:
            config = custom_config
        else:
            config = self.default_configs.get(config_name)
            if not config:
                raise ValueError(f"Unknown rate limit configuration: {config_name}")
        
        if not config.enabled:
            return RateLimitResult(
                allowed=True,
                limit=config.limit,
                remaining=config.limit,
                reset_time=datetime.now() + timedelta(seconds=config.window),
                algorithm=config.algorithm.value,
                scope=config.scope.value,
                key=identifier
            )
        
        # Generate cache key
        cache_key = self._generate_key(identifier, config_name, config.scope)
        
        # Check burst limit first if configured
        if config.burst_limit and config.burst_window:
            burst_result = self._check_burst_limit(cache_key, config)
            if not burst_result.allowed:
                return burst_result
        
        # Apply main rate limit
        algorithm = self.algorithms[config.algorithm]
        result = algorithm.check_limit(cache_key, config)
        
        # Log rate limit events
        self._log_rate_limit_event(identifier, config_name, result)
        
        # Handle grace period
        if not result.allowed and config.grace_period > 0:
            result = self._apply_grace_period(cache_key, config, result)
        
        return result
    
    def _generate_key(self, identifier: str, config_name: str, scope: RateLimitScope) -> str:
        """Generate cache key for rate limiting"""
        return f"rate_limit:{scope.value}:{config_name}:{identifier}"
    
    def _check_burst_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check burst rate limit"""
        burst_config = RateLimitConfig(
            limit=config.burst_limit,
            window=config.burst_window,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=config.scope
        )
        
        burst_key = f"{key}:burst"
        algorithm = self.algorithms[RateLimitAlgorithm.SLIDING_WINDOW]
        
        return algorithm.check_limit(burst_key, burst_config)
    
    def _apply_grace_period(self, key: str, config: RateLimitConfig, 
                          result: RateLimitResult) -> RateLimitResult:
        """Apply grace period for rate limit violations"""
        grace_key = f"{key}:grace"
        
        try:
            # Check if grace period is active
            grace_data = self.redis.get(grace_key)
            
            if not grace_data:
                # Start grace period
                grace_info = {
                    'start_time': time.time(),
                    'violations': 1
                }
                self.redis.setex(grace_key, config.grace_period, json.dumps(grace_info))
                
                # Allow request during grace period
                result.allowed = True
                logger.info("Grace period started", key=key, config=config.description)
            else:
                grace_info = json.loads(grace_data)
                grace_info['violations'] += 1
                
                # Update grace period data
                remaining_time = config.grace_period - (time.time() - grace_info['start_time'])
                if remaining_time > 0:
                    self.redis.setex(grace_key, int(remaining_time), json.dumps(grace_info))
                    result.allowed = True
                    
                    logger.warning(
                        "Grace period violation",
                        key=key,
                        violations=grace_info['violations'],
                        remaining_time=remaining_time
                    )
        
        except Exception as e:
            logger.error("Grace period check failed", key=key, error=str(e))
        
        return result
    
    def _log_rate_limit_event(self, identifier: str, config_name: str, 
                            result: RateLimitResult) -> None:
        """Log rate limit events for monitoring"""
        event_data = {
            'identifier': identifier,
            'config_name': config_name,
            'allowed': result.allowed,
            'limit': result.limit,
            'remaining': result.remaining,
            'current_usage': result.current_usage,
            'algorithm': result.algorithm,
            'scope': result.scope,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if result.allowed:
            logger.debug("Rate limit check passed", **event_data)
        else:
            logger.warning("Rate limit exceeded", **event_data)
            
            # Store violation for analytics
            self._store_violation(identifier, config_name, result)
    
    def _store_violation(self, identifier: str, config_name: str, 
                        result: RateLimitResult) -> None:
        """Store rate limit violation for analytics"""
        try:
            violation_key = f"rate_limit_violations:{datetime.now().strftime('%Y-%m-%d')}"
            violation_data = {
                'identifier': identifier,
                'config_name': config_name,
                'timestamp': time.time(),
                'limit': result.limit,
                'usage': result.current_usage,
                'algorithm': result.algorithm,
                'scope': result.scope
            }
            
            # Store in Redis list with daily expiration
            self.redis.lpush(violation_key, json.dumps(violation_data))
            self.redis.expire(violation_key, 86400 * 7)  # Keep for 7 days
            
        except Exception as e:
            logger.error("Failed to store rate limit violation", error=str(e))
    
    def get_rate_limit_status(self, identifier: str, config_name: str = "api_general") -> Dict[str, Any]:
        """Get current rate limit status without incrementing counters"""
        config = self.default_configs.get(config_name)
        if not config:
            return {"error": f"Unknown configuration: {config_name}"}
        
        cache_key = self._generate_key(identifier, config_name, config.scope)
        
        try:
            if config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                # Count entries in sliding window
                now = time.time()
                window_start = now - config.window
                sliding_key = f"rate_limit:sliding:{cache_key}"
                
                # Clean expired entries
                self.redis.zremrangebyscore(sliding_key, 0, window_start)
                current_count = self.redis.zcard(sliding_key)
                
                return {
                    'limit': config.limit,
                    'remaining': max(0, config.limit - current_count),
                    'current_usage': current_count,
                    'reset_time': datetime.fromtimestamp(now + config.window).isoformat(),
                    'algorithm': config.algorithm.value
                }
            
            elif config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                bucket_key = f"rate_limit:token_bucket:{cache_key}"
                bucket_data = self.redis.get(bucket_key)
                
                if bucket_data:
                    bucket = json.loads(bucket_data)
                    tokens = bucket['tokens']
                    last_refill = bucket['last_refill']
                    
                    # Calculate current tokens
                    now = time.time()
                    time_elapsed = now - last_refill
                    refill_rate = config.limit / config.window
                    tokens = min(config.limit, tokens + (time_elapsed * refill_rate))
                    
                    return {
                        'limit': config.limit,
                        'remaining': int(tokens),
                        'current_usage': config.limit - int(tokens),
                        'algorithm': config.algorithm.value
                    }
                else:
                    return {
                        'limit': config.limit,
                        'remaining': config.limit,
                        'current_usage': 0,
                        'algorithm': config.algorithm.value
                    }
            
            # Default response for other algorithms
            return {
                'limit': config.limit,
                'algorithm': config.algorithm.value,
                'status': 'active'
            }
            
        except Exception as e:
            logger.error("Failed to get rate limit status", identifier=identifier, error=str(e))
            return {"error": "Failed to get status"}
    
    def reset_rate_limit(self, identifier: str, config_name: str = "api_general") -> bool:
        """Reset rate limit for given identifier"""
        config = self.default_configs.get(config_name)
        if not config:
            return False
        
        cache_key = self._generate_key(identifier, config_name, config.scope)
        
        try:
            # Delete all related keys
            keys_to_delete = [
                f"rate_limit:fixed:{cache_key}:*",
                f"rate_limit:sliding:{cache_key}",
                f"rate_limit:token_bucket:{cache_key}",
                f"rate_limit:leaky_bucket:{cache_key}",
                f"{cache_key}:burst",
                f"{cache_key}:grace"
            ]
            
            for key_pattern in keys_to_delete:
                if '*' in key_pattern:
                    # Handle wildcard patterns
                    keys = self.redis.keys(key_pattern)
                    if keys:
                        self.redis.delete(*keys)
                else:
                    self.redis.delete(key_pattern)
            
            logger.info("Rate limit reset", identifier=identifier, config_name=config_name)
            return True
            
        except Exception as e:
            logger.error("Failed to reset rate limit", identifier=identifier, error=str(e))
            return False
    
    def get_violations_summary(self, days: int = 1) -> Dict[str, Any]:
        """Get rate limit violations summary"""
        try:
            violations = []
            
            for i in range(days):
                date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                violation_key = f"rate_limit_violations:{date}"
                
                daily_violations = self.redis.lrange(violation_key, 0, -1)
                for violation_json in daily_violations:
                    violation = json.loads(violation_json)
                    violation['date'] = date
                    violations.append(violation)
            
            # Aggregate statistics
            total_violations = len(violations)
            violations_by_config = {}
            violations_by_identifier = {}
            
            for violation in violations:
                config_name = violation['config_name']
                identifier = violation['identifier']
                
                violations_by_config[config_name] = violations_by_config.get(config_name, 0) + 1
                violations_by_identifier[identifier] = violations_by_identifier.get(identifier, 0) + 1
            
            return {
                'total_violations': total_violations,
                'violations_by_config': violations_by_config,
                'violations_by_identifier': violations_by_identifier,
                'top_violators': sorted(violations_by_identifier.items(), 
                                      key=lambda x: x[1], reverse=True)[:10],
                'period_days': days
            }
            
        except Exception as e:
            logger.error("Failed to get violations summary", error=str(e))
            return {"error": "Failed to get summary"}

# Decorator for rate limiting
def rate_limit(config_name: str = "api_general", 
               identifier_func: Optional[callable] = None,
               custom_config: Optional[RateLimitConfig] = None):
    """Decorator for applying rate limits to functions"""
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            rate_limiter = AdvancedRateLimiter()
            
            # Determine identifier
            if identifier_func:
                identifier = identifier_func(*args, **kwargs)
            else:
                # Default to function name + first argument
                identifier = f"{func.__name__}:{args[0] if args else 'default'}"
            
            # Check rate limit
            result = rate_limiter.check_rate_limit(identifier, config_name, custom_config)
            
            if not result.allowed:
                raise RateLimitError(
                    f"Rate limit exceeded for {identifier}. "
                    f"Limit: {result.limit}, Current: {result.current_usage}",
                    result
                )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

# Async version of the decorator
def async_rate_limit(config_name: str = "api_general",
                    identifier_func: Optional[callable] = None,
                    custom_config: Optional[RateLimitConfig] = None):
    """Async decorator for applying rate limits to async functions"""
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            rate_limiter = AdvancedRateLimiter()
            
            # Determine identifier
            if identifier_func:
                if asyncio.iscoroutinefunction(identifier_func):
                    identifier = await identifier_func(*args, **kwargs)
                else:
                    identifier = identifier_func(*args, **kwargs)
            else:
                identifier = f"{func.__name__}:{args[0] if args else 'default'}"
            
            # Check rate limit
            result = rate_limiter.check_rate_limit(identifier, config_name, custom_config)
            
            if not result.allowed:
                raise RateLimitError(
                    f"Rate limit exceeded for {identifier}. "
                    f"Limit: {result.limit}, Current: {result.current_usage}",
                    result
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator

# Global rate limiter instance
rate_limiter = AdvancedRateLimiter()

# Export public API
__all__ = [
    "RateLimitAlgorithm",
    "RateLimitScope", 
    "RateLimitAction",
    "RateLimitConfig",
    "RateLimitResult",
    "RateLimitError",
    "AdvancedRateLimiter",
    "rate_limit",
    "async_rate_limit",
    "rate_limiter"
]

logger.info("Rate limiter module initialized")


