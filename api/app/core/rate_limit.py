from redis.asyncio import Redis
from api.app.core.settings import settings

class RateLimitRedis:

    def __init__(self, redis: Redis, limit_per_minute: int):

        self.redis=redis
        self.limit= limit_per_minute

    #The  following code sets a limit  on  repeated requests pre API key.
    async def check(self, key: str)-> None:
        redis_key= f"{settings.REDIS_PREFIX}:rl:{key}"
        count = await self.redis.incr(redis_key)

        if count ==1:
            await self.redis.expire(redis_key,60)

        if count >self.limit:
            raise ValueError("Set rate limit exceeded!")