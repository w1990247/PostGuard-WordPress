import hashlib 
from redis.asyncio import Redis
from api.app.core.settings import settings

class ReplayProtectorRedis:

    def __init__(self,redis:Redis,window_seconds:int):

        self.redis= redis
        self.window_seconds= window_seconds

    # The function below builds a replay token from the signed request.
    @staticmethod
    def token1(api_key:str, signature: str, timestamp: int,body: bytes)->str:

        hashing= hashlib.sha256(body).hexdigest()
        raw= f"{api_key}:{signature}:{timestamp}:{hashing}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
    
    async def check_redis(self, api_key:str, signature: str, timestamp: int,body: bytes)->None:

        token= self.token1(api_key, signature, timestamp, body)
        key= f"{settings.REDIS_PREFIX}:replay:{token}"
        replay_detected= await self.redis.set(name=key, value="1", nx=True, ex=self.window_seconds)
        if not replay_detected:
            raise ValueError("Replay was detected!")