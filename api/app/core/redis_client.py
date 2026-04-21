from redis.asyncio import Redis,from_url
from api.app.core.settings import settings

redis1:Redis| None=None

def GET_redis()->Redis:
    global redis1

    if redis1 is None:
        redis1 = from_url(settings.REDIS_URL,encoding="utf-8",decode_responses=True,)
    return redis1

async def close_redis()->None:
    global redis1

    if redis1 is not None:
        await redis1.aclose()
        redis1=None

