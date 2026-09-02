import asyncio
from app.config import settings
from redis.asyncio import Redis
async def main():
    redis=Redis.from_url(settings.redis_url,decode_responses=True)
    try:
        while True:
            await redis.xread({"netsentinel:proxy-events":"$"},block=30000,count=100)
    finally: await redis.aclose()
if __name__=="__main__": asyncio.run(main())
