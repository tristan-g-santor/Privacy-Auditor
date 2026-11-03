import os, json
import redis.asyncio as redis

_client = None
CATEGORY_TTL_SECONDS = 5 * 24 * 60 * 60

async def init_cache(url=None):
    """Connect to Redis. Returns False (cache disabled) when no REDIS_URL is set."""
    global _client
    url = url or os.environ.get("REDIS_URL")
    if not url:
        return False
    _client = redis.from_url(url, decode_responses = True)
    await _client.ping()
    return True


async def close_cache():
    global _client
    if _client:
        await _client.close()
        _client = None


def is_enabled():
    return _client is not None


#Core cache features
async def get_cached_category(domain):
    value = await _client.get(f"category:{domain}")
    return json.loads(value) if value else None


async def set_cached_category(domain, info):
    await _client.setex(f"category:{domain}", CATEGORY_TTL_SECONDS, json.dumps(info))