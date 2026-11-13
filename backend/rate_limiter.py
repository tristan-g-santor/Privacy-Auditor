#per-IP scan limit, stored in Redis so it's shared across restarts and replicas
#fixed window: each IP gets SCAN_RATE_LIMIT scans, the counter resets SCAN_RATE_WINDOW_SECONDS after the first one
import os
import category_cache

SCAN_RATE_LIMIT = int(os.environ.get("SCAN_RATE_LIMIT", "10"))
SCAN_RATE_WINDOW_SECONDS = int(os.environ.get("SCAN_RATE_WINDOW_SECONDS", "600"))
# 0 locally (no proxy in front); 1 behind Azure Container Apps ingress
TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))


def client_ip(request):
    """The caller's real IP. Behind a proxy, read X-Forwarded-For from the RIGHT - entries on
    the left are whatever the client claimed and can be faked; the proxy appends the true one."""
    if TRUSTED_PROXY_HOPS:
        hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        if len(hops) >= TRUSTED_PROXY_HOPS:
            return hops[-TRUSTED_PROXY_HOPS]
    return request.client.host if request.client else "unknown"


async def check_scan_allowed(ip):
    """Returns (allowed, seconds_until_reset). Fails open: if Redis is down, scans still work -
    the semaphore keeps protecting the server's memory either way."""
    redis = category_cache.get_client()
    if redis is None:
        return True, 0
    key = f"ratelimit:scan:{ip}"
    try:
        async with redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.ttl(key)
            count, ttl = await pipe.execute()
        if ttl == -1:  # brand-new key (or one that lost its expiry) - start the window
            await redis.expire(key, SCAN_RATE_WINDOW_SECONDS)
            ttl = SCAN_RATE_WINDOW_SECONDS
    except Exception:
        return True, 0
    return count <= SCAN_RATE_LIMIT, max(ttl, 0)
