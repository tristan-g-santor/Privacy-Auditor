#SSRF guard: the scanner's browser runs inside our server's network, so it must only
#ever talk to public internet addresses - never localhost, docker services, or cloud metadata
import asyncio, ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


class BlockedURLError(ValueError):
    pass


def _is_public(ip_str):
    ip = ipaddress.ip_address(ip_str)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    # multicast (224.x) counts as "global" in python but is never a web server
    return ip.is_global and not ip.is_multicast


async def resolve_public(host):
    """True only if host resolves and EVERY address it resolves to is public."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except (socket.gaierror, ValueError):  # ValueError also covers UnicodeError (bad IDN labels) and null bytes
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(_is_public(a) for a in addresses)


async def validate_url(url):
    """Normalize and check a user-supplied URL before the browser ever sees it."""
    url = url.strip()  # copy-pasted URLs often carry spaces or newlines
    if "\\" in url:
        # browsers read "\" as "/" but urlparse doesn't, so they'd disagree about which host this is
        raise BlockedURLError("URLs containing a backslash can't be scanned")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise BlockedURLError(f"Only http and https URLs can be scanned, got {parsed.scheme!r}")
    if not parsed.hostname:
        raise BlockedURLError("URL has no hostname")
    try:
        parsed.port  # raises ValueError for ':99999' or ':abc'
    except ValueError:
        raise BlockedURLError("URL has an invalid port")
    if not await resolve_public(parsed.hostname):
        raise BlockedURLError(f"{parsed.hostname} is not a public internet address")
    return url
