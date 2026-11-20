#Standard
import asyncio, json, os, httpx, tldextract #send http requests to form data
from urllib.parse import urlparse
import category_cache

#`sa`me as  and try to load once not per scanj
ENTITY_MAP_PATH = os.path.join(os.path.dirname(__file__), "scanner", "entity_map.json")
ENTITY_PREVALENCE_PATH = os.path.join(os.path.dirname(__file__), "scanner", "entity_prevalence.json")

with open(ENTITY_MAP_PATH, encoding="utf-8") as f:
    _entity_map = json.load(f)

with open(ENTITY_PREVALENCE_PATH, encoding="utf-8") as f:
    ENTITY_PREVALENCE = json.load(f)



DOMAIN_TO_ENTITY = {}

for entity_name, entity_data in _entity_map.items():
    for domain in entity_data.get("properties", []):
        DOMAIN_TO_ENTITY[domain] = entity_name


def _etld1(host):
    return tldextract.extract(host or "").top_domain_under_public_suffix


async def get_category_info(domain):

    registrable_domain = _etld1(domain)
    #implement redis cache
    if category_cache.is_enabled():
        cached = await category_cache.get_cached_category(registrable_domain)
        if cached:
            return cached

    url = f"https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/domains/US/{registrable_domain}.json"

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(url)

        if response.status_code == 200:
            data = response.json()
            info = {"categories": data.get("categories", []), "fingerprinting": data.get("fingerprinting")}
            if category_cache.is_enabled():
                await category_cache.set_cached_category(registrable_domain, info)
            return info

    except (httpx.TimeoutException, httpx.RequestError):
        pass

    return {"categories": [], "fingerprinting": None}



async def get_tracker_info(domain):
    """Look up what entity owns this domain, and how prevalent/what-category that entity is as a tracker."""
    registrable_domain = _etld1(domain)
    entity = DOMAIN_TO_ENTITY.get(registrable_domain)
    category_info = await get_category_info(domain)

    if not entity:
        return {"domain": domain, "entity": None, "prevalence": None, **category_info}

    prevalence_data = ENTITY_PREVALENCE.get(entity, {})
    return {
        "domain": domain,
        "entity": entity,
        "prevalence": prevalence_data.get("tracking"),
        **category_info
    }


async def build_trackers(result):
    """Every third-party domain, plus same-owner domains that Tracker Radar classes as tracking.
    Example: doubleclick.net on youtube.com - Google owns both, so it is 'first party', but it is
    still ad tracking and must count. Lookups run in parallel (at most 10 at once)."""
    site = _etld1(urlparse(result.get("final_url") or result.get("url") or "").hostname)
    third_party = sorted(result["third_party_domains"])
    same_owner = sorted(d for d in result["first_party_domains"] if _etld1(d) != site)

    limit = asyncio.Semaphore(10)  # created per call, so it always belongs to the running event loop

    async def lookup(domain):
        async with limit:
            return await get_tracker_info(domain)

    third_info = await asyncio.gather(*(lookup(d) for d in third_party))
    owner_info = await asyncio.gather(*(lookup(d) for d in same_owner))
    trackers = [{**t, "same_owner": False} for t in third_info]
    trackers += [{**t, "same_owner": True} for t in owner_info if is_tracking(t)]
    return trackers



# ---------- Scoring: OWASP Risk Rating Methodology ----------
# Every factor is rated 0-9. Likelihood and impact are the weighted average of their factors,
# each becomes LOW / MEDIUM / HIGH, and the OWASP severity matrix combines the two levels into
# Note / Low / Medium / High / Critical -> grade A-F. All numbers live in scoring_config.json.
SCORING_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "scoring_config.json")


def load_config(path=SCORING_CONFIG_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


SCORING_CONFIG = load_config()


def _curve(points, x):
    """Piecewise-linear lookup: points are [input, rating] pairs in increasing input order."""
    if x <= points[0][0]:
        return points[0][1]
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        if x <= x1:
            return y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return points[-1][1]


def category_rating(tracker, cfg=None):
    """0-9 rating of a tracker's most invasive Tracker Radar category."""
    severity = (cfg or SCORING_CONFIG)["category_severity"]
    categories = tracker.get("categories") or []
    if not categories:
        return severity["Unclassified"]
    return max(severity.get(c, severity["other"]) for c in categories)


def is_tracking(tracker, cfg=None):
    cfg = cfg or SCORING_CONFIG
    return category_rating(tracker, cfg) >= cfg["tracking_threshold"]


def likelihood_factors(trackers, cfg):
    load_cfg = cfg["tracking_load"]
    mods, thresholds = load_cfg["prevalence_modifiers"], load_cfg["prevalence_thresholds"]

    load = 0.0
    for t in trackers:
        weight = _curve(load_cfg["category_weight_curve"], category_rating(t, cfg))
        prevalence = t.get("prevalence")
        if prevalence is None:
            modifier = mods["none"]
        elif prevalence > thresholds["high"]:
            modifier = mods["high"]
        elif prevalence > thresholds["medium"]:
            modifier = mods["medium"]
        else:
            modifier = mods["low"]
        load += weight * modifier

    tracking = [t for t in trackers if is_tracking(t, cfg)]
    f = cfg["likelihood_factors"]
    factors = {
        "tracking_load": _curve(f["tracking_load"]["curve"], load),
        "tracker_severity": max((category_rating(t, cfg) for t in trackers), default=0),
        "tracker_reach": _curve(f["tracker_reach"]["curve"],
                                max((t.get("prevalence") or 0 for t in tracking), default=0)),
        "fingerprinting": _curve(f["fingerprinting"]["curve"],
                                 max((t.get("fingerprinting") or 0 for t in trackers), default=0)),
    }
    return {k: round(v, 2) for k, v in factors.items()}, round(load, 2)


def impact_factors(result, cfg):
    """Returns (factors, findings). Findings are the concrete problems, labelled with OWASP Top 10."""
    f, labels, findings = cfg["impact_factors"], cfg["owasp_top10"], []

    def finding(key, title):
        findings.append({"id": key, "title": title, "owasp": labels.get(key)})

    headers = (result.get("main_document") or {}).get("security_headers") or {}
    final_url = result.get("final_url") or result.get("url") or ""
    host = urlparse(final_url).hostname

    # Data leakage: headers that limit what leaks to other sites
    weights = f["data_leakage"]["headers"]
    missing = [h for h in weights if h not in headers]
    data_leakage = 9 * sum(weights[h] for h in missing) / sum(weights.values())
    names = {"content-security-policy": ("missing_csp", "No Content-Security-Policy header"),
             "referrer-policy": ("missing_referrer_policy", "No Referrer-Policy header (page URLs can leak to other sites)"),
             "permissions-policy": ("missing_permissions_policy", "No Permissions-Policy header")}
    for h in missing:
        if h in names:
            finding(*names[h])

    # Transport security: TLS version of the main page + HSTS
    t = f["transport_security"]
    if urlparse(final_url).scheme != "https":
        protocol = "none"
    else:
        protocol = ((result.get("tls_info") or {}).get(host) or {}).get("protocol") or "unknown"
    transport = t["tls"].get(protocol, t["tls"].get("unknown", 2))
    if transport >= 5:
        finding("weak_tls", f"Outdated or missing encryption ({protocol})")
    if "strict-transport-security" not in headers:
        transport += t["missing_hsts"]
        finding("missing_hsts", "No Strict-Transport-Security header")
    transport = min(transport, 9)

    # Cookie protection: average weakness of first-party cookies (matched by registrable domain,
    # so cookies set on .example.com count for www.example.com)
    site_domains = {_etld1(h) for h in result["first_party_domains"]} | {_etld1(host)}
    cookies = [c for c in result.get("cookies") or [] if _etld1(c["domain"].lstrip(".")) in site_domains]
    flags = f["cookie_protection"]["flags"]
    no_secure = [c for c in cookies if not c.get("secure")]
    no_httponly = [c for c in cookies if not c.get("httpOnly")]
    samesite_none = [c for c in cookies if c.get("sameSite") == "None"]
    if cookies:
        weakness = (len(no_secure) * flags["secure"] + len(no_httponly) * flags["httpOnly"]
                    + len(samesite_none) * flags["sameSite_none"])
        cookie_protection = 9 * weakness / (len(cookies) * sum(flags.values()))
    else:
        cookie_protection = 0
    if no_secure:
        finding("cookie_not_secure", f"{len(no_secure)} of {len(cookies)} site cookies sent without the Secure flag")
    if no_httponly:
        finding("cookie_not_httponly", f"{len(no_httponly)} of {len(cookies)} site cookies readable by scripts (no HttpOnly)")
    if samesite_none:
        finding("cookie_samesite_none", f"{len(samesite_none)} of {len(cookies)} site cookies shared cross-site (SameSite=None)")

    # Framing protection: X-Frame-Options or CSP frame-ancestors
    csp = (headers.get("content-security-policy") or "").lower()
    if "x-frame-options" in headers or "frame-ancestors" in csp:
        framing = 0
    else:
        framing = f["framing_protection"]["missing"]
        finding("missing_framing_protection", "Page can be embedded by other sites (no X-Frame-Options or frame-ancestors)")

    factors = {"data_leakage": data_leakage, "transport_security": transport,
               "cookie_protection": cookie_protection, "framing_protection": framing}
    return {k: round(v, 2) for k, v in factors.items()}, findings


def _weighted_average(factors, factor_cfg):
    total = sum(factor_cfg[k].get("weight", 1) for k in factors)
    return sum(v * factor_cfg[k].get("weight", 1) for k, v in factors.items()) / total


def level(value, cfg=None):
    levels = (cfg or SCORING_CONFIG)["levels"]
    if value < levels["low_below"]:
        return "LOW"
    if value < levels["medium_below"]:
        return "MEDIUM"
    return "HIGH"


def grade_from_score(score, cfg=None):
    for g in (cfg or SCORING_CONFIG)["grades"].values():
        if isinstance(g, dict) and g["band"][0] <= score <= g["band"][1]:
            return g["grade"]
    raise ValueError(f"score {score} is not inside any grade band")


def score_scan(result, trackers, cfg=None):
    """Pure scoring (no network): same inputs + same config always give the same score."""
    cfg = cfg or SCORING_CONFIG
    l_factors, load = likelihood_factors(trackers, cfg)
    i_factors, findings = impact_factors(result, cfg)
    likelihood = round(_weighted_average(l_factors, cfg["likelihood_factors"]), 2)
    impact = round(_weighted_average(i_factors, cfg["impact_factors"]), 2)
    l_level, i_level = level(likelihood, cfg), level(impact, cfg)

    severity = cfg["severity_matrix"][i_level][l_level]
    grade = cfg["grades"][severity]
    low, high = grade["band"]
    # inside the grade's band, more combined risk = lower number (keeps sites sortable within a grade)
    score = round(high - (likelihood + impact) / 18 * (high - low))

    tracking = [t for t in trackers if is_tracking(t, cfg)]
    if tracking:
        companies = {t.get("entity") or _etld1(t["domain"]) for t in tracking}
        findings.insert(0, {"id": "third_party_tracking",
                            "title": f"{len(tracking)} tracking domains from {len(companies)} companies",
                            "owasp": cfg["owasp_top10"].get("third_party_tracking")})
    if l_factors["fingerprinting"] > 0:
        findings.insert(1 if tracking else 0, {"id": "fingerprinting",
                                               "title": "Trackers known to fingerprint browsers are present",
                                               "owasp": cfg["owasp_top10"].get("fingerprinting")})

    return {
        "score": score,
        "grade": grade["grade"],
        "severity": severity,
        "breakdown": {
            "likelihood": likelihood,
            "impact": impact,
            "likelihood_level": l_level,
            "impact_level": i_level,
            "tracking_load": load,
            "factors": {**l_factors, **i_factors},
        },
        "findings": findings,
        "trackers": trackers,
        "scoring_version": cfg["version"],
    }


async def compute_score(result):
    return score_scan(result, await build_trackers(result))


if __name__ == "__main__":
    from scanner.engine_populate import scan

    async def test():
        result = await scan("https://www.kimberly-clark.com/")
        score_result = await compute_score(result)
        print(f"Score: {score_result['score']} ({score_result['grade']}, {score_result['severity']})")
        print(f"Breakdown: {score_result['breakdown']}")
        for item in score_result["findings"]:
            print(f"  [{item['owasp']}] {item['title']}")

    asyncio.run(test())
