#Standard  
import json, os, httpx, tldextract #send http requests to form data
from urllib.parse import urlparse

#same as  and try to load once not per scanj
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


#cahce setup
CATEGORY_CACHE_PATH = os.path.join(os.path.dirname(__file__), "category_cache.json")

if os.path.exists(CATEGORY_CACHE_PATH):
    with open(CATEGORY_CACHE_PATH, encoding="utf-8") as f:
        _category_cache = json.load(f)
else:
    _category_cache = {}


async def get_category_info(domain):
    registrable_domain = tldextract.extract(domain).top_domain_under_public_suffix

    if registrable_domain in _category_cache:
        return _category_cache[registrable_domain]

    url = f"https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/domains/US/{registrable_domain}.json"

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(url)

        if response.status_code == 200:
            data = response.json()
            info = {"categories": data.get("categories", []), "fingerprinting": data.get("fingerprinting")}
            _category_cache[registrable_domain] = info
            return info
    except (httpx.TimeoutException, httpx.RequestError):
        pass

    return {"categories": [], "fingerprinting": None}



def save_category_cache():
    with open(CATEGORY_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(_category_cache, f, indent=2)

async def get_tracker_info(domain):
    """Look up what entity owns this domain, and how prevalent/what-category that entity is as a tracker."""
    registrable_domain = tldextract.extract(domain).top_domain_under_public_suffix
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


async def build_tracker_list(third_party_domains):
    return [await get_tracker_info(d) for d in third_party_domains]



#Scoring Core
SCORING_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "scoring_config.json")
with open(SCORING_CONFIG_PATH, encoding="utf-8") as f:
    SCORING_CONFIG = json.load(f)


def score_likelihood(tracker_list):
    cfg = SCORING_CONFIG
    score = 0

    for tracker in tracker_list:
        categories = tracker.get("categories") or ["Unclassified"]
        weight = max(cfg["category_weights"].get(c, 1) for c in categories)

        prevalence = tracker.get("prevalence")
        if prevalence is None:
            modifier = cfg["prevalence_modifiers"]["none"]
        elif prevalence > cfg["prevalence_thresholds"]["high"]:
            modifier = cfg["prevalence_modifiers"]["high"]
        elif prevalence > cfg["prevalence_thresholds"]["medium"]:
            modifier = cfg["prevalence_modifiers"]["medium"]
        else:
            modifier = cfg["prevalence_modifiers"]["low"]

        score += weight * modifier

    return min(score, cfg["likelihood_cap"])


def score_impact(main_document, cookies, first_party_domains, tls_info, main_domain):
    cfg = SCORING_CONFIG
    score = 0

    # Headers — from main_document only, not the merged per-domain dict
    headers = main_document.get("security_headers", {}) if main_document else {}
    for header, weight in cfg["header_weights"].items():
        if header not in headers:
            score += weight

    # Cookies — first-party only
    first_party_cookies = [c for c in cookies if c["domain"].lstrip(".") in first_party_domains]
    for c in first_party_cookies:
        if not c.get("httpOnly"): score += cfg["cookie_weights"]["httpOnly"]
        if not c.get("secure"): score += cfg["cookie_weights"]["secure"]
        if c.get("sameSite") == "None": score += cfg["cookie_weights"]["sameSite"]

    # TLS — main domain only
    protocol = tls_info.get(main_domain, {}).get("protocol", "")
    score += cfg["tls_weights"].get(protocol, 0)  # QUIC/TLS 1.3 not in dict → defaults to 0

    return min(score, cfg["impact_cap"])


def grade_from_score(score):
    thresholds = SCORING_CONFIG["grade_thresholds"]
    if score >= thresholds["A"]: return "A"
    if score >= thresholds["B"]: return "B"
    if score >= thresholds["C"]: return "C"
    if score >= thresholds["D"]: return "D"
    return "F"


async def compute_score(result):
    cfg = SCORING_CONFIG
    tracker_list = await build_tracker_list(result["third_party_domains"])

    likelihood = score_likelihood(tracker_list)
    impact = score_impact(
        result.get("main_document"),
        result["cookies"],
        result["first_party_domains"],
        result["tls_info"],
        urlparse(result["final_url"]).hostname
    )

    likelihood_pct = (likelihood / cfg["likelihood_cap"]) * 100
    impact_pct = (impact / cfg["impact_cap"]) * 100
    risk = (likelihood_pct * cfg["likelihood_weight"]) + (impact_pct * cfg["impact_weight"])
    final_score = round(100 - risk)

    return {
        "score": final_score,
        "grade": grade_from_score(final_score),
        "breakdown": {"likelihood": round(likelihood, 2), "impact": round(impact, 2)},
        "trackers": tracker_list
    }









if __name__ == "__main__":
    import asyncio
    from scanner.engine_populate import scan

    async def test():
        result = await scan("https://www.misp-project.org/feeds/")
        score_result = await compute_score(result)
        print(f"Score: {score_result['score']} ({score_result['grade']})")
        print(f"Breakdown: {score_result['breakdown']}")
        print("Trackers:")
        for t in score_result['trackers']:
            print(" ", t)
        save_category_cache()

    asyncio.run(test())
