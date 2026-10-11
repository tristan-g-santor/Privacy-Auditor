from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scanner.engine_populate import scan
from entity_scoring import compute_score

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/scan")
async def run_scan(url: str):
    result = await scan(url)

    score_result = await compute_score(result)
    result["score"] = score_result["score"]
    result["grade"] = score_result["grade"]
    result["breakdown"] = score_result["breakdown"]
    result["trackers"] = score_result["trackers"]

    result["third_party_domains"] = sorted(result["third_party_domains"])
    result["first_party_domains"] = sorted(result["first_party_domains"])
    result["unknown_hosts"] = sorted(result["unknown_hosts"])
    return result
