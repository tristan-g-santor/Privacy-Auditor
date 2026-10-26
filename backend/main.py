import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from scanner.engine_populate import scan
from entity_scoring import compute_score
import db

logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app):
    if not await db.init_db():
        logger.warning("DATABASE_URL not set - scans will not be saved to history")
    yield
    await db.close_db()


app = FastAPI(lifespan=lifespan)

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

    # still return the scan if saving fails; scan_id = None tells the client it isn't in history
    result["scan_id"] = None
    if db.is_enabled():
        try:
            result["scan_id"] = await db.save_scan(result)
        except Exception:
            logger.exception("failed to save scan for %s", url)
    return result


@app.get("/history")
async def scan_history(url: str, limit: int = Query(50, ge=1, le=500)):
    if not db.is_enabled():
        raise HTTPException(503, "History is unavailable: database not configured")
    return await db.get_history(url, limit)


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: int):
    if not db.is_enabled():
        raise HTTPException(503, "History is unavailable: database not configured")
    scan_result = await db.get_scan(scan_id)
    if scan_result is None:
        raise HTTPException(404, "Scan not found")
    return scan_result
