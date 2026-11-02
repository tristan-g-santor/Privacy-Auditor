import logging
from typing import Literal
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from scanner.engine_populate import scan
from entity_scoring import compute_score
import db
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("uvicorn.error")




@asynccontextmanager
async def lifespan(app):
    if not await db.init_db():
        logger.warning("DATABASE_URL not set - scans will not be saved to history")
    try:
        yield
    finally:
        await db.close_db()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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
    result["save_error"] = None
    if db.is_enabled():
        try:
            result["scan_id"] = await db.save_scan(result)
        except Exception:
            logger.exception("failed to save scan for %s", url)
            result["save_error"] = "Scan completed, but could not be saved. Please try scanning again."
    else:
        result["save_error"] = "Scan completed, but history is unavailable because the database is not configured."
    return result


@app.get("/history")
async def scan_history(
    url: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    grade: Literal["A", "B", "C", "D", "F"] | None = None,
    #no_csp: bool = False, maybe come back to this 
    tls: list[Literal["TLS 1.2", "TLS 1.3"]] | None = Query(None),
    sort: Literal["most-recent", "worst-score", "most-trackers", "best-score"] = "most-recent",
):
    if not db.is_enabled():
        raise HTTPException(503, "History is unavailable: database not configured")
    try:
        return await db.get_history(url, limit, grade=grade,
                                    tls_protocols=tls, sort=sort, offset=offset)
    except Exception:
        logger.exception("failed to load scan history")
        raise HTTPException(503, "Could not load scan history. Please try again.")


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: int):
    if not db.is_enabled():
        raise HTTPException(503, "History is unavailable: database not configured")
    try:
        scan_result = await db.get_scan(scan_id)
    except Exception:
        logger.exception("failed to load saved scan %s", scan_id)
        raise HTTPException(503, "Could not load this scan. Please try again.")
    if scan_result is None:
        raise HTTPException(404, "Scan not found")
    return scan_result
