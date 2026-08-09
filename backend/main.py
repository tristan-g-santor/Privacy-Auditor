


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scanner.scantest import scan

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
    result["third_party_domains"] = sorted(result["third_party_domains"])
    return result