#run from backend/:  python -m pytest tests -v
#integration tests need a throwaway database:  TEST_DATABASE_URL=postgresql://user@localhost/auditor_test
import asyncio, json, math, os, sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db

TEST_DSN = os.environ.get("TEST_DATABASE_URL")


def make_result(**overrides):
    result = {
        "url": "https://www.example.com/home",
        "final_url": "https://www.example.com/home",
        "score": 82,
        "grade": "B",
        "breakdown": {"likelihood": 4.5, "impact": 8.0},
        "cookies": [{"name": "sid", "domain": ".example.com", "httpOnly": True, "secure": True}],
        "tls_info": {"www.example.com": {"protocol": "TLS 1.3", "issuer": "Test CA"}},
        "trackers": [
            {"domain": "www.google-analytics.com", "entity": "Google LLC", "prevalence": 0.611,
             "categories": ["Analytics"], "fingerprinting": 2},
            {"domain": "cdn.unknown.net", "entity": None, "prevalence": None,
             "categories": [], "fingerprinting": None},
        ],
        "third_party_domains": ["cdn.unknown.net", "www.google-analytics.com"],
        "first_party_domains": ["www.example.com"],
        "unknown_hosts": [],
    }
    result.update(overrides)
    return result


def many_trackers(n):
    return [{"domain": f"t{i}.tracker{i}.com", "entity": None, "prevalence": round(i / n, 3),
             "categories": ["Advertising"], "fingerprinting": i % 4} for i in range(n)]


# ---------- validation (no database needed) ----------

def test_valid_result_builds_row():
    row = db.build_scan_row(make_result())
    assert row["host"] == "example.com"
    assert row["tls_protocol"] == "TLS 1.3"
    assert row["tracker_count"] == 2
    assert row["cookie_count"] == 1
    assert json.loads(row["result"])["score"] == 82


@pytest.mark.parametrize("url,host", [
    ("https://www.Example.com/a?b=1", "example.com"),
    ("http://example.com", "example.com"),
    ("example.com", "example.com"),
    ("https://shop.example.com", "shop.example.com"),
])
def test_normalize_host(url, host):
    assert db.normalize_host(url) == host


def test_empty_tracker_list_is_valid():
    row = db.build_scan_row(make_result(trackers=[]))
    assert row["trackers"] == [] and row["tracker_count"] == 0


def test_missing_trackers_key_is_valid():
    result = make_result()
    del result["trackers"]
    assert db.build_scan_row(result)["tracker_count"] == 0


@pytest.mark.parametrize("tls_info", [{}, None, {"other-host.com": {"protocol": "TLS 1.2"}},
                                      {"www.example.com": {}}, {"www.example.com": None}])
def test_missing_tls_stores_null(tls_info):
    assert db.build_scan_row(make_result(tls_info=tls_info))["tls_protocol"] is None


def test_missing_tls_key_entirely():
    result = make_result()
    del result["tls_info"]
    assert db.build_scan_row(result)["tls_protocol"] is None


def test_missing_final_url_stores_null_tls():
    result = make_result()
    del result["final_url"]
    row = db.build_scan_row(result)
    assert row["final_url"] is None and row["tls_protocol"] is None


def test_large_tracker_list():
    row = db.build_scan_row(make_result(trackers=many_trackers(75)))
    assert row["tracker_count"] == 75 and len(row["trackers"]) == 75


@pytest.mark.parametrize("score", [-1, 101, 82.5, "82", None, True, float("nan")])
def test_bad_score_rejected(score):
    with pytest.raises(ValueError, match="score"):
        db.build_scan_row(make_result(score=score))


@pytest.mark.parametrize("grade", ["E", "b", "", None, "AB"])
def test_bad_grade_rejected(grade):
    with pytest.raises(ValueError, match="grade"):
        db.build_scan_row(make_result(grade=grade))


@pytest.mark.parametrize("breakdown", [{}, None, {"likelihood": math.nan, "impact": 1.0},
                                       {"likelihood": 1.0, "impact": math.inf},
                                       {"likelihood": "3", "impact": 1.0}])
def test_bad_breakdown_rejected(breakdown):
    with pytest.raises(ValueError, match="breakdown"):
        db.build_scan_row(make_result(breakdown=breakdown))


@pytest.mark.parametrize("bad", [{"prevalence": 1.5}, {"prevalence": -0.1}, {"prevalence": math.nan},
                                 {"domain": ""}, {"domain": None}, {"fingerprinting": "high"}])
def test_bad_tracker_rejected(bad):
    tracker = {**make_result()["trackers"][0], **bad}
    with pytest.raises(ValueError):
        db.build_scan_row(make_result(trackers=[tracker]))


def test_nan_anywhere_in_result_rejected():
    with pytest.raises(ValueError):
        db.build_scan_row(make_result(cookies=[{"domain": "example.com", "expires": math.nan}]))


def test_url_without_host_rejected():
    with pytest.raises(ValueError, match="host"):
        db.build_scan_row(make_result(url="https://"))


# ---------- PostgreSQL integration ----------

needs_db = pytest.mark.skipif(not TEST_DSN, reason="set TEST_DATABASE_URL to run PostgreSQL tests")


def run(coro):
    return asyncio.run(coro)


async def fresh_db():
    import asyncpg
    conn = await asyncpg.connect(TEST_DSN)
    await conn.execute("DROP TABLE IF EXISTS scan_trackers, scans")
    await conn.close()
    await db.init_db(TEST_DSN)


@needs_db
def test_same_url_twice_keeps_both_rows_newest_first():
    async def body():
        await fresh_db()
        try:
            first = await db.save_scan(make_result(score=70, grade="C"))
            second = await db.save_scan(make_result(score=82, grade="B"))
            history = await db.get_history("example.com")
            assert [h["id"] for h in history] == [second, first]
            assert [h["score"] for h in history] == [82, 70]
        finally:
            await db.close_db()
    run(body())


@needs_db
def test_history_groups_url_variants_and_separates_sites():
    async def body():
        await fresh_db()
        try:
            await db.save_scan(make_result(url="https://www.example.com/a"))
            await db.save_scan(make_result(url="http://example.com/b"))
            await db.save_scan(make_result(url="https://other.org"))
            assert len(await db.get_history("EXAMPLE.com")) == 2
            assert len(await db.get_history("other.org")) == 1
            assert await db.get_history("never-scanned.com") == []
        finally:
            await db.close_db()
    run(body())


@needs_db
def test_empty_trackers_and_missing_tls_round_trip():
    async def body():
        await fresh_db()
        try:
            scan_id = await db.save_scan(make_result(trackers=[], tls_info={}))
            [h] = await db.get_history("example.com")
            assert h["tracker_count"] == 0 and h["tls_protocol"] is None
            stored = await db.get_scan(scan_id)
            assert stored["trackers"] == [] and stored["scan_id"] == scan_id
        finally:
            await db.close_db()
    run(body())


@needs_db
def test_large_tracker_list_round_trip():
    async def body():
        await fresh_db()
        try:
            trackers = many_trackers(120)
            scan_id = await db.save_scan(make_result(trackers=trackers))
            async with db._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT domain, prevalence, categories, fingerprinting FROM scan_trackers "
                    "WHERE scan_id = $1 ORDER BY domain", scan_id)
            assert len(rows) == 120
            expected = sorted((t["domain"], t["prevalence"], t["categories"], t["fingerprinting"]) for t in trackers)
            assert [tuple(r) for r in rows] == expected
        finally:
            await db.close_db()
    run(body())


@needs_db
def test_failed_insert_leaves_no_partial_scan():
    async def body():
        await fresh_db()
        try:
            dup = make_result()["trackers"][0]
            with pytest.raises(Exception):
                # duplicate tracker domain violates the primary key midway through the batch
                await db.save_scan(make_result(trackers=[dup, dup]))
            async with db._pool.acquire() as conn:
                assert await conn.fetchval("SELECT count(*) FROM scans") == 0
                assert await conn.fetchval("SELECT count(*) FROM scan_trackers") == 0
        finally:
            await db.close_db()
    run(body())


@needs_db
def test_db_constraints_reject_bad_data_even_if_validation_bypassed():
    async def body():
        await fresh_db()
        try:
            import asyncpg
            async with db._pool.acquire() as conn:
                with pytest.raises(asyncpg.CheckViolationError):
                    await conn.execute(
                        "INSERT INTO scans (url, host, score, grade, likelihood, impact, tracker_count, "
                        "cookie_count, result) VALUES ('x', 'x', 150, 'A', 0, 0, 0, 0, '{}')")
                with pytest.raises(asyncpg.CheckViolationError):
                    await conn.execute(
                        "INSERT INTO scans (url, host, score, grade, likelihood, impact, tracker_count, "
                        "cookie_count, result) VALUES ('x', 'x', 50, 'Z', 0, 0, 0, 0, '{}')")
        finally:
            await db.close_db()
    run(body())


@needs_db
def test_init_db_is_idempotent():
    async def body():
        await fresh_db()
        await db.close_db()
        assert await db.init_db(TEST_DSN)  # schema already exists - must not error
        await db.close_db()
    run(body())
