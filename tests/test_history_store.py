from copy import deepcopy
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
import config
from history_store import HistoryStore, HistoryError
from tests.supabase_fake import MemoryDataAPI


def report(text="ข้อความ OTP %_*", score=68):
    return {"input_text": text, "risk": {"risk_level": "สูง", "risk_score": score},
            "metadata": {"source_type": "image", "report_version": 1, "analysis_status": "partial",
                         "analyzed_at": "2026-10-03T18:30:00+00:00"}}


@pytest.fixture
def history():
    api = MemoryDataAPI()
    return HistoryStore(api.client, sleep=lambda _: None), api


def test_idempotent_save_preserves_snapshot_and_star(history):
    store, api = history
    first = store.save("a" * 32, report())
    store.star(first["id"], True)
    replacement = report("edited after save", 99)
    second = store.save("a" * 32, replacement)
    assert second["id"] == first["id"]
    assert second["is_starred"]
    assert store.get(first["id"])["report_json"] == report()
    assert len(api.rows) == 1


def test_concurrent_same_job_never_creates_duplicate(history):
    store, api = history
    with ThreadPoolExecutor(4) as pool:
        ids = list(pool.map(lambda _: store.save("b" * 32, report())["id"], range(8)))
    assert len(set(ids)) == 1
    assert len(api.rows) == 1


def test_timeout_after_commit_is_reconciled_by_job_id(history):
    store, api = history
    api.timeout_after_insert = True
    saved = store.save("c" * 32, report())
    assert saved["id"] in api.rows
    assert len(api.rows) == 1


def test_offline_errors_do_not_expose_details(history):
    store, api = history
    api.offline = True
    with pytest.raises(HistoryError) as error:
        store.save("d" * 32, report())
    assert "ยืนยัน" in str(error.value)
    assert "private" not in str(error.value)
    assert len(api.requests) == 3  # One write, two reconciliation reads.


def test_literal_thai_search_and_timezone_boundaries(history):
    store, api = history
    first = store.save("e" * 32, report())
    store.save("f" * 32, report("OTP without special characters"))
    zone = timezone(timedelta(hours=7))
    results = store.list(query="%_*", start=datetime(2026, 10, 4, tzinfo=zone), end=datetime(2026, 10, 5, tzinfo=zone))
    assert results["total"] == 1
    assert results["items"][0]["id"] == first["id"]
    assert "report_json" not in results["items"][0]
    store.star(first["id"], True)
    assert store.list(starred=True)["total"] == 1


def test_pagination_and_null_scores(history):
    store, _ = history
    item = report(score=None)
    item["risk"]["risk_level"] = "ไม่สามารถประเมินได้"
    item["metadata"]["analysis_status"] = "unavailable"
    for index in range(21):
        store.save(str(index).zfill(32), item)
    assert len(store.list()["items"]) == 20
    assert len(store.list(page=2)["items"]) == 1
    assert all(row["risk_score"] is None for row in store.list()["items"])


def test_delete_one_then_all(history):
    store, api = history
    first = store.save("g" * 32, report())
    store.save("h" * 32, report())
    store.delete(first["id"])
    assert len(api.rows) == 1
    store.delete()
    assert not api.rows


def test_missing_configuration_and_invalid_filters(monkeypatch):
    monkeypatch.setattr(config, "SUPABASE_URL", "")
    monkeypatch.setattr(config, "SUPABASE_SECRET_KEY", "")
    store = HistoryStore()
    assert not store.configured
    with pytest.raises(HistoryError, match="SUPABASE_URL"):
        store.list()
    for kwargs in ({"page": 0}, {"level": "invalid"}, {"query": "x" * 201}, {"start": datetime(2026, 10, 4)}):
        with pytest.raises(ValueError):
            store.list(**kwargs)
    with pytest.raises(ValueError):
        store.get("not-a-uuid")
