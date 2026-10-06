from io import BytesIO
import json
import logging
import threading
import time
import urllib.request
import urllib.error
import pytest
from PIL import Image
import config
from history_store import HistoryStore
from web_server import JobStore, make_server, RESULT_TTL
from tests.supabase_fake import MemoryDataAPI


def synthetic_check(text, *, progress):
    progress("ai")
    return {"input_text": text, "risk": {"risk_level": "สูง", "risk_score": 68, "scam_type": "ทดสอบ", "reasons": ["หลักฐานทดสอบ"]},
            "ai_result": {"analysis_status": "ok", "ai_confidence": 68, "ai_summary": "รายงานทดสอบ", "risk_assessment": {"harm": {"level": 3, "evidence": [text], "reason": "หลักฐานทดสอบ"}}},
            "kb_result": {"kb_status": "ready", "kb_score": 0, "matched_phrases": []}, "vt_results": [], "analysis_mode": "independent_ai"}


@pytest.fixture
def feature_service(monkeypatch):
    monkeypatch.setattr(config, "GEMINI_API_KEY", "unit-secret")
    database = MemoryDataAPI()
    release = threading.Event()
    calls = []
    def ocr(data, mime):
        calls.append((data, mime))
        release.wait(2)
        return {"text": "ข้อความจากภาพ", "warnings": []}
    store = JobStore(synthetic_check, ocr)
    server = make_server(0, store, HistoryStore(database.client, sleep=lambda _: None))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", store, database, release, calls
    release.set()
    server.shutdown()
    server.server_close()
    thread.join(2)


def request(base, path, method="GET", payload=None, data=None, headers=None):
    headers = headers or {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    body = response.read()
    return response.status, json.loads(body) if response.headers.get_content_type() == "application/json" else body


def wait(base, job_id):
    for _ in range(100):
        status, result = request(base, f"/api/jobs/{job_id}")
        assert status == 200
        if result["status"] != "running":
            return result
        time.sleep(.01)
    pytest.fail("job timed out")


def image_bytes():
    output = BytesIO()
    Image.new("RGB", (20, 30), "white").save(output, "PNG")
    return output.getvalue()


def test_full_report_history_snapshot_and_mutations(feature_service):
    base, store, database, _, _ = feature_service
    status, submitted = request(base, "/api/check", "POST", {"message": "ฉบับแก้ไขจากภาพ", "source_type": "image"})
    assert status == 202
    report = wait(base, submitted["job_id"])["result"]
    assert report["metadata"]["source_type"] == "image"
    assert report["metadata"]["analyzed_at"]
    assert "".join(part["text"] for part in report["evidence_highlights"]["segments"]) == report["input_text"]
    status, saved = request(base, "/api/history", "POST", {"job_id": submitted["job_id"], "report_json": {"fake": True}})
    assert status == 200
    record_id = saved["id"]
    assert request(base, f"/api/history/{record_id}", "PATCH", {"is_starred": True})[0] == 200
    assert request(base, "/api/history?starred=true")[1]["total"] == 1
    assert request(base, "/api/history", "POST", {"job_id": submitted["job_id"]})[1]["id"] == record_id
    assert len(database.rows) == 1
    detail = request(base, f"/api/history/{record_id}")[1]
    assert detail["report_json"] == report
    assert "fake" not in detail["report_json"]
    assert request(base, "/api/history", "DELETE", {"confirm": "no"})[0] == 400
    assert request(base, f"/api/history/{record_id}", "DELETE")[0] == 200
    assert request(base, "/api/history")[1]["total"] == 0


def test_ocr_jobs_share_slot_and_cannot_be_saved_as_reports(feature_service):
    base, store, _, release, calls = feature_service
    status, submitted = request(base, "/api/ocr", "POST", data=image_bytes(), headers={"Content-Type": "image/png"})
    assert status == 202
    assert request(base, "/api/check", "POST", {"message": "ซ้อน"})[0] == 429
    assert request(base, "/api/history", "POST", {"job_id": submitted["job_id"]})[0] == 400
    release.set()
    job = wait(base, submitted["job_id"])
    assert job["kind"] == "ocr"
    assert job["result"]["text"] == "ข้อความจากภาพ"
    assert request(base, "/api/history", "POST", {"job_id": submitted["job_id"]})[0] == 400
    assert len(calls) == 1
    assert request(base, "/api/check", "POST", {"message": "หลังภาพ"})[0] == 202


def test_invalid_image_and_invalid_source_do_not_start_jobs(feature_service):
    base, store, _, _, calls = feature_service
    assert request(base, "/api/ocr", "POST", data=b"bad", headers={"Content-Type": "image/png"})[0] == 400
    assert request(base, "/api/check", "POST", {"message": "test", "source_type": "fake"})[0] == 400
    assert not calls
    assert not store.jobs


def test_history_guards_logs_and_missing_config(feature_service, caplog, monkeypatch):
    base, store, _, _, _ = feature_service
    for method, payload in [("POST", {"job_id": "a" * 32}), ("PATCH", {"is_starred": True}), ("DELETE", None)]:
        path = "/api/history" if method == "POST" else "/api/history/00000000-0000-0000-0000-000000000001"
        assert request(base, path, method, payload, headers={"Origin": "https://untrusted.invalid"})[0] == 403
    with caplog.at_level(logging.INFO, logger="web_server"):
        request(base, "/api/history?q=secret-search-text")
    assert "secret-search-text" not in caplog.text
    assert "unit-secret" not in json.dumps(request(base, "/api/status")[1])
    assert request(base, "/supabase/migrations/20261004000100_saved_checks.sql")[0] == 404


def test_expired_job_not_saved_and_delete_all_confirmation(feature_service):
    base, store, database, _, _ = feature_service
    _, submitted = request(base, "/api/check", "POST", {"message": "ผลชั่วคราว"})
    wait(base, submitted["job_id"])
    request(base, "/api/history", "POST", {"job_id": submitted["job_id"]})
    with store.lock:
        store.jobs[submitted["job_id"]]["finished_at"] = time.monotonic() - RESULT_TTL - 1
    assert request(base, "/api/history", "POST", {"job_id": submitted["job_id"]})[0] == 404
    assert request(base, "/api/history", "DELETE", {"confirm": "delete_all_history"})[0] == 200
    assert not database.rows
