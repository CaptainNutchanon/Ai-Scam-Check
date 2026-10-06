"""Exercise HTTP boundaries and background jobs without spending provider quota."""

import json
import threading
import time
import urllib.error
import urllib.request

import pytest
import config
from web_server import JobStore, make_server, RESULT_TTL
from main import check_message


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setattr(config, "GEMINI_API_KEY", "test-secret-never-sent-to-browser")
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "test-vt-secret")
    release = threading.Event()

    def checker(text, *, progress):
        progress("ai")
        release.wait(3)
        if text == "trigger error":
            raise RuntimeError("private-provider-error")
        return {"input_text": text, "risk": {"risk_score": 12, "risk_level": "ต่ำ"}}

    store = JobStore(checker)
    server = make_server(0, store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    yield base, store, release
    release.set()
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def request(base, path, payload=None, **headers):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    if data is not None:
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    return response.status, response.headers, response.read()


def finish(base, job_id):
    for _ in range(100):
        status, _, body = request(base, "/api/jobs/" + job_id)
        assert status == 200
        job = json.loads(body)
        if job["status"] != "running":
            return job
        time.sleep(.01)
    pytest.fail("Background analysis did not finish")


def test_real_job_is_nonblocking_and_single_flight(service):
    base, _, release = service
    status, _, body = request(base, "/api/check", {"message": "ข้อความทดสอบ"})
    assert status == 202
    job_id = json.loads(body)["job_id"]
    status, _, body = request(base, "/api/jobs/" + job_id)
    assert status == 200
    assert json.loads(body)["status"] == "running"
    assert request(base, "/")[0] == 200  # Page still responds while AI waits.
    assert request(base, "/api/check", {"message": "รายการซ้อน"})[0] == 429
    release.set()
    job = finish(base, job_id)
    assert job["status"] == "done"
    assert job["result"]["input_text"] == "ข้อความทดสอบ"
    assert job["result"]["risk"]["risk_score"] == 12


@pytest.mark.parametrize("payload", [{"message": "   "}, {"message": 123}, [], {"message": "x" * 4001}, {"message": "https://a.invalid https://b.invalid https://c.invalid https://d.invalid"}])
def test_invalid_input_never_starts_analysis(service, payload):
    base, store, _ = service
    assert request(base, "/api/check", payload)[0] == 400
    assert not store.jobs


def test_secret_files_and_cross_origin_calls_are_blocked(service):
    base, store, _ = service
    for path in ["/.env", "/virustotalapi.txt", "/../.env", "/main.py"]:
        assert request(base, path)[0] == 404
    assert request(base, "/api/check", {"message": "ทดสอบ"}, Origin="https://other.example")[0] == 403
    assert request(base, "/api/check", {"message": "ทดสอบ"}, Host="other.example")[0] == 403
    assert not store.jobs
    status, headers, body = request(base, "/api/status")
    assert status == 200
    assert b"test-secret" not in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_missing_gemini_is_an_explicit_error(service, monkeypatch):
    base, store, _ = service
    monkeypatch.setattr(config, "GEMINI_API_KEY", "")
    assert request(base, "/api/check", {"message": "ทดสอบ"})[0] == 503
    assert not store.jobs


def test_failed_analysis_does_not_leak_provider_details(service):
    base, _, release = service
    release.set()
    status, _, body = request(base, "/api/check", {"message": "trigger error"})
    assert status == 202
    job = finish(base, json.loads(body)["job_id"])
    assert job["status"] == "error"
    assert "private-provider-error" not in json.dumps(job)


def test_expired_results_are_removed_from_memory(service):
    base, store, release = service
    release.set()
    status, _, body = request(base, "/api/check", {"message": "temporary result"})
    assert status == 202
    job_id = json.loads(body)["job_id"]
    finish(base, job_id)
    with store.lock:
        store.jobs[job_id]["finished_at"] = time.monotonic() - RESULT_TTL - 1
    store.cleanup()
    assert job_id not in store.jobs
    assert request(base, "/api/jobs/" + job_id)[0] == 404


def test_pipeline_progress_keeps_existing_scoring(monkeypatch):
    stages = []
    monkeypatch.setattr("main.check_url", lambda url: {"url": url, "verdict": "safe", "malicious_count": 0, "total_engines": 80})
    monkeypatch.setattr("main.analyze_with_ai", lambda *args: {"analysis_status": "ok", "ai_confidence": 12, "scam_type": "ข้อความทั่วไป", "ai_summary": "ทดสอบ", "indicators": []})
    text = "รายละเอียดเพิ่มเติม https://example.org"
    observed = check_message(text, progress=stages.append)
    assert observed == check_message(text)
    assert stages == ["parsing", "links", "knowledge_base", "ai", "scoring"]
