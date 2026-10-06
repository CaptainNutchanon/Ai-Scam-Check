"""Verify VT evidence reaches Gemini, while KB signals and fallback scores do not."""

import json
import subprocess
import sys
from unittest.mock import MagicMock

import pytest
import requests

import ai_analyzer
from tests.evidence_fixtures import evidence_payload
import run_gemini_vt
import virustotal_checker as vt


def make_client(score=90, text="message"):
    client = MagicMock()
    client.models.generate_content.return_value.text = json.dumps(evidence_payload(score, text))
    return client


def test_no_kb_prompt_preserves_vt_evidence():
    client = make_client()
    ai_analyzer.analyze_with_ai(
        "message", vt_results=[{"url": "https://vt-evidence.example", "verdict": "unknown"}],
        kb_result={"kb_score": 100, "matched_phrases": ["KB_SENTINEL"]},
        client=client, use_knowledge_base=False,
    )
    prompt = client.models.generate_content.call_args.kwargs["contents"]
    assert "VirusTotal" in prompt
    assert "https://vt-evidence.example" in prompt
    assert "unknown" in prompt
    assert "KB_SENTINEL" not in prompt
    assert "Knowledge Base" not in prompt
    assert "KB Score" not in prompt


def test_no_kb_api_failure_has_no_fallback():
    client = make_client()
    client.models.generate_content.return_value.text = "not json"
    with pytest.raises(RuntimeError, match="no fallback score"):
        ai_analyzer.analyze_with_ai("message", client=client, use_knowledge_base=False)


def test_runner_deobfuscates_and_checks_unique_links(monkeypatch):
    check = MagicMock(return_value={"url": "http://evil.example/path", "verdict": "unknown", "total_engines": 0})
    monkeypatch.setattr(run_gemini_vt, "check_url", check)
    client = make_client(80, "hxxp://evil[.]example/path http://evil.example/path")
    result = run_gemini_vt.inspect_message("hxxp://evil[.]example/path http://evil.example/path", client)
    check.assert_called_once_with("http://evil.example/path")
    assert result["risk_level"] == "สูง"
    assert result["ai_result"]["ai_confidence"] == 80
    assert result["decision_source"] == "gemini"
    assert "unknown" in client.models.generate_content.call_args.kwargs["contents"]


def test_malicious_link_overrides_low_ai_without_changing_its_score(monkeypatch):
    monkeypatch.setattr(run_gemini_vt, "check_url", lambda url: {"url": url, "verdict": "malicious"})
    result = run_gemini_vt.inspect_message("https://evil.example", make_client(5, "https://evil.example"))
    assert result["risk_level"] == "สูง"
    assert result["ai_result"]["ai_confidence"] == 5
    assert result["decision_source"] == "virustotal_malicious_override"


def test_no_links_makes_no_vt_call(monkeypatch):
    check = MagicMock()
    monkeypatch.setattr(run_gemini_vt, "check_url", check)
    result = run_gemini_vt.inspect_message("hello", make_client(0))
    check.assert_not_called()
    assert result["vt_results"] == []
    assert result["risk_level"] == "ต่ำ"


def test_vt_404_response_submits_scan(monkeypatch):
    missing = requests.Response()
    missing.status_code = 404  # Real Response is falsey; still must trigger submission.
    submitted = requests.Response()
    submitted.status_code = 200
    report = requests.Response()
    report.status_code = 200
    report._content = b'{"data":{"attributes":{"last_analysis_stats":{"harmless":1}}}}'
    request = MagicMock(side_effect=[missing, submitted, report])
    monkeypatch.setattr(vt, "_make_request_with_retry", request)
    monkeypatch.setattr(vt.time, "sleep", lambda _: None)
    monkeypatch.setattr(vt.config, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "_CACHE", {})
    result = vt.check_url("https://new.example")
    assert [call.args[0] for call in request.call_args_list] == ["GET", "POST", "GET"]
    assert result["scan_submitted"] is True
    assert result["verdict"] == "safe"


def test_vt_http_failure_is_unknown_with_error(monkeypatch):
    unauthorized = requests.Response()
    unauthorized.status_code = 401
    monkeypatch.setattr(vt, "_make_request_with_retry", lambda *a, **kw: unauthorized)
    monkeypatch.setattr(vt.config, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "_CACHE", {})
    result = vt.check_url("https://error.example")
    assert result["verdict"] == "unknown"
    assert result["error"] == "VirusTotal HTTP 401"


def test_scan_submission_failure_is_reported_as_error(monkeypatch):
    missing = requests.Response()
    missing.status_code = 404
    forbidden = requests.Response()
    forbidden.status_code = 403
    monkeypatch.setattr(vt, "_make_request_with_retry", MagicMock(side_effect=[missing, forbidden]))
    monkeypatch.setattr(vt.config, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "_CACHE", {})
    result = vt.check_url("https://scan-failed.example")
    assert result["verdict"] == "unknown"
    assert result["error"] == "VirusTotal HTTP 403"
    assert result["scan_submitted"] is False


def test_runner_import_does_not_load_knowledge_base():
    result = subprocess.run(
        [sys.executable, "-B", "-c", "import run_gemini_vt, sys; assert not any(m.startswith('knowledge_base') for m in sys.modules)"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
