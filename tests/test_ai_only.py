"""Checks that AI-only testing ignores external signals and never scores API failure."""

import json
from unittest.mock import MagicMock

import pytest

import ai_analyzer
from tests.evidence_fixtures import evidence_payload
import run_ai_only


def make_client(score=90, text="message"):
    client = MagicMock()
    client.models.generate_content.return_value.text = json.dumps(evidence_payload(score, text))
    return client


def test_ai_only_prompt_ignores_external_context():
    client = make_client(text="Send OTP to https://example.com")
    result = ai_analyzer.analyze_with_ai(
        "Send OTP to https://example.com", client=client, ai_only=True,
        vt_results=[{"url": "VT_SENTINEL", "verdict": "safe"}],
        kb_result={"kb_score": 100, "matched_categories": ["KB_SENTINEL"], "matched_phrases": ["PHRASE_SENTINEL"]},
    )
    prompt = client.models.generate_content.call_args.kwargs["contents"]
    assert "https://example.com" in prompt
    for sentinel in ["VT_SENTINEL", "KB_SENTINEL", "PHRASE_SENTINEL", "Knowledge Base", "KB Score", "[ผลตรวจลิงก์จาก VirusTotal]"]:
        assert sentinel not in prompt
    assert result["ai_confidence"] == 90


def test_ai_only_unavailable_client_is_error(monkeypatch):
    monkeypatch.setattr(ai_analyzer, "_get_genai_client", lambda: None)
    with pytest.raises(RuntimeError, match="client unavailable"):
        ai_analyzer.analyze_with_ai("message", ai_only=True)


def test_ai_only_bad_json_never_returns_fallback():
    client = make_client()
    client.models.generate_content.return_value.text = "not json"
    with pytest.raises(RuntimeError, match="no fallback score"):
        ai_analyzer.analyze_with_ai("message", client=client, ai_only=True)


def test_ai_only_invalid_score_rejected(monkeypatch):
    monkeypatch.setattr(ai_analyzer.time, "sleep", lambda _: None)
    with pytest.raises(RuntimeError, match="no fallback score"):
        ai_analyzer.analyze_with_ai("message", client=make_client(120), ai_only=True)


def test_runner_uses_ai_score_without_weighting():
    result = run_ai_only.inspect_message("message", make_client(78))
    assert result["ai_result"]["ai_confidence"] == 78
    assert result["risk_level"] == "สูง"


def test_case_runner_counts_api_errors_as_failures(monkeypatch, tmp_path):
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(json.dumps([{"id": 1, "description": "benign", "text": "hello", "expected_risk": "ต่ำ"}]), encoding="utf-8")
    monkeypatch.setattr(run_ai_only, "TEST_CASES_FILE", cases_path)
    monkeypatch.setattr(run_ai_only, "inspect_message", MagicMock(side_effect=RuntimeError("API unavailable")))
    report = run_ai_only.run_cases(make_client(), json_output=True)
    assert report["errors"] == 1
    assert report["passed"] == 0
    assert "risk_level" not in report["results"][0]
