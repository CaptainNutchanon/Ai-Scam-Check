"""Regression checks for independent Gemini analysis when the KB has no match."""

import json
from unittest.mock import MagicMock

import pytest

import ai_analyzer
from tests.evidence_fixtures import evidence_payload
import main
from knowledge_base import check_knowledge_base
from risk_engine import calculate_risk


EMPTY_KB = {"matched_categories": [], "matched_phrases": [], "kb_score": 0}
EXTORTION_TEXT = "ฉันรู้ว่าคุณทำอะไรไว้ ถ้าไม่ส่งเงินเข้ามาจะส่งรูปที่แอบถ่ายให้ทุกคนในรายชื่อของคุณ"


def make_client(score, text="message"):
    client = MagicMock()
    client.models.generate_content.return_value.text = json.dumps(evidence_payload(score, text))
    return client


def test_kb_miss_prompt_is_independent_and_keeps_link_evidence():
    prompt = ai_analyzer.build_analysis_prompt(
        EXTORTION_TEXT, [{"url": "https://test.example", "verdict": "unknown"}], EMPTY_KB,
    )
    assert EXTORTION_TEXT in prompt
    assert "https://test.example" in prompt
    assert "unknown" in prompt
    assert "KB Score" not in prompt
    assert "Knowledge Base" not in prompt


def test_kb_match_prompt_still_contains_evidence_and_allows_new_patterns():
    prompt = ai_analyzer.build_analysis_prompt(
        "message", [], {"kb_score": 30, "matched_categories": ["urgency"], "matched_phrases": ["ด่วนที่สุด"]},
    )
    assert "30/100" in prompt
    assert "ด่วนที่สุด" in prompt
    assert "ไม่ใช่ข้อจำกัดในการวิเคราะห์" in prompt


@pytest.mark.parametrize("verdict", [None, "safe", "unknown"])
@pytest.mark.parametrize("score,level", [(5, "ต่ำ"), (50, "ปานกลาง"), (68, "สูง")])
def test_kb_miss_does_not_dilute_ai_score(verdict, score, level):
    links = [] if verdict is None else [{"verdict": verdict, "url": "https://test.example"}]
    result = calculate_risk(links, EMPTY_KB, {"ai_confidence": score, "indicators": []})
    expected_score = score
    assert result["risk_score"] == expected_score
    assert result["risk_level"] == level
    assert result["score_source"] == "ai_and_virustotal"


def test_main_analyzes_a_real_kb_miss_independently(monkeypatch):
    assert check_knowledge_base(EXTORTION_TEXT)["matched_phrases"] == []
    client = make_client(68, EXTORTION_TEXT)
    monkeypatch.setattr(ai_analyzer, "_get_genai_client", lambda: client)
    result = main.check_message(EXTORTION_TEXT)
    assert result["analysis_mode"] == "independent_ai"
    assert result["kb_result"]["kb_score"] == 0
    assert result["risk"]["risk_level"] == "สูง"
    assert result["risk"]["risk_score"] == 68
    assert result["ai_result"]["analysis_status"] == "ok"
    assert "Knowledge Base" not in client.models.generate_content.call_args.kwargs["contents"]


def test_main_keeps_kb_assisted_analysis_when_phrases_match(monkeypatch):
    client = make_client(86, "ด่วนที่สุด! คุณได้รับรางวัล")
    monkeypatch.setattr(ai_analyzer, "_get_genai_client", lambda: client)
    result = main.check_message("ด่วนที่สุด! คุณได้รับรางวัล")
    assert result["analysis_mode"] == "kb_assisted"
    assert result["kb_result"]["matched_phrases"]
    assert "Knowledge Base" in client.models.generate_content.call_args.kwargs["contents"]
    assert result["risk"]["score_source"] == "kb_ai_and_virustotal"


def test_kb_miss_and_unavailable_ai_is_not_reported_safe(monkeypatch):
    monkeypatch.setattr(ai_analyzer, "_get_genai_client", lambda: None)
    result = main.check_message(EXTORTION_TEXT)
    assert result["risk"]["risk_level"] == "ไม่สามารถประเมินได้"
    assert result["risk"]["risk_score"] is None
    display = main.format_cli_output(result)
    assert "ยังประเมินไม่ได้" in display
    assert "LOW RISK / SAFE" not in display
    assert "Confidence:" not in display


def test_malicious_link_still_overrides_when_kb_and_ai_unavailable():
    result = calculate_risk(
        [{"url": "https://evil.example", "verdict": "malicious"}], EMPTY_KB,
        {"analysis_status": "unavailable", "ai_confidence": 0},
    )
    assert result["risk_level"] == "สูง"
    assert result["risk_score"] >= 90
