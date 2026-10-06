"""
Unit tests for ai_analyzer.py
"""

from unittest.mock import MagicMock
import json
import pytest
from tests.evidence_fixtures import evidence_payload
from ai_analyzer import analyze_with_ai, build_analysis_prompt, AIAnalysisSchema


def test_empty_text():
    res = analyze_with_ai("")
    assert res["ai_confidence"] == 0
    assert "ว่างเปล่า" in res["ai_summary"]


def test_build_prompt_formatting():
    prompt = build_analysis_prompt(
        original_text="สวัสดี",
        vt_results=[{"url": "https://test.com", "verdict": "safe", "malicious_count": 0, "total_engines": 90}],
        kb_result={"matched_categories": ["urgency"], "matched_phrases": ["ด่วน"], "kb_score": 30},
    )
    assert "https://test.com" in prompt
    assert "urgency" in prompt
    assert "30/100" in prompt


def test_mock_successful_analysis():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = json.dumps(evidence_payload(
        95, "สแกมชัดเจน", scam_type="หลอกกดลิงก์ (Phishing)",
        summary="ข้อความนี้เป็นสแกมแน่นอนเนื่องจากแอบอ้างธนาคาร",
    ))
    mock_client.models.generate_content.return_value = mock_response

    res = analyze_with_ai("สแกมชัดเจน", client=mock_client)
    assert res["scam_type"] == "หลอกกดลิงก์ (Phishing)"
    assert res["ai_confidence"] == 95
    assert "แอบอ้างธนาคาร" in res["ai_summary"]
    assert res["risk_assessment"]["harm"]["level"] == 4
    assert res["score_breakdown"]["harm"] == 86


def test_mock_bad_json_fallback():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "NOT A JSON STRING"
    mock_client.models.generate_content.return_value = mock_response

    res = analyze_with_ai("ทดสอบ", client=mock_client)
    # Should gracefully return fallback without raising an unhandled exception
    assert "ไม่สามารถวิเคราะห์ด้วย AI ได้" in res["ai_summary"]
    assert "scam_type" in res
    assert isinstance(res["ai_confidence"], int)


def test_schema_validation():
    schema = AIAnalysisSchema(
        scam_type="ข้อความปลอดภัย/ไม่ใช่สแกม",
        ai_summary="ปลอดภัย",
        ai_confidence=10,
        indicators=["ข้อความปกติ"]
    )
    assert schema.scam_type == "ข้อความปลอดภัย/ไม่ใช่สแกม"
    assert schema.ai_confidence == 10
    assert schema.ai_summary == "ปลอดภัย"
