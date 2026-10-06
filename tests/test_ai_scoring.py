"""Validate evidence provenance and prevent unsupported model scores/detections."""

import json
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from ai_analyzer import analyze_with_ai, api_retry_delay
from google.genai.errors import APIError
from ai_scoring import GeminiEvidenceSchema, RiskAssessment, score_evidence, EvidenceSelections, evidence_catalog, resolve_selections


def assessment(harm=0, deception=0, pressure=0, link_risk=0, quote="message"):
    return RiskAssessment.model_validate({
        name: {"level": level, "evidence": [quote] if level else [], "reason": "Observed evidence"}
        for name, level in zip(("harm", "deception", "pressure", "link_risk"), (harm, deception, pressure, link_risk))
    })


def wire_assessment(harm=0, ref="text:0"):
    return {
        name: {"level": harm if name == "harm" else 0, "evidence": [ref] if name == "harm" and harm else [], "reason": "Observed evidence"}
        for name in ("harm", "deception", "pressure", "link_risk")
    }


def test_fabricated_evidence_is_rejected():
    with pytest.raises(ValueError, match="not present"):
        score_evidence(assessment(harm=4, quote="send password"), "hello", [])


def test_positive_level_requires_evidence():
    factors = assessment(harm=4)
    factors.harm.evidence = []
    with pytest.raises(ValueError, match="requires quoted evidence"):
        score_evidence(factors, "message", [])


def test_kb_phrase_and_vt_report_cannot_justify_message_harm():
    with pytest.raises(ValueError, match="not present"):
        score_evidence(assessment(harm=4, quote="send password"), "hello", [{"note": "send password"}])


@pytest.mark.parametrize("level", [3, 4])
def test_unknown_report_cannot_be_claimed_as_a_detection(level):
    with pytest.raises(ValueError, match="requires a .*VirusTotal report"):
        score_evidence(assessment(link_risk=level, quote="https://example.com"), "https://example.com", [{"verdict": "unknown"}])


def test_actual_malicious_report_can_support_link_evidence():
    result = score_evidence(
        assessment(link_risk=4, quote="https://example.com"), "https://example.com",
        [{"url": "https://example.com", "verdict": "malicious"}],
    )
    assert result["score_breakdown"]["link_risk"] == 4


def test_link_factor_requires_an_actual_url():
    with pytest.raises(ValueError, match="requires a URL"):
        score_evidence(assessment(link_risk=1), "message", [])


def test_detection_for_one_url_cannot_be_attributed_to_another():
    with pytest.raises(ValueError, match="cite the URL"):
        score_evidence(
            assessment(link_risk=4, quote="https://safe.example"),
            "https://safe.example https://evil.example",
            [{"url": "https://safe.example", "verdict": "safe"}, {"url": "https://evil.example", "verdict": "malicious"}],
        )


def test_backend_ignores_model_proposed_total():
    client = MagicMock()
    client.models.generate_content.return_value.text = json.dumps({
        "scam_type": "Scam", "ai_summary": "Evidence of a harmful request",
        "ai_confidence": 95,
        "risk_assessment": wire_assessment(harm=3),
    })
    result = analyze_with_ai("message", client=client, ai_only=True)
    assert result["ai_confidence"] == 68
    assert result["scoring_method"] == "evidence_rubric_v1"
    assert "ai_confidence" not in GeminiEvidenceSchema.model_json_schema()["properties"]


def test_boolean_or_out_of_range_levels_are_invalid():
    for invalid in [True, -1, 5, "4"]:
        with pytest.raises(ValidationError):
            assessment(harm=invalid)


def test_invalid_evidence_does_not_silently_use_model_total(monkeypatch):
    monkeypatch.setattr("ai_analyzer.time.sleep", lambda _: None)
    client = MagicMock()
    client.models.generate_content.return_value.text = json.dumps({
        "scam_type": "Scam", "ai_summary": "Claim without evidence", "ai_confidence": 95,
        "risk_assessment": wire_assessment(harm=4, ref="text:999"),
    })
    with pytest.raises(RuntimeError, match="no fallback score"):
        analyze_with_ai("hello", client=client, ai_only=True)


def test_invalid_quote_gets_specific_repair_request():
    client = MagicMock()
    invalid = {"scam_type": "Scam", "ai_summary": "Suspicious", "risk_assessment": wire_assessment(harm=3, ref="text:999")}
    valid = {"scam_type": "Scam", "ai_summary": "Suspicious", "risk_assessment": wire_assessment(harm=3)}
    client.models.generate_content.side_effect = [
        MagicMock(text=json.dumps(invalid)), MagicMock(text=json.dumps(valid)),
    ]
    result = analyze_with_ai("message", client=client, ai_only=True)
    assert result["ai_confidence"] == 68
    assert client.models.generate_content.call_count == 2
    repair_prompt = client.models.generate_content.call_args_list[1].kwargs["contents"]
    assert "harm: evidence reference is not supplied" in repair_prompt
    assert "ห้ามเรียบเรียงใหม่" in repair_prompt
    assert "'text:999'" in repair_prompt


def test_reference_resolution_preserves_exact_original_words():
    message = "เริ่มงานด้วยการเติมเงิน 300 บาท รับคืนพร้อมค่าจ้างหลังทำภารกิจแรก"
    catalog = evidence_catalog(message, [])
    ref = next(key for key, value in catalog.items() if value == "เริ่มงานด้วยการเติมเงิน 300 บาท")
    selections = EvidenceSelections.model_validate(wire_assessment(harm=3, ref=ref))
    resolved = resolve_selections(selections, message, [])
    assert resolved.harm.evidence == ["เริ่มงานด้วยการเติมเงิน 300 บาท"]
    assert "เริ่มต้น" not in resolved.harm.evidence[0]
    assert score_evidence(resolved, message, [])["ai_confidence"] == 68


def test_url_reference_cannot_substitute_for_message_evidence():
    selections = EvidenceSelections.model_validate(wire_assessment(harm=3, ref="url:0"))
    with pytest.raises(ValueError, match="only support link_risk"):
        resolve_selections(selections, "hello", [{"url": "https://example.com"}])


def test_quota_retry_honors_server_delay():
    error = APIError(429, {"error": {"details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "27s"}]}})
    assert api_retry_delay(error, 1.5) == 28


def test_quota_without_retry_hint_keeps_backoff():
    assert api_retry_delay(APIError(429, {"error": {"message": "quota exceeded"}}), 3) == 3
