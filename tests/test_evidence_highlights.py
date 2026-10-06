from evidence_highlights import build_highlights


def ai(**factors):
    return {"analysis_status": "ok", "risk_assessment": factors}


def factor(quote):
    return {"level": 3, "evidence": [quote], "reason": "หลักฐานในข้อความ"}


def test_exact_unicode_and_overlapping_factors_preserve_original():
    text = "🛡️ ด่วน! แจ้งรหัส OTP\nแจ้งรหัส OTP <script>alert(1)</script>"
    result = build_highlights(text, ai(harm=factor("แจ้งรหัส OTP"), pressure=factor("OTP")))
    assert "".join(part["text"] for part in result["segments"]) == text
    assert any(len(part["evidence_ids"]) == 2 and part["text"] == "OTP" for part in result["segments"])
    assert all(ref["occurrences"] == 2 for ref in result["annotations"])


def test_unavailable_ai_and_level_zero_never_highlight():
    assert not build_highlights("OTP", {"analysis_status": "unavailable", "risk_assessment": {"harm": factor("OTP")}})["annotations"]
    assert not build_highlights("OTP", ai(harm={"level": 0, "evidence": ["OTP"]}))["annotations"]


def test_report_url_not_in_original_is_unmatched_not_rewritten():
    text = "hxxp://evil[.]invalid"
    result = build_highlights(text, ai(link_risk=factor("http://evil.invalid")))
    assert result["unmatched"] == ["e0"]
    assert result["segments"] == [{"text": text, "evidence_ids": []}]


def test_full_message_quote_and_duplicate_quotes_are_not_shortened():
    text = "ส่งรหัส OTP ตอนนี้"
    result = build_highlights(text, ai(harm={"level": 4, "evidence": [text, text], "reason": "คำขอ"}))
    assert len(result["annotations"]) == 1
    assert result["segments"] == [{"text": text, "evidence_ids": ["e0"]}]
