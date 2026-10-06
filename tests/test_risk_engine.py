"""
Unit tests for risk_engine.py
"""

import pytest
from risk_engine import calculate_risk


def test_vt_malicious_override():
    vt = [{"url": "http://evil.com", "verdict": "malicious", "malicious_count": 5, "total_engines": 90}]
    kb = {"matched_categories": [], "matched_phrases": [], "kb_score": 0}
    ai = {"ai_summary": "ไม่แน่ใจ", "ai_confidence": 20, "indicators": []}

    res = calculate_risk(vt, kb, ai)
    assert res["risk_level"] == "สูง"
    assert res["risk_score"] >= 90
    assert any("VirusTotal ตรวจพบ URL อันตราย" in r for r in res["reasons"])


def test_all_safe_with_url():
    vt = [{"url": "https://kasikornbank.com", "verdict": "safe", "malicious_count": 0, "total_engines": 92}]
    kb = {"matched_categories": [], "matched_phrases": [], "kb_score": 0}
    ai = {"ai_summary": "ปลอดภัย", "ai_confidence": 5, "indicators": []}

    res = calculate_risk(vt, kb, ai)
    assert res["risk_level"] == "ต่ำ"
    assert res["risk_score"] < 35


def test_no_url_high_scam():
    vt = []  # No URLs
    kb = {"matched_categories": ["urgency", "money_reward", "personal_info"], "matched_phrases": ["ด่วน", "รางวัล", "OTP"], "kb_score": 80}
    ai = {"ai_summary": "สแกมหลอกลวง", "ai_confidence": 85, "indicators": ["ขอ OTP"]}

    res = calculate_risk(vt, kb, ai)
    assert res["risk_level"] == "สูง"
    assert res["risk_score"] >= 70


def test_no_url_clean():
    vt = []
    kb = {"matched_categories": [], "matched_phrases": [], "kb_score": 0}
    ai = {"ai_summary": "ข้อความปกติ", "ai_confidence": 5, "indicators": []}

    res = calculate_risk(vt, kb, ai)
    assert res["risk_level"] == "ต่ำ"
    assert res["risk_score"] <= 10


def test_medium_risk():
    vt = []
    kb = {"matched_categories": ["urgency"], "matched_phrases": ["ด่วนที่สุด"], "kb_score": 30}
    ai = {"ai_summary": "ส่งงานด่วน", "ai_confidence": 40, "indicators": []}

    res = calculate_risk(vt, kb, ai)
    assert res["risk_level"] == "ปานกลาง"
    assert 35 <= res["risk_score"] < 65


def test_gambling_scam_type():
    vt = [{"url": "http://slot-bonus.net", "verdict": "unknown", "malicious_count": 0, "total_engines": 0}]
    kb = {"matched_categories": ["gambling"], "matched_phrases": ["สล็อตออนไลน์", "แจกเครดิตฟรี"], "kb_score": 30}
    ai = {"scam_type": "เว็บพนันออนไลน์", "ai_summary": "ชวนเล่นการพนัน", "ai_confidence": 80, "indicators": ["เครดิตฟรี"]}

    res = calculate_risk(vt, kb, ai)
    assert res["risk_level"] == "สูง"
    assert res["scam_type"] == "เว็บพนันออนไลน์"
