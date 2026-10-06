"""
Integration tests for main.py check_message pipeline.
Uses mocked external APIs to ensure consistent, fast, and repeatable testing.
"""

from unittest.mock import patch, MagicMock
import json
import pytest
from main import check_message, format_cli_output


@patch("main.analyze_with_ai")
def test_web_otp_example_uses_actual_kb_hits(mock_ai):
    mock_ai.return_value = {"analysis_status": "ok", "ai_confidence": 94, "ai_summary": "ขอ OTP", "indicators": [], "scam_type": "หลอกขอ OTP"}
    text = "เจ้าหน้าที่ธนาคารแจ้งว่าบัญชีของคุณถูกระงับ กรุณาส่งรหัส OTP ที่ได้รับมาให้เจ้าหน้าที่ภายใน 5 นาที เพื่อปลดล็อกบัญชี"
    result = check_message(text)
    kb = result["kb_result"]
    assert result["analysis_mode"] == "kb_assisted"
    assert {"personal_info", "urgency", "impersonation"} <= set(kb["matched_categories"])
    assert "ส่งรหัส OTP" in kb["matched_phrases"]
    assert mock_ai.call_args.args[2] == kb
    assert "ส่งรหัส OTP" in format_cli_output(result)


@patch("main.check_url")
@patch("main.analyze_with_ai")
def test_full_pipeline_scam(mock_ai, mock_vt):
    # Mock VT detecting malicious link
    mock_vt.return_value = {
        "url": "https://bit.ly/scam-test",
        "malicious_count": 7,
        "total_engines": 90,
        "verdict": "malicious"
    }

    # Mock AI detecting scam
    mock_ai.return_value = {
        "ai_summary": "ข้อความนี้เป็นสแกมฟิชชิ่ง หลอกลวงให้รับรางวัลและมีลิงก์อันตราย",
        "ai_confidence": 95,
        "indicators": ["แอบอ้างรางวัล", "ลิงก์ย่อต้องสงสัย", "กดดันเวลา 24 ชม."]
    }

    text = "ด่วนที่สุด! คุณได้รับรางวัล 100,000 บาท กรุณายืนยันตัวตนที่ https://bit.ly/scam-test ภายใน 24 ชม."
    result = check_message(text)

    assert result["risk"]["risk_level"] == "สูง"
    assert result["risk"]["risk_score"] >= 85
    assert len(result["parsed"]["urls"]) == 1
    assert result["parsed"]["urls"][0] == "https://bit.ly/scam-test"
    assert result["kb_result"]["kb_score"] >= 60

    cli_text = format_cli_output(result)
    assert "ระดับความเสี่ยง: สูง" in cli_text
    assert "https://bit.ly/scam-test" in cli_text


@patch("main.check_url")
@patch("main.analyze_with_ai")
def test_full_pipeline_benign_chat(mock_ai, mock_vt):
    mock_ai.return_value = {
        "ai_summary": "ข้อความนัดหมายพูดคุยทั่วไป ปลอดภัย",
        "ai_confidence": 5,
        "indicators": []
    }

    text = "สวัสดีครับ วันนี้ทานข้าวเที่ยงด้วยกันไหมครับ"
    result = check_message(text)

    assert result["risk"]["risk_level"] == "ต่ำ"
    assert result["risk"]["risk_score"] < 35
    assert len(result["parsed"]["urls"]) == 0
    assert result["kb_result"]["kb_score"] == 0

    cli_text = format_cli_output(result)
    assert "ระดับความเสี่ยง: ต่ำ" in cli_text


@patch("main.check_url")
@patch("main.analyze_with_ai")
def test_full_pipeline_safe_link(mock_ai, mock_vt):
    mock_vt.return_value = {
        "url": "https://www.kasikornbank.com",
        "malicious_count": 0,
        "total_engines": 92,
        "verdict": "safe"
    }
    mock_ai.return_value = {
        "ai_summary": "ลิงก์เว็บไซต์ทางการของธนาคารกสิกรไทย ปลอดภัย",
        "ai_confidence": 10,
        "indicators": ["เว็บไซต์ทางการ"]
    }

    text = "ตรวจสอบรายละเอียดได้ที่ https://www.kasikornbank.com ครับ"
    result = check_message(text)

    assert result["risk"]["risk_level"] == "ต่ำ"
    assert result["risk"]["risk_score"] < 35
    assert result["vt_results"][0]["verdict"] == "safe"
