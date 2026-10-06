"""
Unit tests for knowledge_base/kb_checker.py
"""

from pathlib import Path
import json
import pytest
from knowledge_base.kb_checker import check_knowledge_base, KBChecker


def test_empty_text():
    res = check_knowledge_base("")
    assert res["kb_score"] == 0
    assert res["matched_categories"] == []
    assert res["matched_phrases"] == []


def test_benign_text():
    res = check_knowledge_base("สวัสดีครับ วันนี้อากาศดีมาก ทานข้าวเที่ยงหรือยัง")
    assert res["kb_score"] == 0
    assert len(res["matched_phrases"]) == 0


def test_single_category_match():
    # Only urgency
    res = check_knowledge_base("ส่งงานด่วนที่สุดนะครับอาจารย์")
    assert "urgency" in res["matched_categories"]
    assert len(res["matched_categories"]) == 1
    assert res["kb_score"] == 30


def test_two_categories_match():
    # urgency + money_reward
    res = check_knowledge_base("ด่วนที่สุด! คุณได้รับรางวัล 1,000,000 บาท")
    assert "urgency" in res["matched_categories"]
    assert "money_reward" in res["matched_categories"]
    assert res["kb_score"] >= 60


def test_all_four_categories_match():
    # urgency + money_reward + personal_info + impersonation
    res = check_knowledge_base(
        "ด่วนที่สุด! ธนาคารกรุงไทยแจ้งว่าคุณได้รับรางวัล กรุณาแจ้งรหัส OTP เพื่อยืนยันสิทธิ์"
    )
    assert len(res["matched_categories"]) == 4
    assert res["kb_score"] >= 95


def test_custom_phrases_file(tmp_path: Path):
    custom_file = tmp_path / "custom.json"
    custom_file.write_text('{"cat1": ["คำเตือนลับ"]}', encoding="utf-8")
    checker = KBChecker(custom_file)
    res = checker.check("นี่คือ คำเตือนลับ สำหรับคุณ")
    assert "cat1" in res["matched_categories"]
    assert res["kb_score"] == 30


@pytest.mark.parametrize("text,phrase", [
    ("กรุณาแจ้งรหัสOTP", "แจ้งรหัส OTP"),
    ("กรุณา แจ้ง รหัส OTP", "แจ้งรหัส OTP"),
    ("กรุณาแจ้งรหัส\nOTP", "แจ้งรหัส OTP"),
    ("กรุณาแจ้งรหัส：ＯＴＰ", "แจ้งรหัส OTP"),
    ("กรุณาแจ้งรหัส O T P", "แจ้งรหัส OTP"),
    ("กรุณาแจ้งรหัส O.T.P.", "แจ้งรหัส OTP"),
    ("กรุณาส่งรหัส OTP", "ส่งรหัส OTP"),
    ("กรุณาส่งเลขotp", "ส่งเลข OTP"),
    ("ด่วน\u200bที่สุด", "ด่วนที่สุด"),
    ("ด่วน ที่สุด", "ด่วนที่สุด"),
    ("คุณได้รับ รางวัล", "คุณได้รับรางวัล"),
])
def test_spacing_and_copy_paste_variants_match(text, phrase):
    result = check_knowledge_base(text)
    assert result["kb_status"] == "ready"
    assert phrase in result["matched_phrases"]
    assert result["kb_score"] > 0


@pytest.mark.parametrize("text", ["adsite", "ฝาก 10 รับ 1000", "พรุ่งนี้เจอกันที่ร้านกาแฟ", "ฝากโอนค่าข้าวให้เพื่อน 150 บาท"])
def test_normal_text_and_partial_latin_words_do_not_create_hits(text):
    assert check_knowledge_base(text)["matched_phrases"] == []


def test_new_sms_variants_match_specific_phrases():
    cases = {
        "กรุณาชำระค่าประกันวงเงิน 499 บาทก่อนรับเงิน": "money_reward",
        "ชำระค่าจัดส่งใหม่ 15 บาท": "money_reward",
        "รับงานกดหัวใจ เริ่มงานด้วยการเติมเงิน 300 บาท": "money_reward",
        "เจ้าหน้าที่ธนาคารขอรหัส OTP ภายใน 5 นาที": "personal_info",
    }
    for text, category in cases.items():
        assert category in check_knowledge_base(text)["matched_categories"]


def test_database_updates_are_reloaded_without_restart(tmp_path):
    path = tmp_path / "phrases.json"
    path.write_text(json.dumps({"test": ["รางวัลทดสอบ"]}), encoding="utf-8-sig")
    checker = KBChecker(path)
    assert checker.check("รางวัลทดสอบ")["kb_score"] == 30
    path.write_text(json.dumps({"test": ["ส่งรหัส OTP", "รับเงินคืน"]}), encoding="utf-8")
    updated = checker.check("ส่งรหัสOTP")
    assert updated["matched_phrases"] == ["ส่งรหัส OTP"]
    assert updated["phrase_count"] == 2
    assert checker.check("รางวัลทดสอบ")["matched_phrases"] == []


@pytest.mark.parametrize("content", ["not json", "[]", "{}", '{"test": "not a list"}', '{"test": [""]}'])
def test_invalid_database_is_reported_as_unavailable(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    result = KBChecker(path).check("ข้อความ")
    assert result["kb_status"] == "unavailable"
    assert result["phrase_count"] == 0


def test_missing_database_is_reported_as_unavailable(tmp_path):
    checker = KBChecker(tmp_path / "missing.json")
    assert checker.check("ข้อความ")["kb_status"] == "unavailable"
