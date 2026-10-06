"""
Unit tests for parser.py
"""

import pytest
from parser import parse_message, deobfuscate_text, clean_url


def test_no_urls():
    text = "สวัสดีครับ วันนี้อากาศดีจัง ไปเที่ยวกันไหม"
    res = parse_message(text)
    assert res["urls"] == []
    assert res["text_only"] == text


def test_single_normal_url():
    text = "กรุณาตรวจสอบข้อมูลที่ https://www.google.com"
    res = parse_message(text)
    assert res["urls"] == ["https://www.google.com"]
    assert res["text_only"] == "กรุณาตรวจสอบข้อมูลที่"


def test_multiple_urls():
    text = "ดูที่ https://a.com/test และ https://b.com/sub/path เพื่อดูข้อมูล"
    res = parse_message(text)
    assert len(res["urls"]) == 2
    assert "https://a.com/test" in res["urls"]
    assert "https://b.com/sub/path" in res["urls"]
    assert "และ" in res["text_only"]
    assert "เพื่อดูข้อมูล" in res["text_only"]


def test_url_without_protocol():
    text = "เข้าชมได้ที่ www.kasikornbank.com ได้ทันที"
    res = parse_message(text)
    assert res["urls"] == ["https://www.kasikornbank.com"]
    assert "เข้าชมได้ที่" in res["text_only"]
    assert "ได้ทันที" in res["text_only"]


def test_shortener_url():
    text = "กดรับของขวัญที่ bit.ly/gift2026 ด่วน"
    res = parse_message(text)
    assert res["urls"] == ["https://bit.ly/gift2026"]
    assert "กดรับของขวัญที่" in res["text_only"]
    assert "ด่วน" in res["text_only"]


def test_obfuscated_url():
    text = "ตรวจสอบบัญชีที่ hxxp://evil[.]com/login"
    res = parse_message(text)
    assert res["urls"] == ["http://evil.com/login"]
    assert "ตรวจสอบบัญชีที่" in res["text_only"]


def test_trailing_punctuation_in_url():
    text = "ติดต่อ https://example.com/info."
    res = parse_message(text)
    assert res["urls"] == ["https://example.com/info"]


def test_empty_string():
    res = parse_message("")
    assert res["urls"] == []
    assert res["text_only"] == ""


def test_duplicate_urls():
    text = "ลิงก์ https://example.com/test และอีกรอบ https://example.com/test"
    res = parse_message(text)
    assert len(res["urls"]) == 1
    assert res["urls"] == ["https://example.com/test"]
