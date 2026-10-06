"""Browser test fixture ONLY. All reports/OCR and the Data API are synthetic."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import time
import config
from ai_scoring import evidence_catalog, resolve_selections, EvidenceSelections, score_evidence
from history_store import HistoryStore
from web_server import JobStore, make_server
from tests.supabase_fake import MemoryDataAPI


def checker(text, *, progress):
    progress("ai")
    time.sleep(.2)
    quote = "ส่งรหัส OTP" if "ส่งรหัส OTP" in text else text
    refs = evidence_catalog(text, [])
    ref = next(key for key, value in refs.items() if value == quote)
    assessment = resolve_selections(EvidenceSelections.model_validate({name: {"level": 3 if name == "harm" else 0,
        "evidence": [ref] if name == "harm" else [], "reason": "ขอให้ส่งข้อมูลส่วนตัว (ข้อมูลสังเคราะห์สำหรับทดสอบ)"}
        for name in ["harm", "deception", "pressure", "link_risk"]}), text, [])
    return {"input_text": text, "parsed": {"urls": [], "text_only": text}, "vt_results": [],
        "kb_result": {"kb_status": "ready", "kb_score": 0, "matched_phrases": [], "matched_categories": []},
        "ai_result": {"analysis_status": "ok", "ai_summary": "ตัวอย่างทดสอบ: ขอข้อมูล OTP", "scam_type": "ฟิชชิ่ง", **score_evidence(assessment, text, []), "risk_assessment": assessment.model_dump()},
        "risk": {"risk_score": 68, "risk_level": "สูง", "scam_type": "ฟิชชิ่ง", "reasons": ["ตัวอย่างทดสอบ: คำขอข้อมูลส่วนตัว"]}, "analysis_mode": "independent_ai"}


def ocr(data, mime):
    time.sleep(.7)
    return {"text": "แจ้งจากผู้ส่ง: ส่งรหัส OTP ตอนนี้", "warnings": ["ตรวจทานตัวเลขก่อนส่งวิเคราะห์"]}


if __name__ == "__main__":
    config.GEMINI_API_KEY = "unit-test-not-real"
    database = MemoryDataAPI()
    server = make_server(8012, JobStore(checker, ocr), HistoryStore(database.client, sleep=lambda _: None))
    print("SYNTHETIC UI TEST SERVER http://127.0.0.1:8012 - NO REAL AI OR DATABASE", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
