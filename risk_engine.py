"""
Risk Engine Module for Scam Checker AI.
Combines signals from VirusTotal (VT), Knowledge Base (KB), and AI Analysis
using clear, explainable rule-based scoring and weighted aggregation.
"""

from typing import Dict, List, Any


def calculate_risk(
    vt_results: List[Dict[str, Any]],
    kb_result: Dict[str, Any],
    ai_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Computes overall risk assessment (level, score, and reasons).

    Args:
        vt_results: List of VirusTotal scan results.
        kb_result: Knowledge Base match result.
        ai_result: AI Analysis result.

    Returns:
        dict: {
            "risk_level": "ต่ำ" | "ปานกลาง" | "สูง",
            "risk_score": int (0-100),
            "reasons": list of descriptive reasons in Thai
        }
    """
    reasons: List[str] = []

    # 1. Evaluate VirusTotal signals
    vt_verdicts = [r.get("verdict", "unknown") for r in vt_results] if vt_results else []
    vt_has_malicious = "malicious" in vt_verdicts
    vt_has_suspicious = "suspicious" in vt_verdicts
    vt_all_safe = len(vt_results) > 0 and all(v == "safe" for v in vt_verdicts)

    # 2. Extract KB and AI scores
    kb_score = int(kb_result.get("kb_score", 0))
    kb_categories = kb_result.get("matched_categories", [])
    kb_phrases = kb_result.get("matched_phrases", [])
    kb_has_matches = bool(kb_categories or kb_phrases)

    ai_confidence = int(ai_result.get("ai_confidence", 0))
    ai_indicators = ai_result.get("indicators", [])

    vt_has_unknown = "unknown" in vt_verdicts

    # A KB miss provides no evidence about safety. If Gemini is unavailable too,
    # only an actual VT detection can support a risk decision.
    if not kb_has_matches and ai_result.get("analysis_status") == "unavailable" and not (vt_has_malicious or vt_has_suspicious):
        return {
            "risk_level": "ไม่สามารถประเมินได้",
            "risk_score": None,
            "scam_type": "ไม่สามารถระบุประเภทได้แน่ชัด",
            "score_source": "unavailable",
            "reasons": ["ไม่พบคำตรงกับ Knowledge Base และ Gemini ไม่สามารถวิเคราะห์ได้ในขณะนี้ จึงยังประเมินความเสี่ยงของข้อความไม่ได้"],
        }

    # 3. Calculate VT component score & weights
    if not kb_has_matches:
        # Use Gemini directly when there is no matching KB evidence. A zero KB
        # score must not dilute Gemini's score; VT detections still take priority.
        raw_score = ai_confidence
        if vt_has_malicious:
            raw_score = max(raw_score, 100)
        elif vt_has_suspicious:
            raw_score = max(raw_score, 70)
    elif vt_has_malicious:
        vt_score = 100
        raw_score = (vt_score * 0.40) + (kb_score * 0.30) + (ai_confidence * 0.30)
    elif vt_has_suspicious:
        vt_score = 70
        raw_score = (vt_score * 0.40) + (kb_score * 0.30) + (ai_confidence * 0.30)
    elif vt_all_safe:
        vt_score = 0
        raw_score = (vt_score * 0.40) + (kb_score * 0.30) + (ai_confidence * 0.30)
    elif len(vt_results) > 0:
        # Unknown/Unverified URLs (e.g. newly registered zero-day domains)
        # Lack of VT database history must NOT suppress high AI confidence
        if ai_confidence >= 60:
            raw_score = (ai_confidence * 0.60) + (kb_score * 0.25) + 15
        else:
            raw_score = (ai_confidence * 0.50) + (kb_score * 0.30) + 10
    else:
        # No URL present in message
        raw_score = (kb_score * 0.50) + (ai_confidence * 0.50)

    risk_score = int(round(raw_score))

    # 5. Rule-based Overrides (Explainable security decisions)
    # Rule 1: Confirmed malicious URL -> Immediate High Risk
    if vt_has_malicious:
        risk_score = max(risk_score, 90)
        risk_level = "สูง"
        for r in vt_results:
            if r.get("verdict") == "malicious":
                reasons.append(
                    f"VirusTotal ตรวจพบ URL อันตราย: {r.get('url')} "
                    f"(ตรวจพบโดย {r.get('malicious_count')}/{r.get('total_engines')} ระบบความปลอดภัย)"
                )

    # Rule 2: Suspicious URL combined with suspicious text/AI -> High Risk
    elif vt_has_suspicious and (kb_score >= 30 or ai_confidence >= 60):
        risk_score = max(risk_score, ai_confidence, 70)
        risk_level = "สูง"
        reasons.append("ลิงก์ในข้อความมีความน่าสงสัยในระดับสูง ร่วมกับเนื้อหาที่มีลักษณะหลอกลวง")

    # Rule 3: High AI confidence OR unverified zero-day link with suspicious text -> High Risk
    elif (ai_confidence >= 70) or (ai_confidence >= 60 and vt_has_unknown) or (kb_score >= 60 and ai_confidence >= 55):
        risk_score = max(risk_score, ai_confidence, 65)
        risk_level = "สูง"
        reasons.append("ตรวจพบลักษณะพฤติกรรมหลอกลวง (Phishing/Scam Pattern) ในระดับความเสี่ยงสูง")
        if vt_has_unknown:
            reasons.append("พบลิงก์แปลกปลอมที่ยังไม่มีประวัติความปลอดภัยในระบบ (เสี่ยงเป็นลิงก์หลอกลวงที่เพิ่งสร้างขึ้น)")

    # Default level mapping from score
    else:
        if risk_score >= 65:
            risk_level = "สูง"
        elif risk_score >= 35:
            risk_level = "ปานกลาง"
        else:
            risk_level = "ต่ำ"

    # 6. Generate detailed explanatory reasons in Thai
    if kb_categories:
        cat_names_th = {
            "urgency": "สร้างความเร่งด่วน/กดดันเวลา",
            "money_reward": "ผลประโยชน์/เงินรางวัล/เงินกู้",
            "personal_info": "ขอข้อมูลส่วนตัว/รหัส OTP",
            "impersonation": "แอบอ้างสถาบัน/หน่วยงานรัฐ",
            "gambling": "เว็บพนัน/คาสิโนออนไลน์",
        }
        translated_cats = [cat_names_th.get(c, c) for c in kb_categories]
        reasons.append(f"พบคำหรือวลีต้องสงสัยในหมวด: {', '.join(translated_cats)}")

    if ai_indicators:
        reasons.append(f"AI ตรวจพบข้อสังเกต: {', '.join(ai_indicators[:3])}")

    if not kb_has_matches:
        reasons.append("ไม่พบคำตรงกับ Knowledge Base จึงใช้การวิเคราะห์บริบทจาก Gemini และผลตรวจลิงก์จาก VirusTotal")

    if vt_all_safe and risk_level == "ต่ำ":
        reasons.append("ลิงก์ผ่านการตรวจสอบจาก VirusTotal ไม่พบรายงานความไม่ปลอดภัย")

    if not reasons:
        if risk_level == "ต่ำ":
            reasons.append("ไม่พบรูปแบบคำหลอกลวงหรือลิงก์ที่เป็นอันตราย เป็นข้อความปลอดภัย")
        else:
            reasons.append("บริบทของข้อความมีองค์ประกอบที่ควรระมัดระวัง")

    # 7. Determine Scam Type / Classification
    scam_type = ai_result.get("scam_type")
    if risk_level == "ต่ำ":
        scam_type = "ข้อความปลอดภัย (ไม่ใช่สแกม)"
    elif not scam_type or scam_type in ("สแกมทั่วไป", "ไม่สามารถระบุประเภทได้แน่ชัด"):
        if "gambling" in kb_categories:
            scam_type = "เว็บพนันออนไลน์"
        elif vt_has_malicious or (vt_results and ("personal_info" in kb_categories or "urgency" in kb_categories)):
            scam_type = "หลอกกดลิงก์ (Phishing)"
        elif "money_reward" in kb_categories:
            scam_type = "หลอกโอนเงิน / หลอกรับรางวัล"
        elif "impersonation" in kb_categories:
            scam_type = "แอบอ้างหน่วยงานรัฐ / ข่มขู่"
        else:
            scam_type = "ข้อความหลอกลวง (Scam)"

    return {
        "risk_level": risk_level,
        "risk_score": max(0, min(100, risk_score)),
        "scam_type": scam_type,
        "score_source": "kb_ai_and_virustotal" if kb_has_matches else "ai_and_virustotal",
        "reasons": reasons,
    }


if __name__ == "__main__":
    vt = [{"url": "http://evil.com", "malicious_count": 5, "total_engines": 90, "verdict": "malicious"}]
    kb = {"matched_categories": ["urgency"], "matched_phrases": ["ด่วนที่สุด"], "kb_score": 30}
    ai = {"ai_summary": "สแกม", "ai_confidence": 90, "indicators": ["กดดันเวลา"]}

    res = calculate_risk(vt, kb, ai)
    print("Risk Engine Output:", res)
