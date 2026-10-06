"""Evidence-based, deterministic scoring; these scores are not calibrated probabilities."""

import json
import re
from typing import List

from pydantic import BaseModel, Field


HARM_BASE_POINTS = (0, 18, 42, 68, 86)
SUPPORT_MAX_POINTS = {"deception": 6, "pressure": 4, "link_risk": 4}
FACTOR_LABELS = {
    "harm": "การขอข้อมูล/เงินหรือการข่มขู่",
    "deception": "การหลอกอ้าง",
    "pressure": "การกดดัน",
    "link_risk": "ลิงก์น่าสงสัย",
}


class EvidenceFactor(BaseModel):
    level: int = Field(ge=0, le=4, strict=True, description="ระดับหลักฐาน 0-4 ตามเกณฑ์ใน prompt")
    evidence: List[str] = Field(description="คัดข้อความที่มีอยู่จริงแบบตรงตัว ห้ามสร้างข้อความเพิ่ม; ระดับ 0 ใช้ []")
    reason: str = Field(min_length=1, description="เหตุผลสั้น ๆ ที่เชื่อมหลักฐานกับระดับที่ให้")


class RiskAssessment(BaseModel):
    harm: EvidenceFactor
    deception: EvidenceFactor
    pressure: EvidenceFactor
    link_risk: EvidenceFactor


class EvidenceSelection(BaseModel):
    level: int = Field(ge=0, le=4, strict=True, description="ระดับหลักฐาน 0-4 ตามเกณฑ์")
    evidence: List[str] = Field(description="เลือกรหัสจาก evidence_catalog เท่านั้น เช่น text:0 หรือ url:0; ระดับ 0 ใช้ [] ห้ามเขียนข้อความอ้างอิงเอง")
    reason: str = Field(min_length=1, description="เหตุผลสั้น ๆ เป็นภาษาไทย")


class EvidenceSelections(BaseModel):
    harm: EvidenceSelection
    deception: EvidenceSelection
    pressure: EvidenceSelection
    link_risk: EvidenceSelection


class GeminiEvidenceSchema(BaseModel):
    scam_type: str = Field(min_length=1, description="ประเภทสแกมหรือข้อความทั่วไป เป็นภาษาไทย")
    ai_summary: str = Field(min_length=1, description="สรุปหลักฐานและข้อจำกัดเป็นภาษาไทย")
    risk_assessment: EvidenceSelections


def evidence_catalog(original_text: str, vt_results: list) -> dict:
    """Generate stable references to exact input substrings and real report URLs."""
    snippets = [original_text]
    seen = {original_text}
    tokens = list(re.finditer(r"\S+", original_text))
    for width in (4, 3, 2, 1):
        for index in range(len(tokens) - width + 1):
            snippet = original_text[tokens[index].start():tokens[index + width - 1].end()]
            if snippet not in seen:
                seen.add(snippet)
                snippets.append(snippet)
    catalog = {f"text:{index}": text for index, text in enumerate(snippets)}
    catalog.update({f"url:{index}": row["url"] for index, row in enumerate(vt_results) if row.get("url")})
    return catalog


def evidence_catalog_prompt(original_text: str, vt_results: list) -> str:
    return "\n[evidence_catalog: รหัสข้อความต้นฉบับสำหรับเลือกหลักฐาน]:\n" + json.dumps(evidence_catalog(original_text, vt_results), ensure_ascii=False)


def resolve_selections(selections: EvidenceSelections, original_text: str, vt_results: list) -> RiskAssessment:
    """Model selects IDs; the application produces exact quotations without paraphrases."""
    catalog = evidence_catalog(original_text, vt_results)
    resolved = {}
    for name in FACTOR_LABELS:
        factor = getattr(selections, name)
        quotes = []
        for ref in factor.evidence:
            if ref not in catalog:
                raise ValueError(f"{name}: evidence reference is not supplied: {ref!r}")
            if ref.startswith("url:") and name != "link_risk":
                raise ValueError(f"{name}: report URL references can only support link_risk")
            quotes.append(catalog[ref])
        resolved[name] = {"level": factor.level, "evidence": quotes, "reason": factor.reason}
    return RiskAssessment.model_validate(resolved)


SCORING_INSTRUCTIONS = """
[การประเมินหลักฐานก่อนให้คะแนน]:
ตอบ scam_type, ai_summary และ risk_assessment ตาม schema ไม่ต้องเสนอคะแนนรวม ai_confidence
ประเมิน 4 ด้านเป็น level 0-4 พร้อม evidence เป็นรหัสจาก evidence_catalog และ reason สั้น ๆ
เช่น evidence=["text:4", "text:5"] ห้ามเขียนข้อความอ้างอิงเอง ระบบจะดึงต้นฉบับจากรหัสมาให้
ระดับ 0 ให้ evidence=[]; ทุกระดับที่มากกว่า 0 ต้องเลือกรหัสที่รองรับข้อสังเกตจริง
เลือกข้อความเฉพาะส่วนที่เป็นหลักฐาน หากแบ่งย่อยไม่ได้ใช้ text:0 ได้ คำอธิบายใส่ reason เท่านั้น
1. harm (การขอข้อมูล/เงินหรือการข่มขู่):
   0 ไม่มีการร้องขอที่อันตรายหรือเป็นกิจกรรมปกติ เช่น โอนค่าอาหาร หรือเตือนอย่าบอก OTP
   1 มีคำเชิญ/คำขอทั่วไปที่ข้อมูลยังไม่พอ บริบทอาจปกติได้ ไม่รวมการล่อรับเงินผ่านลิงก์พราง
   2 ขอทำรายการหรือยืนยันข้อมูลโดยที่เจตนายังไม่ชัด ต้องตรวจเพิ่ม
   3 มีการร้องขอเสี่ยงเป็นรูปธรรม เช่น จ่ายก่อนรับสินเชื่อ/รางวัล เติมเงินก่อนรับค่าจ้าง
     หรือล่อให้กดลิงก์เพื่อรับเงิน/รางวัลโดยไม่มีบริบทการเข้าร่วมกิจกรรมที่อธิบายได้
     การล่อรับเงินผ่าน URL ที่พรางด้วย hxxp หรือ [.] เป็นการชักนำเสี่ยง ไม่ใช่คำเชิญทั่วไป
   4 ขอให้ส่ง OTP/รหัสผ่านให้บุคคลอื่น หรือข่มขู่ทำอันตราย/เผยข้อมูลส่วนตัวเพื่อเรียกเงิน
2. deception (การหลอกอ้าง): 0 ไม่มี, 1 ข้ออ้างคลุมเครือ, 2 อ้างผลประโยชน์หรืออำนาจที่ยังยืนยันไม่ได้,
   3 ข้ออ้างมีความผิดปกติชัดเจนในบริบท, 4 ข้ออ้างขัดแย้งกับพฤติกรรมอย่างชัดเจน
   ชื่อธนาคารหรือหน่วยงานเพียงอย่างเดียวไม่ใช่หลักฐานว่ามีการแอบอ้าง
3. pressure (การกดดัน): 0 ไม่มี, 1 เร่งเล็กน้อย, 2 กำหนดเวลาหรือกลัวเสียสิทธิ,
   3 บังคับเร่งให้ทำรายการเสี่ยง, 4 ขู่ลงโทษ/เปิดเผยข้อมูล/ทำอันตรายพร้อมเงื่อนไข
4. link_risk: 0 ไม่มีลิงก์หรือไม่มีหลักฐานผิดปกติ, 1 ลิงก์ปกติแต่ปลายทางยังไม่ยืนยัน,
   2 ลิงก์พราง/ย่อหรือโดเมนที่ขัดกับผู้ส่งในบริบท, 3 VirusTotal รายงาน suspicious,
   4 VirusTotal รายงาน malicious เท่านั้น ห้ามอ้างว่าได้ตรวจเว็บถ้าไม่มีรายงาน
   unknown ไม่ใช่หลักฐานว่าอันตรายหรือปลอดภัย; safe ไม่รับประกันความปลอดภัย
   ให้ประเมินรูปแบบ URL ในข้อความต้นฉบับด้วย รายงาน safe ไม่ลบข้อสังเกตว่าลิงก์ถูกพรางหรือใช้เพื่อหลอกล่อ
   ด้าน link_risk เลือก url:N จากรายงานได้ ด้านอื่นใช้ text:N จากข้อความผู้ใช้เท่านั้น
แยกการใช้คำในบริบทปกติ/คำเตือน/ข่าว ออกจากคำสั่งให้ผู้รับทำรายการเสี่ยงจริง
รูปแบบหลอกลวงใหม่วิเคราะห์ได้จากบริบท แม้ไม่มีคำตรงในฐานข้อมูล
ข้อความลักษณะใกล้กันให้ระดับใกล้กันได้ อย่าจงใจเปลี่ยนระดับเพื่อให้คะแนนหลากหลาย
"""


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def score_evidence(assessment: RiskAssessment, original_text: str, vt_results: list) -> dict:
    """Validate quoted evidence, then convert severity and supporting factors to points."""
    text_source = _normalize(original_text)
    link_source = text_source + " " + _normalize(json.dumps(vt_results, ensure_ascii=False))
    for name in FACTOR_LABELS:
        factor = getattr(assessment, name)
        if factor.level > 0 and not factor.evidence:
            raise ValueError(f"{name}: positive level requires quoted evidence")
        source = link_source if name == "link_risk" else text_source
        for quote in factor.evidence:
            normalized = _normalize(quote)
            if not normalized or normalized not in source:
                raise ValueError(f"{name}: evidence is not present in supplied input: {quote!r}")
    verdicts = {row.get("verdict") for row in vt_results}
    link_level = assessment.link_risk.level
    if link_level == 4 and "malicious" not in verdicts:
        raise ValueError("link_risk=4 requires a malicious VirusTotal report")
    if link_level == 3 and not verdicts.intersection({"suspicious", "malicious"}):
        raise ValueError("link_risk=3 requires a suspicious VirusTotal report")
    if link_level >= 3:
        allowed_verdicts = {"malicious"} if link_level == 4 else {"suspicious", "malicious"}
        detected_urls = [_normalize(row.get("url", "")) for row in vt_results if row.get("verdict") in allowed_verdicts]
        quotes = [_normalize(quote) for quote in assessment.link_risk.evidence]
        if not any(url and url in quote for url in detected_urls for quote in quotes):
            raise ValueError("link_risk evidence must cite the URL with the VirusTotal detection")
    if link_level > 0:
        # Quoting ordinary words cannot justify a link assessment without a URL.
        from parser import parse_message
        if not vt_results and not parse_message(original_text)["urls"]:
            raise ValueError("link_risk requires a URL in the supplied input")
    points = {"harm": HARM_BASE_POINTS[assessment.harm.level]}
    points.update({name: getattr(assessment, name).level * maximum / 4 for name, maximum in SUPPORT_MAX_POINTS.items()})
    score = int(sum(points.values()) + 0.5)
    return {"ai_confidence": score, "score_breakdown": points, "scoring_method": "evidence_rubric_v1"}
