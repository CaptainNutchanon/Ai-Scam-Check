"""
Main entry point for Scam Checker AI.
Integrates Parser, VirusTotal Checker, Knowledge Base, AI Analyzer, and Risk Engine.
Provides both a Python API `check_message()` and a Command Line Interface (CLI).
"""

import argparse
import json
import logging
import sys
from typing import Dict, Any, Callable, Optional

# Ensure proper Thai UTF-8 display in Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Suppress internal google_genai SDK warnings
logging.getLogger("google_genai").setLevel(logging.ERROR)

from parser import parse_message
from virustotal_checker import check_url
from knowledge_base import check_knowledge_base
from ai_analyzer import analyze_with_ai
from risk_engine import calculate_risk
from ai_scoring import FACTOR_LABELS

logger = logging.getLogger(__name__)


def check_message(text: str, *, progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """
    Main pipeline function: analyzes a message to determine scam probability.

    Steps:
    1. Parse and deobfuscate text, extracting URLs.
    2. Check each URL against VirusTotal API v3 (reputation, malicious counts).
    3. Check text content against Thai Scam Knowledge Base.
    4. Call Google Gemini AI to analyze contextual semantics.
    5. Aggregate all signals in Risk Engine to calculate final risk score and level.

    Args:
        text: Raw user input text (e.g. SMS message, LINE chat, or email).

    Returns:
        dict: Full inspection report including all module outputs and final risk.
    """
    def report(stage: str) -> None:
        if progress:
            progress(stage)

    # Step 1: Parse message & isolate URLs
    report("parsing")
    parsed = parse_message(text)

    # Step 2: VirusTotal link checks
    vt_results = []
    report("links" if parsed["urls"] else "knowledge_base")
    for url in parsed["urls"]:
        vt_results.append(check_url(url))

    # Step 3: Knowledge Base matching
    report("knowledge_base")
    kb_result = check_knowledge_base(parsed["text_only"])
    kb_has_matches = bool(kb_result["matched_phrases"] or kb_result["matched_categories"])

    # Step 4: AI Contextual Analysis
    report("ai")
    ai_result = analyze_with_ai(text, vt_results, kb_result)

    # Step 5: Risk Engine Scoring & Decision
    report("scoring")
    risk = calculate_risk(vt_results, kb_result, ai_result)

    return {
        "input_text": text,
        "parsed": parsed,
        "vt_results": vt_results,
        "kb_result": kb_result,
        "ai_result": ai_result,
        "analysis_mode": "kb_assisted" if kb_has_matches else "independent_ai",
        "risk": risk,
    }


def format_cli_output(result: Dict[str, Any]) -> str:
    """Formats inspection result into a clear, structured terminal display in Thai."""
    risk = result["risk"]
    level = risk["risk_level"]
    score = risk["risk_score"]

    if level == "สูง":
        badge = "🔴 ระดับความเสี่ยง: สูง (HIGH RISK)"
    elif level == "ปานกลาง":
        badge = "🟡 ระดับความเสี่ยง: ปานกลาง (MEDIUM RISK)"
    elif level == "ต่ำ":
        badge = "🟢 ระดับความเสี่ยง: ต่ำ (LOW RISK / SAFE)"
    else:
        badge = "⚪ ระดับความเสี่ยง: ยังประเมินไม่ได้"

    lines = [
        "=" * 65,
        "🛡️  ผลการตรวจสอบข้อความสแกม (Scam Checker AI)",
        "=" * 65,
        f"ข้อความ: \"{result['input_text']}\"",
        "-" * 65,
        f"{badge}",
        f"🏷️  ประเภทข้อความ: {risk.get('scam_type', 'ไม่ระบุ')}",
        f"คะแนนความเสี่ยงรวม: {score}/100" if score is not None else "คะแนนความเสี่ยงรวม: ไม่มีผลประเมิน",
        "",
        "📌 สรุปเหตุผล:",
    ]
    for r in risk["reasons"]:
        lines.append(f"  • {r}")

    lines.append("")
    lines.append("🔍 รายละเอียดการตรวจสอบแต่ละขั้นตอน:")

    # 1. URLs
    urls = result["parsed"]["urls"]
    if urls:
        lines.append(f"  [1] ลิงก์ที่พบ ({len(urls)} รายการ):")
        for vt in result["vt_results"]:
            verdict_icon = "❌" if vt["verdict"] == "malicious" else ("✅" if vt["verdict"] == "safe" else "⚠️")
            lines.append(
                f"      {verdict_icon} {vt['url']} -> {vt['verdict']} "
                f"({vt['malicious_count']}/{vt['total_engines']} engines)"
            )
    else:
        lines.append("  [1] ลิงก์ที่พบ: ไม่มีลิงก์ในข้อความ")

    # 2. Knowledge Base
    kb = result["kb_result"]
    lines.append(f"  [2] การตรวจคำในฐานข้อมูล (KB Score: {kb['kb_score']}/100):")
    if kb["matched_categories"]:
        lines.append(f"      - หมวดที่พบ: {', '.join(kb['matched_categories'])}")
        lines.append(f"      - วลีที่พบ: {', '.join(kb['matched_phrases'])}")
    else:
        lines.append("      - ไม่พบคำหรือวลีต้องสงสัยในฐานข้อมูล")
        lines.append("      - ให้ Gemini วิเคราะห์บริบทเองร่วมกับผลตรวจลิงก์")

    # 3. AI Analysis
    ai = result["ai_result"]
    if ai.get("analysis_status") == "unavailable":
        lines.append("  [3] Gemini ไม่พร้อมใช้งาน (ผลสำรอง ไม่ใช่คะแนนจาก AI):")
    else:
        lines.append(f"  [3] การวิเคราะห์ด้วย AI (คะแนนประเมิน: {ai['ai_confidence']}/100):")
    if ai.get("scam_type"):
        lines.append(f"      - ประเภทที่ AI วิเคราะห์ได้: {ai['scam_type']}")
    lines.append(f"      - สรุป: {ai['ai_summary']}")
    if ai.get("indicators"):
        lines.append(f"      - สัญญาณเตือน: {', '.join(ai['indicators'])}")
    if ai.get("risk_assessment"):
        lines.append("      - หลักฐานและคะแนนย่อย:")
        for name, label in FACTOR_LABELS.items():
            factor = ai["risk_assessment"][name]
            points = ai["score_breakdown"][name]
            lines.append(f"        {label}: ระดับ {factor['level']}/4 → {points:g} คะแนน")
            if factor["evidence"]:
                lines.append(f"          ข้อความอ้างอิง: {' | '.join(factor['evidence'])}")

    lines.append("=" * 65)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Scam Checker AI — ระบบตรวจสอบข้อความและลิงก์สแกม")
    parser.add_argument("message", nargs="?", help="ข้อความที่ต้องการตรวจสอบ")
    parser.add_argument("--json", action="store_true", help="แสดงผลลัพธ์เป็น JSON")
    args = parser.parse_args()

    message = args.message
    if not message:
        print("💡 ใส่ข้อความที่ต้องการตรวจสอบ (กด Enter เพื่อส่ง):")
        try:
            message = input("> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nยกเลิกการทำงาน")
            sys.exit(0)

    if not message:
        print("ข้อความว่างเปล่า ยกเลิกการตรวจสอบ")
        sys.exit(0)

    result = check_message(message)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(format_cli_output(result))


if __name__ == "__main__":
    main()
