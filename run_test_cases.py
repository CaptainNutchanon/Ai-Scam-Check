"""
Automated Test Case Runner.
Evaluates all test cases in tests/test_cases.json against the Scam Checker pipeline
and produces a summary report.
"""

import json
from pathlib import Path
from main import check_message

TEST_CASES_FILE = Path(__file__).resolve().parent / "tests" / "test_cases.json"


def run_all_cases():
    with open(TEST_CASES_FILE, "r", encoding="utf-8") as f:
        cases = json.load(f)

    print("=" * 70)
    print(f"🚀 เริ่มการทดสอบชุด Test Cases ทั้งหมด ({len(cases)} เคส)")
    print("=" * 70)

    passed_count = 0
    results_summary = []

    for item in cases:
        case_id = item["id"]
        desc = item["description"]
        text = item["text"]
        expected = item["expected_risk"]

        print(f"\n[Case {case_id}] {desc}")
        print(f"ข้อความ: \"{text[:60]}...\"" if len(text) > 60 else f"ข้อความ: \"{text}\"")

        res = check_message(text)
        actual_risk = res["risk"]["risk_level"]
        actual_score = res["risk"]["risk_score"]

        # Consider pass if risk matches expected
        # Or if benign test is either 'ต่ำ' (expected) or 'ปานกลาง'
        is_match = (actual_risk == expected)
        if is_match:
            status = "✅ PASS"
            passed_count += 1
        else:
            status = f"⚠️ MISMATCH (คาดหวัง: {expected}, ได้จริง: {actual_risk})"

        print(f"-> ผลลัพธ์: {actual_risk} ({actual_score}/100) | สถานะ: {status}")
        print(f"   เหตุผล: {', '.join(res['risk']['reasons'][:2])}")

        results_summary.append({
            "id": case_id,
            "desc": desc,
            "expected": expected,
            "actual": actual_risk,
            "score": actual_score,
            "pass": is_match,
        })

    print("\n" + "=" * 70)
    print(f"📊 สรุปผลการทดสอบ: ผ่าน {passed_count}/{len(cases)} เคส ({(passed_count/len(cases))*100:.1f}%)")
    print("=" * 70)
    return results_summary


if __name__ == "__main__":
    run_all_cases()
