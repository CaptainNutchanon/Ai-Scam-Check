"""Test Gemini directly without importing the KB, VirusTotal, or risk engine."""

import argparse
import json
import sys
from pathlib import Path

from google import genai
from google.genai import types

import config
from ai_analyzer import analyze_with_ai

TEST_CASES_FILE = Path(__file__).resolve().parent / "tests" / "test_cases.json"


def confidence_to_level(score: int) -> str:
    """Use the existing 35/65 score bands directly on Gemini's score."""
    if score >= 65:
        return "สูง"
    if score >= 35:
        return "ปานกลาง"
    return "ต่ำ"


def inspect_message(text: str, client: genai.Client) -> dict:
    """Return only validated Gemini output and its direct score classification."""
    if not text.strip():
        raise ValueError("Message must not be empty.")
    analysis = analyze_with_ai(text, client=client, ai_only=True)
    return {
        "input_text": text,
        "ai_result": analysis,
        "risk_level": confidence_to_level(analysis["ai_confidence"]),
    }


def run_cases(client: genai.Client, json_output: bool = False, *, inspect_fn=None, mode: str = "ai_only") -> dict:
    """Run every example; failed API calls are errors, never successful predictions."""
    cases = json.loads(TEST_CASES_FILE.read_text(encoding="utf-8"))
    rows = []
    inspect_fn = inspect_fn or inspect_message
    for case in cases:
        row = {"id": case["id"], "description": case["description"], "expected_risk": case["expected_risk"]}
        try:
            row.update(inspect_fn(case["text"], client))
            row["pass"] = row["risk_level"] == case["expected_risk"]
        except (RuntimeError, ValueError) as exc:
            row.update({"input_text": case["text"], "error": str(exc), "pass": False})
        rows.append(row)
        if not json_output:
            print(json.dumps(row, ensure_ascii=False, indent=2), flush=True)
    report = {
        "mode": mode,
        "score_bands": "0-34 low, 35-64 medium, 65-100 high; direct AI score" +
                       ("; VirusTotal malicious overrides to high without changing AI score" if mode == "gemini_virustotal_no_kb" else ""),
        "total": len(rows),
        "passed": sum(row["pass"] for row in rows),
        "errors": sum("error" in row for row in rows),
        "links_checked": sum(len(row.get("vt_results", [])) for row in rows),
        "links_unknown": sum(vt.get("verdict") == "unknown" for row in rows for vt in row.get("vt_results", [])),
        "link_errors": sum(bool(vt.get("error")) for row in rows for vt in row.get("vt_results", [])),
        "results": rows,
    }
    if json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Passed: {report['passed']}/{report['total']}; AI errors: {report['errors']}; "
              f"links checked: {report['links_checked']}; unknown: {report['links_unknown']}; link errors: {report['link_errors']}")
    return report


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Test Gemini alone, without Knowledge Base or VirusTotal.")
    parser.add_argument("message", nargs="?", help="Message to analyze; omit for interactive input.")
    parser.add_argument("--cases", action="store_true", help="Run tests/test_cases.json (8 examples).")
    parser.add_argument("--json", action="store_true", help="Print a single JSON report.")
    args = parser.parse_args()
    if args.cases and args.message is not None:
        parser.error("Choose either a message or --cases.")
    if not config.GEMINI_API_KEY or config.GEMINI_API_KEY == "your_gemini_api_key_here":
        print("Set GEMINI_API_KEY in .env before testing.", file=sys.stderr)
        return 2
    try:
        message = args.message
        if not args.cases and message is None:
            message = input("ข้อความที่ต้องการทดสอบ: ").strip()
        with genai.Client(api_key=config.GEMINI_API_KEY, http_options=types.HttpOptions(timeout=30000)) as client:
            if args.cases:
                report = run_cases(client, args.json)
                return 0 if report["passed"] == report["total"] else 1
            result = inspect_message(message or "", client)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        return 130


if __name__ == "__main__":
    sys.exit(main())
