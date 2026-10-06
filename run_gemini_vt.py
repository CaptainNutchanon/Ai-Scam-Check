"""Test Gemini with VirusTotal evidence, without loading the Knowledge Base."""

import argparse
import json
import sys
from pathlib import Path

from google import genai
from google.genai import types

import config
from ai_analyzer import analyze_with_ai
from parser import parse_message
from run_ai_only import confidence_to_level, run_cases
from virustotal_checker import check_url


def inspect_message(text: str, client: genai.Client) -> dict:
    """Check extracted URLs, then supply real VT evidence to Gemini without KB."""
    if not text.strip():
        raise ValueError("Message must not be empty.")
    urls = parse_message(text)["urls"]
    vt_results = [check_url(url) for url in urls]
    analysis = analyze_with_ai(
        text, vt_results=vt_results, client=client, use_knowledge_base=False,
    )
    level = confidence_to_level(analysis["ai_confidence"])
    decision_source = "gemini"
    if any(result["verdict"] == "malicious" for result in vt_results):
        level = "สูง"
        decision_source = "virustotal_malicious_override"
    return {
        "input_text": text,
        "urls": urls,
        "vt_results": vt_results,
        "ai_result": analysis,
        "risk_level": level,
        "decision_source": decision_source,
    }


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Test Gemini + VirusTotal without Knowledge Base.")
    parser.add_argument("message", nargs="?", help="Message to inspect; omit for interactive input.")
    parser.add_argument("--cases", action="store_true", help="Run the eight example messages.")
    parser.add_argument("--json", action="store_true", help="Print a single JSON report.")
    parser.add_argument("--output", type=Path, help="Save the JSON result to this file.")
    args = parser.parse_args()
    if args.cases and args.message is not None:
        parser.error("Choose either a message or --cases.")
    for name in ("GEMINI_API_KEY", "VIRUSTOTAL_API_KEY"):
        value = getattr(config, name)
        if not value or value.startswith("your_"):
            print(f"Set {name} in .env before testing.", file=sys.stderr)
            return 2
    try:
        message = args.message
        if not args.cases and message is None:
            message = input("ข้อความที่ต้องการทดสอบ: ").strip()
        with genai.Client(api_key=config.GEMINI_API_KEY, http_options=types.HttpOptions(timeout=30000)) as client:
            if args.cases:
                report = run_cases(client, args.json, inspect_fn=inspect_message, mode="gemini_virustotal_no_kb")
                exit_code = 0 if report["passed"] == report["total"] and not report["link_errors"] else 1
            else:
                report = inspect_message(message or "", client)
                print(json.dumps(report, ensure_ascii=False, indent=2))
                exit_code = 1 if any(vt.get("error") for vt in report["vt_results"]) else 0
        if args.output:
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return exit_code
    except (RuntimeError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        return 130


if __name__ == "__main__":
    sys.exit(main())
