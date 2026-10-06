"""
Configuration module for Scam Checker AI.
Loads and validates environment variables from .env file.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load .env file explicitly from the project root
load_dotenv(dotenv_path=BASE_DIR / ".env")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()

# Default Gemini model (gemini-3.5-flash-lite is fast, reliable, and avoids 503 spikes)
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
GEMINI_OCR_MODEL = os.getenv("GEMINI_OCR_MODEL", GEMINI_MODEL).strip()
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "").strip()


def validate_config() -> None:
    """
    Validates that required API keys are configured properly.
    Raises ValueError if any required key is missing or empty.
    """
    missing = []
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
        missing.append("VIRUSTOTAL_API_KEY")
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
        missing.append("GEMINI_API_KEY")

    if missing:
        raise ValueError(
            f"Missing or invalid configuration for: {', '.join(missing)}. "
            f"Please update your .env file in {BASE_DIR}."
        )


if __name__ == "__main__":
    try:
        validate_config()
        print("Config validated successfully!")
        print(f"- VirusTotal API Key: {'*' * (len(VIRUSTOTAL_API_KEY) - 6) + VIRUSTOTAL_API_KEY[-6:] if len(VIRUSTOTAL_API_KEY) >= 6 else 'Configured'}")
        print(f"- Gemini API Key: {'*' * (len(GEMINI_API_KEY) - 6) + GEMINI_API_KEY[-6:] if len(GEMINI_API_KEY) >= 6 else 'Configured'}")
    except ValueError as e:
        print(f"Configuration Error: {e}")
