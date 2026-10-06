"""
Parser module for extracting and normalizing URLs and cleaning text.
Handles obfuscated URLs (e.g. hxxp://, [.]), shorteners, and text-only separation.
"""

import re
from typing import TypedDict, List
from urllib.parse import urlparse


class ParsedMessage(TypedDict):
    urls: List[str]
    text_only: str


# Common URL shorteners and high-risk domains without explicit protocol
COMMON_SHORTENERS = (
    r"bit\.ly|tinyurl\.com|t\.co|is\.gd|buff\.ly|ow\.ly|line\.me|cutt\.ly|rb\.gy|v\.gd"
)

# Regex to match URLs (including http, https, www, common shorteners, and IP addresses)
URL_REGEX = re.compile(
    r"(?i)\b(?:https?://|www\.|(?:"
    + COMMON_SHORTENERS
    + r")/)"
    + r"[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)


def deobfuscate_text(text: str) -> str:
    """
    Deobfuscates common evasive URL representations:
    - hxxp:// or hxxps:// -> http:// or https://
    - [.] or (.) -> .
    - [/] -> /
    """
    text = re.sub(r"(?i)\bhxxps://", "https://", text)
    text = re.sub(r"(?i)\bhxxp://", "http://", text)
    text = re.sub(r"\[\.\]|\(\.\)", ".", text)
    text = re.sub(r"\[/\]|\(/ \)", "/", text)
    return text


def clean_url(raw_url: str) -> str:
    """
    Strips trailing punctuation marks that often get attached to URLs in prose.
    Normalizes scheme (prepends https:// if missing).
    """
    # Strip trailing punctuation marks
    url = re.sub(r"[.,!?;:\"')\]}>]+$", "", raw_url.strip())

    # Add default scheme if starts with www. or shortener domain
    if url.lower().startswith("www."):
        url = "https://" + url
    elif not url.startswith("http://") and not url.startswith("https://"):
        # If it looks like a shortener or domain without scheme
        url = "https://" + url

    return url


def parse_message(text: str) -> ParsedMessage:
    """
    Extracts URLs and isolates text-only content from raw message text.

    Args:
        text: Raw input message string.

    Returns:
        dict: {"urls": list of normalized unique URLs, "text_only": cleaned message}
    """
    if not text:
        return {"urls": [], "text_only": ""}

    # 1. Deobfuscate
    deobfuscated = deobfuscate_text(text)

    # 2. Extract URLs
    raw_matches = URL_REGEX.findall(deobfuscated)

    extracted_urls: List[str] = []
    seen = set()

    for m in raw_matches:
        cleaned = clean_url(m)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            extracted_urls.append(cleaned)

    # 3. Create text_only by removing the original/deobfuscated URL patterns
    # Also strip original matched substrings from deobfuscated text
    text_only = URL_REGEX.sub(" ", deobfuscated)
    # Clean up excess whitespace
    text_only = re.sub(r"\s+", " ", text_only).strip()

    return {
        "urls": extracted_urls,
        "text_only": text_only,
    }


if __name__ == "__main__":
    sample = "ด่วนที่สุด! คลิกที่ hxxp://evil[.]com/login หรือ www.scam-bank.com/transfer หรือ https://bit.ly/scam-test เพื่อรับสิทธิ์!"
    res = parse_message(sample)
    print("Sample:", sample)
    print("Parsed URLs:", res["urls"])
    print("Text Only:", res["text_only"])
