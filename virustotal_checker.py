"""
VirusTotal Checker Module for Scam Checker AI.
Interacts with VirusTotal API v3 to scan and retrieve reputation reports for URLs.
Includes rate limiting, caching, exponential backoff retries, and error handling.
"""

import base64
import logging
import time
from typing import Dict, Any, Optional
import requests

import config

logger = logging.getLogger(__name__)

# VirusTotal v3 API endpoints
VT_BASE_URL = "https://www.virustotal.com/api/v3"
URL_REPORT_ENDPOINT = f"{VT_BASE_URL}/urls/{{url_id}}"
URL_SCAN_ENDPOINT = f"{VT_BASE_URL}/urls"

# In-memory cache to prevent duplicate requests for the same URL: {url: result_dict}
_CACHE: Dict[str, Dict[str, Any]] = {}

# Rate limit tracking: VirusTotal Free tier allows ~4 requests per minute
_REQUEST_TIMESTAMPS: list[float] = []
MAX_REQUESTS_PER_MINUTE = 4
WINDOW_SECONDS = 60.0


def _enforce_rate_limit() -> None:
    """
    Enforces the VirusTotal free tier rate limit of 4 requests per minute.
    Sleeps if necessary to stay within quota.
    """
    now = time.time()
    # Filter out timestamps older than WINDOW_SECONDS
    global _REQUEST_TIMESTAMPS
    _REQUEST_TIMESTAMPS = [t for t in _REQUEST_TIMESTAMPS if now - t < WINDOW_SECONDS]

    if len(_REQUEST_TIMESTAMPS) >= MAX_REQUESTS_PER_MINUTE:
        oldest = _REQUEST_TIMESTAMPS[0]
        sleep_needed = WINDOW_SECONDS - (now - oldest) + 0.5
        if sleep_needed > 0:
            logger.info("VirusTotal rate limit reached. Sleeping for %.2f seconds", sleep_needed)
            time.sleep(sleep_needed)

    _REQUEST_TIMESTAMPS.append(time.time())


def get_url_id(url: str) -> str:
    """
    Encodes URL into VirusTotal URL identifier (base64url without '=' padding).
    """
    return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("utf-8").strip("=")


def _make_request_with_retry(
    method: str,
    url: str,
    headers: dict,
    data: Optional[dict] = None,
    max_retries: int = 3,
) -> Optional[requests.Response]:
    """
    Executes an HTTP request with exponential backoff for transient errors and rate limits.
    """
    delay = 2.0
    for attempt in range(1, max_retries + 1):
        try:
            _enforce_rate_limit()
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=15)
            else:
                response = requests.post(url, headers=headers, data=data, timeout=15)

            if response.status_code in (200, 404):
                return response

            if response.status_code == 429:
                logger.warning("VirusTotal HTTP 429 (Rate Limit). Attempt %d/%d. Waiting %.1fs", attempt, max_retries, delay)
                time.sleep(delay)
                delay *= 2
                continue

            if response.status_code >= 500:
                logger.warning("VirusTotal server error %d. Attempt %d/%d. Waiting %.1fs", response.status_code, attempt, max_retries, delay)
                time.sleep(delay)
                delay *= 2
                continue

            # For client errors like 401, 403, 400 - do not retry
            logger.error("VirusTotal returned status %d: %s", response.status_code, response.text)
            return response

        except (requests.ConnectionError, requests.Timeout) as e:
            logger.warning("Network error calling VirusTotal: %s. Attempt %d/%d", e, attempt, max_retries)
            time.sleep(delay)
            delay *= 2

    return None


def check_url(url: str) -> Dict[str, Any]:
    """
    Checks URL reputation using VirusTotal API v3.

    Args:
        url: URL string to inspect.

    Returns:
        dict: {
            "url": str,
            "malicious_count": int,
            "total_engines": int,
            "verdict": "malicious" | "suspicious" | "safe" | "unknown"
        }
    """
    if not url:
        return {
            "url": "",
            "malicious_count": 0,
            "total_engines": 0,
            "verdict": "unknown",
        }

    normalized_url = url.strip()

    # Check memory cache
    if normalized_url in _CACHE:
        logger.debug("Cache hit for URL: %s", normalized_url)
        return _CACHE[normalized_url]

    api_key = config.VIRUSTOTAL_API_KEY
    if not api_key:
        logger.error("VirusTotal API Key is missing.")
        return {
            "url": normalized_url,
            "malicious_count": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "error": "VirusTotal API key is missing",
        }

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    url_id = get_url_id(normalized_url)
    report_url = URL_REPORT_ENDPOINT.format(url_id=url_id)

    # 1. First, check if report already exists for this URL
    res = _make_request_with_retry("GET", report_url, headers=headers)

    # 2. If 404, submit URL for scanning
    scan_submitted = False
    if res is not None and res.status_code == 404:
        logger.info("URL not previously seen by VirusTotal. Submitting for scan: %s", normalized_url)
        scan_res = _make_request_with_retry(
            "POST",
            URL_SCAN_ENDPOINT,
            headers=headers,
            data={"url": normalized_url},
        )
        if scan_res is not None and scan_res.status_code == 200:
            scan_submitted = True
            # Short wait for initial scan results
            time.sleep(2.0)
            res = _make_request_with_retry("GET", report_url, headers=headers)
        else:
            res = scan_res

    # 3. Parse analysis results
    if res is None or res.status_code != 200:
        result = {
            "url": normalized_url,
            "malicious_count": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "scan_submitted": scan_submitted,
            "report_status": "pending_or_not_found" if res is not None and res.status_code == 404 else "error",
        }
        if res is None or res.status_code != 404:
            result["error"] = "VirusTotal request failed" if res is None else f"VirusTotal HTTP {res.status_code}"
        _CACHE[normalized_url] = result
        return result

    try:
        data = res.json().get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total_engines = sum(stats.values())
        malicious_count = malicious + suspicious

        if malicious >= 2 or malicious_count >= 3:
            verdict = "malicious"
        elif malicious_count >= 1:
            verdict = "suspicious"
        elif total_engines > 0:
            verdict = "safe"
        else:
            verdict = "unknown"

        result = {
            "url": normalized_url,
            "malicious_count": malicious_count,
            "total_engines": total_engines,
            "verdict": verdict,
            "scan_submitted": scan_submitted,
            "report_status": "available" if total_engines else "pending",
        }
        _CACHE[normalized_url] = result
        return result

    except Exception as e:
        logger.exception("Failed to parse VirusTotal response: %s", e)
        result = {
            "url": normalized_url,
            "malicious_count": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "error": "VirusTotal response could not be parsed",
        }
        _CACHE[normalized_url] = result
        return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_urls = [
        "https://www.google.com",
    ]
    for u in test_urls:
        print(f"Checking {u}...")
        r = check_url(u)
        print("Result:", r)
