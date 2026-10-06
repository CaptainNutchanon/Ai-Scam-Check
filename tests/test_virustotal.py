"""
Unit tests for virustotal_checker.py
"""

from unittest.mock import MagicMock, patch
import pytest
import requests

from virustotal_checker import check_url, get_url_id, _CACHE


@pytest.fixture(autouse=True)
def clear_cache():
    _CACHE.clear()


def test_get_url_id():
    url = "https://example.com"
    encoded = get_url_id(url)
    assert "=" not in encoded
    assert len(encoded) > 0


def test_empty_url():
    res = check_url("")
    assert res["verdict"] == "unknown"
    assert res["malicious_count"] == 0


@patch("virustotal_checker._make_request_with_retry")
def test_safe_url(mock_req):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 75,
                    "undetected": 15,
                }
            }
        }
    }
    mock_req.return_value = mock_resp

    res = check_url("https://safe-site.com")
    assert res["verdict"] == "safe"
    assert res["malicious_count"] == 0
    assert res["total_engines"] == 90


@patch("virustotal_checker._make_request_with_retry")
def test_malicious_url(mock_req):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 2,
                    "harmless": 10,
                    "undetected": 70,
                }
            }
        }
    }
    mock_req.return_value = mock_resp

    res = check_url("https://malicious-site.com")
    assert res["verdict"] == "malicious"
    assert res["malicious_count"] == 10


@patch("virustotal_checker._make_request_with_retry")
def test_api_failure_fallback(mock_req):
    mock_req.return_value = None  # network error or 5xx exceeded retries

    res = check_url("https://fail-site.com")
    assert res["verdict"] == "unknown"
    assert res["malicious_count"] == 0


@patch("virustotal_checker._make_request_with_retry")
def test_caching(mock_req):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 50,
                    "undetected": 10,
                }
            }
        }
    }
    mock_req.return_value = mock_resp

    url = "https://cached-site.com"
    res1 = check_url(url)
    res2 = check_url(url)

    assert res1 == res2
    assert mock_req.call_count == 1  # Only 1 HTTP call made due to caching
