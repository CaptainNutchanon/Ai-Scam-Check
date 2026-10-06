import json
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from google.genai.errors import APIError
from ocr_analyzer import extract_text, OCRError


def test_ocr_returns_full_editable_text_not_risk_or_truncated():
    client = Mock()
    text = "ข้อความ\nhttps://example.invalid/path\n" + "ก" * 4100
    client.models.generate_content.return_value = SimpleNamespace(text=json.dumps({"text": text, "warnings": ["ตัวเลขอาจไม่ชัด"]}))
    result = extract_text(b"image-data", "image/png", client=client)
    assert result == {"text": text, "warnings": ["ตัวเลขอาจไม่ชัด"]}
    assert client.models.generate_content.call_count == 1
    assert client.models.generate_content.call_args.kwargs["contents"][0].inline_data.data == b"image-data"
    client.close.assert_not_called()


@pytest.mark.parametrize("body", ["not-json", '{}', '{"text": ""}', '{"text": 1}', '{"text": "   "}'])
def test_unreadable_results_never_produce_fake_text(body):
    client = Mock()
    client.models.generate_content.return_value = SimpleNamespace(text=body)
    with pytest.raises(OCRError):
        extract_text(b"image", "image/png", client=client)


def test_transient_retry_is_bounded_and_provider_errors_hidden():
    client = Mock()
    client.models.generate_content.side_effect = [APIError(503, {"error": {"message": "private-provider-detail"}})] * 2
    sleeper = Mock()
    with pytest.raises(OCRError) as error:
        extract_text(b"image", "image/png", client=client, sleep=sleeper)
    assert "private" not in str(error.value)
    assert client.models.generate_content.call_count == 2
    sleeper.assert_called_once_with(1)


def test_permission_errors_not_retried():
    client = Mock()
    client.models.generate_content.side_effect = APIError(403, {"error": {"message": "private"}})
    with pytest.raises(OCRError):
        extract_text(b"image", "image/png", client=client)
    assert client.models.generate_content.call_count == 1
