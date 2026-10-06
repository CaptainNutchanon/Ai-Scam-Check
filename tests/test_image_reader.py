from io import BytesIO
import pytest
from PIL import Image, PngImagePlugin
import image_reader
from image_reader import ImageInputError, prepare_image


def png_bytes(size=(10, 12)):
    output = BytesIO()
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("private", "sensitive-metadata")
    Image.new("RGB", size, "red").save(output, "PNG", pnginfo=metadata)
    return output.getvalue()


def test_image_is_sanitized_in_memory_and_metadata_removed():
    result, mime = prepare_image(png_bytes(), "image/png")
    assert mime == "image/png"
    assert b"sensitive-metadata" not in result
    with Image.open(BytesIO(result)) as image:
        assert image.size == (10, 12)
        assert not image.info


@pytest.mark.parametrize("data,mime", [(b"", "image/png"), (b"not an image", "image/png"), (png_bytes(), "image/jpeg"), (png_bytes(), "image/svg+xml")])
def test_invalid_images_rejected_before_provider(data, mime):
    with pytest.raises(ImageInputError):
        prepare_image(data, mime)


def test_pixel_and_byte_limits(monkeypatch):
    monkeypatch.setattr(image_reader, "MAX_IMAGE_PIXELS", 100)
    with pytest.raises(ImageInputError, match="16"):
        prepare_image(png_bytes(), "image/png")
    monkeypatch.setattr(image_reader, "MAX_IMAGE_BYTES", 10)
    with pytest.raises(ImageInputError, match="5 MiB"):
        prepare_image(png_bytes(), "image/png")


def test_animated_upload_rejected():
    output = BytesIO()
    Image.new("RGB", (4, 4), "red").save(output, "PNG", save_all=True,
        append_images=[Image.new("RGB", (4, 4), "blue")], duration=100)
    with pytest.raises(ImageInputError, match="ภาพนิ่ง"):
        prepare_image(output.getvalue(), "image/png")


def test_exif_orientation_is_applied():
    output = BytesIO()
    image = Image.new("RGB", (10, 20), "white")
    exif = image.getexif()
    exif[274] = 6
    image.save(output, "JPEG", exif=exif)
    result, _ = prepare_image(output.getvalue(), "image/jpeg")
    with Image.open(BytesIO(result)) as sanitized:
        assert sanitized.size == (20, 10)
        assert not sanitized.getexif()
