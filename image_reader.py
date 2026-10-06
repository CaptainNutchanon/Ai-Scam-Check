"""Validate and sanitize uploaded screenshots entirely in memory."""

from io import BytesIO
import warnings
from PIL import Image, ImageOps, UnidentifiedImageError

MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 16_000_000
IMAGE_TYPES = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}


class ImageInputError(ValueError):
    pass


def prepare_image(data, declared_type):
    """Decode real image data, orient it and return a metadata-free image."""
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise ImageInputError("เลือกภาพขนาดไม่เกิน 5 MiB")
    if declared_type not in IMAGE_TYPES.values():
        raise ImageInputError("รองรับภาพ PNG, JPEG และ WebP แบบภาพนิ่งเท่านั้น")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data)) as image:
                if IMAGE_TYPES.get(image.format) != declared_type:
                    raise ImageInputError("ชนิดข้อมูลภาพไม่ตรงกับไฟล์ที่ส่งมา")
                if image.width * image.height > MAX_IMAGE_PIXELS:
                    raise ImageInputError("ภาพใหญ่เกิน 16 ล้านพิกเซล กรุณาย่อภาพก่อน")
                if getattr(image, "n_frames", 1) != 1:
                    raise ImageInputError("กรุณาใช้ภาพนิ่งแทนภาพเคลื่อนไหว")
                image.load()
                oriented = ImageOps.exif_transpose(image)
                rgba = oriented.convert("RGBA")
                clean = Image.new("RGB", rgba.size, "white")
                clean.paste(rgba, mask=rgba.getchannel("A"))
                output = BytesIO()
                clean.save(output, format="PNG")
                sanitized = output.getvalue()
                if len(sanitized) > 12 * 1024 * 1024:
                    raise ImageInputError("ภาพหลังแปลงมีขนาดใหญ่เกินไป กรุณาย่อภาพก่อน")
                return sanitized, "image/png"
    except ImageInputError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError,
            Image.DecompressionBombWarning) as exc:
        raise ImageInputError("อ่านไฟล์ภาพไม่ได้ กรุณาเลือกภาพที่สมบูรณ์") from exc
