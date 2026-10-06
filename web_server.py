"""Local Scam Checker web UI with Supabase history, evidence highlights and OCR."""

import argparse
import json
import logging
import mimetypes
import secrets
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

import config
from main import check_message
from parser import parse_message
from knowledge_base import check_knowledge_base
from evidence_highlights import build_highlights
from history_store import HistoryStore, HistoryError
from image_reader import prepare_image, ImageInputError, MAX_IMAGE_BYTES
from ocr_analyzer import extract_text, OCRError

WEB_DIR = Path(__file__).resolve().parent / "web"
MAX_TEXT_LENGTH = 4000
MAX_URLS = 3
MAX_BODY_BYTES = 32768
RESULT_TTL = 15 * 60
STATIC_FILES = {"/": "index.html", "/index.html": "index.html", "/styles.css": "styles.css", "/app.js": "app.js", "/features.js": "features.js", "/features.css": "features.css", "/favicon.svg": "favicon.svg"}
logger = logging.getLogger(__name__)


class JobStore:
    """Serialize provider calls and retain only bounded, temporary results."""

    def __init__(self, checker=check_message, ocr=extract_text):
        self.checker = checker
        self.ocr = ocr
        self.jobs = {}
        self.lock = threading.Lock()
        self.slot = threading.BoundedSemaphore(1)

    def _purge(self):
        now = time.monotonic()
        self.jobs = {key: job for key, job in self.jobs.items()
                     if job["status"] == "running" or now - job["finished_at"] < RESULT_TTL}

    def submit(self, text, source_type="text"):
        return self._submit("check", text, source_type)

    def submit_ocr(self, data, mime_type):
        return self._submit("ocr", data, mime_type)

    def _submit(self, kind, payload, extra):
        if not self.slot.acquire(blocking=False):
            return None
        job_id = secrets.token_urlsafe(24)
        with self.lock:
            self._purge()
            while len(self.jobs) >= 32:
                del self.jobs[next(iter(self.jobs))]
            self.jobs[job_id] = {"kind": kind, "status": "running", "stage": "ocr" if kind == "ocr" else "parsing", "url_count": len(parse_message(payload)["urls"]) if kind == "check" else 0, "finished_at": None}
        try:
            threading.Thread(target=self._run, args=(job_id, kind, payload, extra), daemon=True).start()
        except Exception:
            with self.lock:
                self.jobs.pop(job_id, None)
            self.slot.release()
            raise
        return job_id

    def _run(self, job_id, kind, payload, extra):
        def progress(stage):
            with self.lock:
                self.jobs[job_id]["stage"] = stage
        try:
            if kind == "ocr":
                result = self.ocr(payload, extra)
            else:
                result = self.checker(payload, progress=progress)
                risk = result["risk"]
                incomplete = (result.get("ai_result", {}).get("analysis_status") == "unavailable"
                              or result.get("kb_result", {}).get("kb_status") == "unavailable"
                              or any(row.get("verdict") == "unknown" for row in result.get("vt_results", [])))
                result["metadata"] = {"job_id": job_id, "source_type": extra, "report_version": 1,
                    "analyzed_at": datetime.now(timezone.utc).isoformat(),
                    "analysis_status": "unavailable" if risk.get("risk_score") is None else "partial" if incomplete else "complete"}
                result["evidence_highlights"] = build_highlights(result["input_text"], result.get("ai_result", {}))
            with self.lock:
                self.jobs[job_id].update(status="done", stage="done", result=result, finished_at=time.monotonic())
        except Exception as exc:
            # Do not log SMS contents, provider responses, or credentials.
            logger.error("Web analysis failed (%s)", type(exc).__name__)
            with self.lock:
                error = str(exc) if kind == "ocr" and isinstance(exc, OCRError) else "อ่านข้อความจากภาพไม่สำเร็จ กรุณาลองภาพที่ชัดขึ้นหรือตรวจการตั้งค่า Gemini" if kind == "ocr" else "ตรวจสอบไม่สำเร็จ กรุณาลองใหม่อีกครั้ง"
                self.jobs[job_id].update(status="error", error=error, finished_at=time.monotonic())
        finally:
            self.slot.release()

    def get(self, job_id):
        with self.lock:
            self._purge()
            job = self.jobs.get(job_id)
            return deepcopy(job) if job else None

    def cleanup(self):
        with self.lock:
            self._purge()


class RequestError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def handler_for(store, history=None):
    history = history or HistoryStore()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Do not log raw request lines: history query strings contain text.
            logger.info("%s %s", self.command, urlsplit(self.path).path)

        def _headers(self, status, content_type, size):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            self.end_headers()

        def _send(self, status, data):
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(body))
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _trusted_request(self):
            # This server intentionally binds to loopback. Reject DNS rebinding,
            # cross-site fetches and forms before they can spend API quota.
            host = self.headers.get("Host", "")
            expected = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
            if host not in expected:
                self._reject_request("ใช้เว็บผ่าน localhost หรือ 127.0.0.1 เท่านั้น")
                return False
            origin = self.headers.get("Origin")
            if origin and origin != f"http://{host}":
                self._reject_request("ไม่อนุญาตการเรียกจากเว็บไซต์อื่น")
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self._reject_request("ไม่อนุญาตการเรียกจากเว็บไซต์อื่น")
                return False
            return True

        def _reject_request(self, message):
            # On Windows, closing with an unread small POST body can reset the
            # socket before the client receives 403. Drain bounded bytes only;
            # never parse, log or process rejected content.
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if 0 < size <= MAX_BODY_BYTES and not self.headers.get("Transfer-Encoding"):
                    self.connection.settimeout(.2)
                    self.rfile.read(size)
            except (ValueError, OSError):
                pass
            self.close_connection = True
            self._send(403, {"error": message})

        def _dispatch(self, route):
            if not self._trusted_request():
                return
            try:
                route()
            except (RequestError, HistoryError) as exc:
                self._send(exc.status, {"error": str(exc)})
            except (ValueError, ImageInputError) as exc:
                self._send(400, {"error": str(exc)})
            except Exception as exc:
                logger.error("Request failed (%s)", type(exc).__name__)
                self._send(503, {"error": "ดำเนินการไม่สำเร็จ กรุณาลองใหม่"})

        def do_GET(self):
            self._dispatch(self._get)

        def _get(self):
            path = urlsplit(self.path).path
            if path == "/api/status":
                kb = check_knowledge_base("")
                self._send(200, {"gemini": bool(config.GEMINI_API_KEY), "virustotal": bool(config.VIRUSTOTAL_API_KEY), "knowledge_base": kb["kb_status"] == "ready", "kb_phrase_count": kb["phrase_count"], "max_length": MAX_TEXT_LENGTH, "max_urls": MAX_URLS, "history_configured": history.configured, "max_image_bytes": MAX_IMAGE_BYTES})
            elif path == "/api/history":
                params = parse_qs(urlsplit(self.path).query, max_num_fields=12)
                def param(name, default=""):
                    values = params.get(name, [default])
                    if len(values) != 1:
                        raise ValueError("ตัวกรองประวัติซ้ำกัน")
                    return values[0]
                def timestamp(name):
                    raw = param(name)
                    return datetime.fromisoformat(raw.replace("Z", "+00:00")) if raw else None
                starred = param("starred", "false")
                if starred not in {"true", "false"}:
                    raise ValueError("ตัวกรองรายการสำคัญไม่ถูกต้อง")
                self._send(200, history.list(page=int(param("page", "1")), query=param("q"), level=param("level"), starred=starred == "true", start=timestamp("start"), end=timestamp("end")))
            elif path.startswith("/api/history/"):
                record = history.get(path.removeprefix("/api/history/"))
                report = record["report_json"]
                report["evidence_highlights"] = build_highlights(report["input_text"], report.get("ai_result", {}))
                self._send(200, record)
            elif path.startswith("/api/jobs/"):
                job = store.get(path.removeprefix("/api/jobs/"))
                if job:
                    self._send(200, {key: value for key, value in job.items() if key != "finished_at"})
                else:
                    self._send(404, {"error": "ผลตรวจหมดอายุหรือไม่พบรายการ กรุณาตรวจใหม่"})
            elif path in STATIC_FILES:
                file = WEB_DIR / STATIC_FILES[path]
                try:
                    body = file.read_bytes()
                except OSError:
                    self._send(404, {"error": "ไม่พบไฟล์หน้าเว็บ"})
                    return
                content_type = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
                if file.suffix in {".html", ".css", ".js", ".svg"}:
                    content_type += "; charset=utf-8"
                self._headers(200, content_type, len(body))
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                self._send(404, {"error": "ไม่พบหน้าที่ต้องการ"})

        def _body(self, maximum):
            if self.headers.get("Transfer-Encoding"):
                raise RequestError("ไม่รองรับรูปแบบการส่งข้อมูลนี้", 400)
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                size = 0
            if size <= 0 or size > maximum:
                raise RequestError("ข้อมูลมีขนาดไม่ถูกต้องหรือเกินขนาดที่รองรับ", 413)
            self.connection.settimeout(10)
            try:
                body = self.rfile.read(size)
                if len(body) != size:
                    raise RequestError("ได้รับข้อมูลไม่ครบ")
                return body
            except (TimeoutError, OSError) as exc:
                raise RequestError("รับข้อมูลไม่สำเร็จ กรุณาลองใหม่") from exc

        def _json(self):
            if self.headers.get_content_type() != "application/json":
                raise RequestError("กรุณาส่งข้อความในรูปแบบ JSON", 415)
            try:
                payload = json.loads(self._body(MAX_BODY_BYTES))
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise RequestError("อ่านข้อความไม่สำเร็จ กรุณาลองใหม่") from exc
            if not isinstance(payload, dict):
                raise RequestError("ข้อมูลต้องเป็น JSON object")
            return payload

        def do_POST(self):
            self._dispatch(self._post)

        def _post(self):
            path = urlsplit(self.path).path
            if path == "/api/ocr":
                if not config.GEMINI_API_KEY:
                    raise RequestError("ยังไม่ได้ตั้งค่า GEMINI_API_KEY ใน .env", 503)
                data, mime_type = prepare_image(self._body(MAX_IMAGE_BYTES), self.headers.get_content_type())
                job_id = store.submit_ocr(data, mime_type)
                if job_id is None:
                    raise RequestError("ระบบกำลังประมวลผลงานอื่น กรุณารอให้เสร็จ", 429)
                self._send(202, {"job_id": job_id, "kind": "ocr"})
                return
            if path == "/api/history":
                payload = self._json()
                job_id = payload.get("job_id")
                if not isinstance(job_id, str) or len(job_id) != 32:
                    raise RequestError("รหัสผลตรวจไม่ถูกต้อง")
                job = store.get(job_id)
                if not job:
                    raise RequestError("ผลตรวจหมดอายุ จึงบันทึกไม่ได้ กรุณาตรวจใหม่", 404)
                if job["status"] != "done" or job.get("kind") != "check":
                    raise RequestError("บันทึกได้เฉพาะผลวิเคราะห์ข้อความที่เสร็จแล้ว")
                self._send(200, history.save(job_id, job["result"]))
                return
            if path != "/api/check":
                raise RequestError("ไม่พบคำสั่งที่ต้องการ", 404)
            payload = self._json()
            text = payload.get("message")
            source_type = payload.get("source_type", "text")
            if not isinstance(source_type, str) or source_type not in {"text", "image"}:
                raise RequestError("ที่มาของข้อความไม่ถูกต้อง")
            if not isinstance(text, str) or not text.strip():
                self._send(400, {"error": "กรุณาใส่ข้อความที่ต้องการตรวจสอบ"})
                return
            if len(text) > MAX_TEXT_LENGTH:
                self._send(400, {"error": f"ตรวจได้ครั้งละไม่เกิน {MAX_TEXT_LENGTH:,} ตัวอักษร"})
                return
            if len(parse_message(text)["urls"]) > MAX_URLS:
                self._send(400, {"error": f"ตรวจได้ครั้งละไม่เกิน {MAX_URLS} ลิงก์ กรุณาแบ่งข้อความ"})
                return
            if not config.GEMINI_API_KEY:
                self._send(503, {"error": "ยังไม่ได้ตั้งค่า GEMINI_API_KEY ในไฟล์ .env ของโปรเจกต์"})
                return
            job_id = store.submit(text.strip(), source_type)
            if job_id is None:
                self._send(429, {"error": "ระบบกำลังตรวจข้อความอื่นอยู่ กรุณารอให้เสร็จแล้วลองใหม่"})
                return
            self._send(202, {"job_id": job_id})

        def do_PATCH(self):
            self._dispatch(self._patch)

        def _patch(self):
            path = urlsplit(self.path).path
            if not path.startswith("/api/history/"):
                raise RequestError("ไม่พบคำสั่งที่ต้องการ", 404)
            payload = self._json()
            self._send(200, history.star(path.removeprefix("/api/history/"), payload.get("is_starred")))

        def do_DELETE(self):
            self._dispatch(self._delete)

        def _delete(self):
            path = urlsplit(self.path).path
            if path == "/api/history":
                if self._json().get("confirm") != "delete_all_history":
                    raise RequestError("กรุณายืนยันการล้างประวัติ")
                self._send(200, history.delete())
            elif path.startswith("/api/history/"):
                self._send(200, history.delete(path.removeprefix("/api/history/")))
            else:
                raise RequestError("ไม่พบคำสั่งที่ต้องการ", 404)

    return Handler


def make_server(port=8000, store=None, history=None):
    store = store or JobStore()
    server = ThreadingHTTPServer(("127.0.0.1", port), handler_for(store, history))
    server.service_actions = store.cleanup
    return server


def main():
    parser = argparse.ArgumentParser(description="เปิดเว็บ Scam Checker AI")
    parser.add_argument("--port", type=int, default=8000, help="พอร์ตหน้าเว็บ (ค่าเริ่มต้น 8000)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port ต้องอยู่ระหว่าง 1 และ 65535")
    try:
        server = make_server(args.port)
    except OSError:
        parser.exit(1, f"เปิดพอร์ต {args.port} ไม่ได้ ลอง python web_server.py --port 8001\n")
    print(f"Scam Checker พร้อมใช้งาน: http://127.0.0.1:{server.server_port}", flush=True)
    print("หยุดเว็บด้วย Ctrl+C", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
