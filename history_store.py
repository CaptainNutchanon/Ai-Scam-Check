"""Server-only Supabase saved reports. No persistent local history fallback."""

from contextlib import contextmanager
from datetime import datetime, timezone
import time
from urllib.parse import urlsplit
from uuid import UUID
import httpx
import config

SUMMARY_COLUMNS = "id,analyzed_at,saved_at,source_type,input_text,risk_level,risk_score,analysis_status,is_starred,report_version"


class HistoryError(RuntimeError):
    def __init__(self, message="เชื่อมต่อประวัติ Supabase ไม่สำเร็จ กรุณาลองใหม่", status=503):
        super().__init__(message)
        self.status = status


def valid_uuid(value):
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("รหัสประวัติไม่ถูกต้อง") from exc


class HistoryStore:
    def __init__(self, client_factory=None, *, sleep=time.sleep):
        self.client_factory = client_factory
        self.sleep = sleep

    @property
    def configured(self):
        return bool(self.client_factory or (config.SUPABASE_URL and config.SUPABASE_SECRET_KEY))

    @contextmanager
    def _client(self):
        if self.client_factory:
            yield self.client_factory()
            return
        if not self.configured:
            raise HistoryError("ยังไม่ได้ตั้งค่า SUPABASE_URL และ SUPABASE_SECRET_KEY ใน .env")
        parsed = urlsplit(config.SUPABASE_URL)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise HistoryError("SUPABASE_URL ต้องเป็น HTTPS URL ของโปรเจกต์")
        try:
            from supabase import create_client, ClientOptions
        except ImportError as exc:
            raise HistoryError("ยังไม่ได้ติดตั้ง Supabase SDK กรุณาติดตั้ง requirements.txt") from exc
        # Each HTTP request owns its transport. No shared auth state across threads.
        with httpx.Client(timeout=3.5) as transport:
            client = create_client(config.SUPABASE_URL, config.SUPABASE_SECRET_KEY,
                options=ClientOptions(httpx_client=transport, postgrest_client_timeout=3.5,
                                      persist_session=False, auto_refresh_token=False))
            yield client

    def _run(self, operation, attempts=2):
        for attempt in range(attempts):
            try:
                with self._client() as client:
                    return operation(client)
            except HistoryError:
                raise
            except (httpx.TransportError, ConnectionError, TimeoutError) as exc:
                if attempt + 1 < attempts:
                    self.sleep(.2)
                    continue
                raise HistoryError() from exc
            except Exception as exc:
                # Never expose provider details, keys, SQL or reports.
                raise HistoryError("เข้าถึงประวัติไม่ได้ ตรวจการตั้งค่า Supabase และการสร้างตาราง") from exc

    def _by_job(self, job_id):
        response = self._run(lambda c: c.table("checks").select(SUMMARY_COLUMNS).eq("job_id", job_id).limit(1).execute())
        return response.data[0] if response.data else None

    def save(self, job_id, report):
        risk, metadata = report["risk"], report["metadata"]
        row = {"job_id": job_id, "analyzed_at": metadata["analyzed_at"],
               "source_type": metadata["source_type"], "input_text": report["input_text"],
               "risk_level": risk["risk_level"], "risk_score": risk.get("risk_score"),
               "analysis_status": metadata["analysis_status"], "report_version": metadata["report_version"],
               "report_json": report}
        try:
            response = self._run(lambda c: c.table("checks").upsert(row, on_conflict="job_id", ignore_duplicates=True).execute(), attempts=1)
            if response.data:
                return {k: v for k, v in response.data[0].items() if k in SUMMARY_COLUMNS.split(",")}
        except HistoryError as exc:
            if not self.configured:
                raise
            try:
                existing = self._by_job(job_id)
            except HistoryError:
                raise HistoryError("ยังยืนยันการบันทึกไม่ได้ กรุณาลองบันทึกผลเดิมอีกครั้ง") from exc
            if existing:
                return existing
            raise HistoryError("บันทึกไม่สำเร็จ กรุณาตรวจการเชื่อมต่อและการสร้างตาราง Supabase") from exc
        existing = self._by_job(job_id)
        if existing:
            return existing
        raise HistoryError("ยังยืนยันการบันทึกไม่ได้ กรุณาลองบันทึกผลเดิมอีกครั้ง")

    def list(self, *, page=1, query="", level="", starred=False, start=None, end=None):
        if not isinstance(page, int) or not 1 <= page <= 100000 or len(query) > 200:
            raise ValueError("ตัวกรองประวัติไม่ถูกต้อง")
        if level not in {"", "ต่ำ", "ปานกลาง", "สูง", "ไม่สามารถประเมินได้"}:
            raise ValueError("ระดับความเสี่ยงไม่ถูกต้อง")
        for value in (start, end):
            if value and (not isinstance(value, datetime) or value.tzinfo is None):
                raise ValueError("ช่วงวันที่ไม่ถูกต้อง")
        if start and end and start >= end:
            raise ValueError("วันเริ่มต้นต้องไม่เกินวันสิ้นสุด")

        # A typed RPC uses strpos rather than PostgREST's '*' pattern alias,
        # so %, _, *, commas and quotes are searched literally, including Thai.
        params = {"p_page": page, "p_query": query, "p_level": level, "p_starred": starred,
                  "p_start": start.astimezone(timezone.utc).isoformat() if start else None,
                  "p_end": end.astimezone(timezone.utc).isoformat() if end else None}
        response = self._run(lambda c: c.rpc("search_checks", params).execute())
        return response.data

    def get(self, record_id):
        record_id = valid_uuid(record_id)
        response = self._run(lambda c: c.table("checks").select("*").eq("id", record_id).limit(1).execute())
        if not response.data:
            raise HistoryError("ไม่พบรายการประวัติ", 404)
        return response.data[0]

    def star(self, record_id, starred):
        record_id = valid_uuid(record_id)
        if not isinstance(starred, bool):
            raise ValueError("สถานะรายการสำคัญไม่ถูกต้อง")
        response = self._run(lambda c: c.table("checks").update({"is_starred": starred}).eq("id", record_id).execute())
        if not response.data:
            raise HistoryError("ไม่พบรายการประวัติ", 404)
        return {"id": record_id, "is_starred": starred}

    def delete(self, record_id=None):
        if record_id is not None:
            record_id = valid_uuid(record_id)
        # Never truncate: this operation only touches the app's checks table.
        self._run(lambda c: (c.table("checks").delete().eq("id", record_id) if record_id
                            else c.table("checks").delete().neq("id", "00000000-0000-0000-0000-000000000000")).execute())
        return {"deleted": True}
