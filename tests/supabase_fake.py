"""In-memory Data API transport for tests ONLY; exercises the real Python SDK."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import threading
from uuid import uuid4
import httpx
from supabase import create_client, ClientOptions


class MemoryDataAPI:
    def __init__(self):
        self.rows = {}
        self.requests = []
        self.lock = threading.Lock()
        self.timeout_after_insert = False
        self.offline = False

    def client(self):
        return create_client("https://unit-test.supabase.co", "sb_secret_unit_test_only",
            options=ClientOptions(httpx_client=httpx.Client(transport=httpx.MockTransport(self.handle)),
                persist_session=False, auto_refresh_token=False))

    def handle(self, request):
        with self.lock:
            self.requests.append(request)
            if self.offline:
                raise httpx.ReadTimeout("private-test-detail", request=request)
            params = request.url.params
            def matching():
                rows = list(self.rows.values())
                for name in ("id", "job_id"):
                    raw = params.get(name)
                    if raw and raw.startswith("eq."):
                        rows = [row for row in rows if row[name] == raw[3:]]
                    elif raw and raw.startswith("neq."):
                        rows = [row for row in rows if row[name] != raw[4:]]
                return rows
            if request.url.path == "/rest/v1/rpc/search_checks":
                payload = json.loads(request.content)
                rows = [row for row in self.rows.values()
                        if payload["p_query"].lower() in row["input_text"].lower()
                        and (not payload["p_level"] or row["risk_level"] == payload["p_level"])
                        and (not payload["p_starred"] or row["is_starred"])
                        and (not payload["p_start"] or row["analyzed_at"] >= payload["p_start"])
                        and (not payload["p_end"] or row["analyzed_at"] < payload["p_end"])]
                rows.sort(key=lambda row: (row["analyzed_at"], row["id"]), reverse=True)
                page = payload["p_page"]
                summaries = [{k: v for k, v in row.items() if k not in {"report_json", "job_id"}} for row in rows[(page-1)*20:page*20]]
                for row in summaries:
                    row["input_text"] = row["input_text"][:180]
                return httpx.Response(200, json={"items": summaries, "total": len(rows), "page": page, "page_size": 20})
            if request.url.path != "/rest/v1/checks":
                return httpx.Response(404, json={"message": "not found", "code": "404"})
            if request.method == "POST":
                assert "resolution=ignore-duplicates" in request.headers["Prefer"]
                payload = json.loads(request.content)
                if any(row["job_id"] == payload["job_id"] for row in self.rows.values()):
                    return httpx.Response(201, json=[])
                row = {"id": str(uuid4()), "saved_at": datetime.now(timezone.utc).isoformat(), "is_starred": False, **payload}
                self.rows[row["id"]] = deepcopy(row)
                if self.timeout_after_insert:
                    self.timeout_after_insert = False
                    raise httpx.ReadTimeout("private", request=request)
                return httpx.Response(201, json=[row])
            rows = matching()
            if request.method == "GET":
                columns = params.get("select", "*")
                result = deepcopy(rows)
                if columns != "*":
                    result = [{k: v for k, v in row.items() if k in columns.split(",")} for row in result]
                return httpx.Response(200, json=result)
            if request.method == "PATCH":
                for row in rows:
                    row.update(json.loads(request.content))
                return httpx.Response(200, json=deepcopy(rows))
            if request.method == "DELETE":
                for row in rows:
                    del self.rows[row["id"]]
                return httpx.Response(200, json=deepcopy(rows))
            return httpx.Response(405, json={"message": "method", "code": "405"})
