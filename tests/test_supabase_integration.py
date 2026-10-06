"""Opt-in real database verification. Use a dedicated test Supabase project.

Requires SCAMCHECKER_TEST_SUPABASE_URL, SCAMCHECKER_TEST_SUPABASE_SECRET_KEY,
SCAMCHECKER_TEST_SUPABASE_PUBLISHABLE_KEY and the supplied SQL migration.
Only records created by this test are deleted; never clears the full table.
"""
import os
from uuid import uuid4
from datetime import datetime, timezone
import httpx
import pytest
from supabase import create_client, ClientOptions
from history_store import HistoryStore


@pytest.mark.skipif(not all(os.getenv(name) for name in ["SCAMCHECKER_TEST_SUPABASE_URL", "SCAMCHECKER_TEST_SUPABASE_SECRET_KEY", "SCAMCHECKER_TEST_SUPABASE_PUBLISHABLE_KEY"]), reason="Dedicated Supabase integration credentials not configured")
def test_real_migration_crud_literal_search_and_public_permissions():
    url = os.environ["SCAMCHECKER_TEST_SUPABASE_URL"]
    secret = os.environ["SCAMCHECKER_TEST_SUPABASE_SECRET_KEY"]
    public = os.environ["SCAMCHECKER_TEST_SUPABASE_PUBLISHABLE_KEY"]
    job = uuid4().hex
    text = f"ทดสอบ-{job} %_*"
    with httpx.Client(timeout=8) as transport:
        client = create_client(url, secret, options=ClientOptions(httpx_client=transport, auto_refresh_token=False, persist_session=False))
        store = HistoryStore(lambda: client)
        report = {"input_text": text, "risk": {"risk_level": "ไม่สามารถประเมินได้", "risk_score": None},
            "metadata": {"source_type": "image", "analyzed_at": datetime.now(timezone.utc).isoformat(), "analysis_status": "unavailable", "report_version": 1}}
        record_id = None
        try:
            saved = store.save(job, report)
            record_id = saved["id"]
            assert store.save(job, report)["id"] == record_id
            assert store.get(record_id)["report_json"] == report
            store.star(record_id, True)
            result = store.list(query=text, starred=True)
            assert result["total"] == 1
            assert result["items"][0]["risk_score"] is None
            assert store.list(query=f"{job} _%")["total"] == 0
            headers = {"apikey": public}
            denied = transport.get(url + "/rest/v1/checks", headers=headers, params={"id": f"eq.{record_id}", "select": "*"})
            assert denied.status_code in {401, 403}
            denied_search = transport.post(url + "/rest/v1/rpc/search_checks", headers=headers, json={"p_query": text})
            assert denied_search.status_code in {401, 403, 404}
        finally:
            if record_id:
                store.delete(record_id)
