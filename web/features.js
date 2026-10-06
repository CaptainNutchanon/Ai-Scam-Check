"use strict";

// This file uses the validated form, API and report renderer from app.js.
(() => {
  let source = "text";
  let file = null;
  let previewURL = null;
  let ocrJob = null;
  let ocrBusy = false;
  let historyConfigured = false;
  let saving = false;
  let savedJob = null;
  let page = 1;
  let total = 0;
  let generation = 0;
  let historyBusy = false;
  let selectedRecord = null;
  const dialog = byId("history-dialog");
  const dateFormat = new Intl.DateTimeFormat("th-TH", { dateStyle: "medium", timeStyle: "short" });
  const dateText = (value) => value && Number.isFinite(Date.parse(value)) ? dateFormat.format(new Date(value)) : "ไม่มีข้อมูลเวลา";
  const jsonOptions = (method, payload) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });

  try {
    const saved = sessionStorage.getItem("scamchecker-ocr-job");
    if (saved && /^[A-Za-z0-9_-]{32}$/.test(saved)) ocrJob = saved;
  } catch { /* Temporary job IDs are optional browser state. */ }

  function rememberOCR() {
    try {
      if (ocrJob) sessionStorage.setItem("scamchecker-ocr-job", ocrJob);
      else sessionStorage.removeItem("scamchecker-ocr-job");
    } catch { /* Keep working without storage. */ }
  }

  function resetSource() {
    source = "text";
    byId("source-note").hidden = true;
  }

  function restoreSource(value) {
    source = value === "image" ? "image" : "text";
    byId("source-note").hidden = source !== "image";
    byId("source-note").textContent = "ข้อความจากภาพ — ตรวจแก้ก่อนกดตรวจสอบอีกครั้ง";
  }

  function showTab(image) {
    if (busy || activeJob || ocrBusy) return;
    byId("image-panel").hidden = !image;
    for (const [id, active] of [["tab-text", !image], ["tab-image", image]]) {
      byId(id).classList.toggle("active", active);
      byId(id).setAttribute("aria-pressed", String(active));
    }
  }

  function syncControls() {
    const locked = busy || Boolean(activeJob) || ocrBusy || Boolean(ocrJob);
    for (const id of ["image-file", "tab-text", "tab-image"]) byId(id).disabled = locked;
    byId("remove-image").disabled = locked || !file;
    byId("ocr-button").disabled = busy || Boolean(activeJob) || ocrBusy || (!file && !ocrJob);
    byId("ocr-button").textContent = ocrBusy ? "กำลังอ่านข้อความ..." : ocrJob ? "ติดตามผลอ่านภาพอีกครั้ง" : "อ่านข้อความจากภาพ";
    const jobId = currentReport?.metadata?.job_id;
    byId("save-report").disabled = !historyConfigured || saving || !jobId || savedJob === jobId || !currentReport;
    byId("save-report").textContent = saving ? "กำลังบันทึก..." : jobId && savedJob === jobId ? "บันทึกแล้ว" : "บันทึกผลนี้";
  }

  function invalidateReport() {
    currentReport = null;
    savedJob = null;
    showState("empty-state");
    updateForm();
  }

  function removeImage() {
    if (previewURL) URL.revokeObjectURL(previewURL);
    previewURL = null;
    file = null;
    byId("image-preview").removeAttribute("src");
    byId("image-preview").hidden = true;
    byId("image-file").value = "";
    byId("ocr-status").textContent = "";
    byId("ocr-warnings").replaceChildren();
    // The already extracted text remains an image-derived draft.
    syncControls();
  }

  function chooseImage(files) {
    if (busy || activeJob || ocrBusy || ocrJob) return;
    if (files.length !== 1) {
      byId("ocr-status").textContent = "กรุณาเลือกภาพครั้งละหนึ่งไฟล์";
      return;
    }
    const chosen = files[0];
    if (!["image/png", "image/jpeg", "image/webp"].includes(chosen.type) || chosen.size > 5 * 1024 * 1024 || !chosen.size) {
      byId("ocr-status").textContent = "เลือกภาพ PNG, JPEG หรือ WebP ขนาดไม่เกิน 5 MiB";
      byId("image-file").value = "";
      return;
    }
    removeImage();
    file = chosen;
    previewURL = URL.createObjectURL(file);
    byId("image-preview").src = previewURL;
    byId("image-preview").hidden = false;
    byId("ocr-status").textContent = "ภาพพร้อมแล้ว กดอ่านข้อความจากภาพเพื่อเริ่ม";
    invalidateReport();
  }

  async function readImage() {
    if (ocrBusy || busy || activeJob) return;
    if (!ocrJob && !file) return;
    if (!ocrJob && message.value.trim() && !window.confirm("อ่านข้อความจากภาพแล้วแทนที่ข้อความในช่องปัจจุบันหรือไม่?")) return;
    ocrBusy = true;
    updateForm();
    byId("ocr-status").classList.remove("error");
    byId("ocr-status").textContent = "Gemini กำลังอ่านข้อความจากภาพ...";
    try {
      if (!ocrJob) {
        const submitted = await api("/api/ocr", { method: "POST", headers: { "Content-Type": file.type }, body: file });
        ocrJob = submitted.job_id;
        rememberOCR();
      }
      let failures = 0;
      while (ocrJob) {
        let job;
        try {
          job = await api(`/api/jobs/${encodeURIComponent(ocrJob)}`);
          failures = 0;
        } catch (error) {
          if (error.network && ++failures <= 3) { await pause(1500); continue; }
          if (error.status === 404) { ocrJob = null; rememberOCR(); }
          throw error;
        }
        if (job.kind !== "ocr") { ocrJob = null; rememberOCR(); throw new Error("ไม่พบงานอ่านภาพ กรุณาเลือกภาพใหม่"); }
        if (job.status === "done") {
          ocrJob = null;
          rememberOCR();
          message.value = job.result.text;
          source = "image";
          byId("source-note").hidden = false;
          byId("source-note").textContent = "ข้อความจากภาพ — ตรวจแก้ URL ตัวเลข และข้อความที่อ่านได้ก่อนกดตรวจสอบ";
          byId("ocr-warnings").replaceChildren(...(job.result.warnings || []).map((warning) => element("li", "", warning)));
          byId("ocr-status").textContent = Array.from(message.value).length > 4000 ? "อ่านข้อความแล้ว แต่เกิน 4,000 ตัวอักษร กรุณาเลือกแก้หรือแบ่งข้อความก่อนตรวจ" : "อ่านข้อความแล้ว ตรวจแก้ข้อความด้านล่างก่อนกดตรวจสอบ";
          invalidateReport();
          message.focus();
          return;
        }
        if (job.status === "error") {
          ocrJob = null;
          rememberOCR();
          throw new Error(job.error);
        }
        await pause(1000);
      }
    } catch (error) {
      byId("ocr-status").classList.add("error");
      byId("ocr-status").textContent = error.message;
    } finally {
      ocrBusy = false;
      updateForm();
    }
  }

  function renderHighlights(container, reason, note, report, enabled = true) {
    const data = report.evidence_highlights;
    container.replaceChildren();
    reason.replaceChildren();
    if (!enabled || !data?.segments?.length) {
      container.textContent = report.input_text;
    } else {
      const annotations = new Map(data.annotations.map((item) => [item.id, item]));
      for (const segment of data.segments) {
        const refs = segment.evidence_ids.map((id) => annotations.get(id)).filter(Boolean);
        if (!refs.length) { container.append(document.createTextNode(segment.text)); continue; }
        const button = element("button", `highlight-mark ${refs[0].factor}`, segment.text);
        button.type = "button";
        button.setAttribute("aria-label", `${refs.map((ref) => ref.label).join(" / ")}: ${segment.text}`);
        button.addEventListener("click", () => {
          reason.replaceChildren(...refs.map((ref) => element("p", "", `${ref.label} — ระดับหลักฐาน ${ref.level}/4\n${ref.reason}${ref.occurrences > 1 ? `\nข้อความเดียวกันพบ ${ref.occurrences} ตำแหน่ง ระบบแสดงทุกตำแหน่งที่ตรงกัน` : ""}`)));
        });
        container.append(button);
      }
    }
    note.textContent = !data?.annotations?.length ? "ไม่มีหลักฐานจาก AI สำหรับไฮไลต์ในผลนี้" : data.unmatched?.length ? "หลักฐานบางส่วนเป็น URL จากรายงานที่ไม่ตรงข้อความต้นฉบับ อ่านรายละเอียดได้ในการ์ดลิงก์" : "ไฮไลต์ใช้หลักฐานจากผลตรวจนี้ ไม่ใช่การวิเคราะห์เพิ่ม";
  }

  function onReport(report) {
    savedJob = null;
    const used = new Set((report.evidence_highlights?.annotations || []).map((ref) => ref.factor));
    byId("highlight-legend").replaceChildren(...Object.entries(factorLabels).filter(([name]) => used.has(name)).map(([name, label]) => element("span", `legend-${name}`, label)));
    renderHighlights(byId("highlight-text"), byId("highlight-reason"), byId("highlight-note"), report, byId("highlight-toggle").checked);
    byId("save-status").textContent = historyConfigured ? "บันทึกเมื่อคุณเลือกเท่านั้น ข้อความและรายงานจะเก็บใน Supabase" : "ประวัติยังไม่พร้อม ตั้งค่า Supabase ใน .env แล้วเปิดเซิร์ฟเวอร์ใหม่";
    syncControls();
  }

  async function saveReport() {
    if (!currentReport?.metadata?.job_id || saving) return;
    const jobId = currentReport.metadata.job_id;
    saving = true;
    syncControls();
    try {
      await api("/api/history", jsonOptions("POST", { job_id: jobId }));
      savedJob = jobId;
      byId("save-status").textContent = "บันทึกใน Supabase แล้ว เปิดดูได้ที่เมนูประวัติ";
    } catch (error) { byId("save-status").textContent = error.message; }
    finally { saving = false; syncControls(); }
  }

  function showPage(pageName) {
    const history = pageName === "history";
    const guidance = pageName === "guidance";
    byId("history-panel").hidden = !history;
    byId("guidance-panel").hidden = !guidance;
    byId("check-workspace").hidden = history || guidance;
    document.querySelector(".intro").hidden = guidance;
    byId("how-it-works").hidden = guidance;
    const skipLink = document.querySelector(".skip-link");
    skipLink.href = guidance ? "#guidance-title" : history ? "#history-title" : "#message";
    skipLink.textContent = guidance ? "ข้ามไปคำแนะนำและคำเตือน" : history ? "ข้ามไปประวัติ" : "ข้ามไปช่องตรวจข้อความ";
    syncScamNotice();
    for (const [id, active] of [["nav-check", !history && !guidance], ["nav-history", history], ["nav-guidance", guidance]]) {
      byId(id).classList.toggle("active", active);
      byId(id).setAttribute("aria-pressed", String(active));
    }
    if (history) { byId("history-title").focus(); void loadHistory(); }
    if (guidance) {
      byId("guidance-title").focus({ preventScroll: true });
      byId("guidance-panel").scrollIntoView({ behavior: "instant", block: "start" });
    }
  }

  function filters() {
    const params = new URLSearchParams({ page: String(page), q: byId("history-query").value,
      level: byId("history-level").value, starred: String(byId("history-starred").checked) });
    const start = byId("history-start").value, end = byId("history-end").value;
    if (start && end && start > end) throw new Error("วันเริ่มต้นต้องไม่เกินวันสิ้นสุด");
    // Construct local midnight, then send UTC boundaries (end is exclusive).
    if (start) params.set("start", new Date(`${start}T00:00:00`).toISOString());
    if (end) {
      const next = new Date(`${end}T00:00:00`);
      next.setDate(next.getDate() + 1);
      params.set("end", next.toISOString());
    }
    return params;
  }

  function historyControls() {
    byId("history-prev").disabled = historyBusy || page <= 1;
    byId("history-next").disabled = historyBusy || page * 20 >= total;
    byId("clear-history").disabled = historyBusy || !historyConfigured || !total;
  }

  async function loadHistory() {
    const token = ++generation;
    historyBusy = true;
    historyControls();
    byId("history-list").replaceChildren();
    byId("history-status").classList.remove("error");
    byId("history-status").textContent = "กำลังโหลดประวัติจาก Supabase...";
    try {
      const result = await api(`/api/history?${filters()}`);
      if (token !== generation) return;
      total = result.total;
      if (!result.items.length && page > 1 && total > 0) { page = Math.max(1, Math.ceil(total / 20)); void loadHistory(); return; }
      byId("history-status").textContent = total ? `พบ ${total.toLocaleString("th-TH")} รายการ` : "ยังไม่มีรายการที่ตรงกับตัวกรอง ตรวจข้อความแล้วเลือกบันทึกผลเพื่อเริ่มเก็บประวัติ";
      byId("history-page").textContent = `หน้า ${page} / ${Math.max(1, Math.ceil(total / 20))}`;
      for (const row of result.items) {
        const card = element("article", "history-item");
        const top = element("div", "history-item-top");
        const levelClass = row.risk_level === "สูง" ? "high" : row.risk_level === "ปานกลาง" ? "medium" : "";
        top.append(element("span", `history-badge ${levelClass}`, `${row.risk_level} · ${row.risk_score ?? "—"}/100`), element("time", "", dateText(row.analyzed_at)));
        card.append(top, element("p", "", row.input_text), element("div", "feature-note", `${row.source_type === "image" ? "จากภาพหน้าจอ" : "จากข้อความ"}${row.analysis_status !== "complete" ? " · ผลบางส่วนหรือยังประเมินไม่ได้" : ""}`));
        const actions = element("div", "history-item-actions");
        const open = element("button", "secondary-button", "เปิดรายงาน");
        open.type = "button";
        open.addEventListener("click", () => void openRecord(row.id));
        const star = element("button", "secondary-button", row.is_starred ? "★ สำคัญ" : "☆ ทำรายการสำคัญ");
        star.type = "button";
        star.setAttribute("aria-pressed", String(row.is_starred));
        star.addEventListener("click", () => void mutateRecord(star, () => api(`/api/history/${row.id}`, jsonOptions("PATCH", { is_starred: !row.is_starred }))));
        const remove = element("button", "danger-button", "ลบ");
        remove.type = "button";
        remove.addEventListener("click", () => {
          if (window.confirm("ลบรายงานนี้ออกจากประวัติ Supabase หรือไม่?")) void mutateRecord(remove, () => api(`/api/history/${row.id}`, { method: "DELETE" }));
        });
        actions.append(open, star, remove);
        card.append(actions);
        byId("history-list").append(card);
      }
    } catch (error) {
      if (token !== generation) return;
      total = 0;
      byId("history-status").classList.add("error");
      byId("history-status").textContent = error.message;
      byId("history-page").textContent = "";
    } finally {
      if (token === generation) { historyBusy = false; historyControls(); }
    }
  }

  async function mutateRecord(button, action) {
    button.disabled = true;
    try { await action(); await loadHistory(); }
    catch (error) { byId("history-status").textContent = error.message; byId("history-status").classList.add("error"); }
    finally { button.disabled = false; historyControls(); }
  }

  function detailBlock(title) {
    const block = element("section", "history-detail-block");
    block.append(element("h3", "", title));
    return block;
  }

  async function openRecord(id) {
    try {
      selectedRecord = await api(`/api/history/${id}`);
      const report = selectedRecord.report_json, risk = report.risk, ai = report.ai_result || {}, kb = report.kb_result || {};
      const root = byId("history-detail");
      root.replaceChildren();
      const summary = detailBlock(`${risk.risk_level} · ${risk.risk_score ?? "—"}/100`);
      summary.append(element("p", "", `${risk.scam_type || ""}\nตรวจเมื่อ ${dateText(selectedRecord.analyzed_at)}\nบันทึกเมื่อ ${dateText(selectedRecord.saved_at)}\n${selectedRecord.source_type === "image" ? "จากภาพหน้าจอ" : "จากข้อความ"}\n${selectedRecord.analysis_status === "complete" ? "ผลตรวจครบ" : selectedRecord.analysis_status === "partial" ? "ผลตรวจบางส่วน" : "ยังประเมินไม่ได้"}`), element("p", "feature-note", "คะแนนตามเกณฑ์ ไม่ใช่เปอร์เซ็นต์ความแม่นยำ รายงานนี้เป็นผล ณ เวลาที่ตรวจ"));
      root.append(summary);
      const sourceBlock = detailBlock("ข้อความและหลักฐาน");
      const text = element("div", "highlight-text"), reason = element("div", "highlight-reason"), note = element("p", "feature-note");
      renderHighlights(text, reason, note, report);
      sourceBlock.append(text, reason, note);
      root.append(sourceBlock);
      const analysis = detailBlock("ผลวิเคราะห์และเหตุผลของคะแนน");
      analysis.append(element("p", "", ai.ai_summary || "ไม่มีข้อมูล AI"), element("p", "feature-note", ai.analysis_status === "unavailable" ? "AI ไม่พร้อมใช้งานในผลนี้" : `คะแนน AI ${ai.ai_confidence ?? "—"}/100`));
      const reasons = element("ul", "");
      reasons.append(...(risk.reasons || []).map((value) => element("li", "", value)));
      analysis.append(reasons);
      for (const [name, label] of Object.entries(factorLabels)) {
        const factor = ai.risk_assessment?.[name];
        if (!factor) continue;
        analysis.append(element("h3", "", `${label} · ระดับ ${factor.level}/4 · ${ai.score_breakdown?.[name] ?? "—"} คะแนน`), element("p", "", factor.reason));
        for (const quote of factor.evidence || []) analysis.append(element("blockquote", "", quote));
      }
      root.append(analysis);
      const sources = detailBlock("Knowledge Base และผลลิงก์");
      sources.append(element("p", "", kb.kb_status === "unavailable" ? "ฐานคำไม่พร้อมใช้งาน" : `KB ${kb.kb_score ?? "—"}/100\n${(kb.matched_phrases || []).join(" · ") || "ไม่พบคำตรงกับฐานข้อมูล"}`));
      if (!report.vt_results?.length) sources.append(element("p", "", "ไม่มีลิงก์ที่ตรวจในรายงานนี้"));
      for (const link of report.vt_results || []) sources.append(element("p", "", `${link.url}\nผล: ${link.verdict} · ${link.malicious_count ?? 0}/${link.total_engines ?? 0} engines${link.verdict === "unknown" ? " · ยังยืนยันไม่ได้" : link.verdict === "safe" ? " · ไม่พบการตรวจจับไม่ได้รับประกันความปลอดภัย" : ""}`));
      root.append(sources);
      byId("reuse-history").disabled = busy || Boolean(activeJob) || ocrBusy || Boolean(ocrJob);
      if (!dialog.open) dialog.showModal();
    } catch (error) { byId("history-status").textContent = error.message; }
  }

  window.ScamFeatures = { onReport, syncControls, resetSource, restoreSource, sourceType: () => source, ocrLocked: () => ocrBusy || Boolean(ocrJob) };
  byId("tab-text").addEventListener("click", () => showTab(false));
  byId("tab-image").addEventListener("click", () => showTab(true));
  byId("image-file").addEventListener("change", (event) => chooseImage(event.target.files));
  byId("remove-image").addEventListener("click", removeImage);
  byId("ocr-button").addEventListener("click", () => void readImage());
  byId("image-drop").addEventListener("dragover", (event) => { event.preventDefault(); byId("image-drop").classList.add("drag-over"); });
  byId("image-drop").addEventListener("dragleave", () => byId("image-drop").classList.remove("drag-over"));
  byId("image-drop").addEventListener("drop", (event) => { event.preventDefault(); byId("image-drop").classList.remove("drag-over"); chooseImage(event.dataTransfer.files); });
  byId("highlight-toggle").addEventListener("change", () => {
    if (currentReport) renderHighlights(byId("highlight-text"), byId("highlight-reason"), byId("highlight-note"), currentReport, byId("highlight-toggle").checked);
  });
  message.addEventListener("input", invalidateReport);
  byId("clear-button").addEventListener("click", () => { resetSource(); removeImage(); invalidateReport(); });
  document.querySelectorAll(".example-button").forEach((button) => button.addEventListener("click", () => { resetSource(); removeImage(); invalidateReport(); }));
  byId("save-report").addEventListener("click", () => void saveReport());
  byId("nav-check").addEventListener("click", () => showPage("check"));
  byId("nav-history").addEventListener("click", () => showPage("history"));
  byId("nav-guidance").addEventListener("click", () => showPage("guidance"));
  byId("guide-check").addEventListener("click", () => { showPage("check"); message.focus(); });
  document.querySelector(".help-link").addEventListener("click", () => showPage("check"));
  byId("history-filters").addEventListener("submit", (event) => { event.preventDefault(); page = 1; void loadHistory(); });
  byId("history-prev").addEventListener("click", () => { page -= 1; void loadHistory(); });
  byId("history-next").addEventListener("click", () => { page += 1; void loadHistory(); });
  byId("clear-history").addEventListener("click", () => {
    if (window.confirm("ล้างประวัติทั้งหมดของแอปนี้ใน Supabase หรือไม่?")) void mutateRecord(byId("clear-history"), () => api("/api/history", jsonOptions("DELETE", { confirm: "delete_all_history" })));
  });
  byId("close-history-dialog").addEventListener("click", () => dialog.close());
  byId("reuse-history").addEventListener("click", () => {
    if (!selectedRecord || busy || activeJob || ocrBusy || ocrJob) return;
    if (message.value.trim() && !window.confirm("แทนที่ข้อความฉบับร่างด้วยข้อความจากประวัติหรือไม่?")) return;
    message.value = selectedRecord.report_json.input_text;
    source = selectedRecord.source_type;
    byId("source-note").hidden = source !== "image";
    byId("source-note").textContent = "ข้อความจากภาพในประวัติ — แก้ไขได้ก่อนตรวจใหม่";
    invalidateReport();
    dialog.close();
    showPage("check");
    message.focus();
  });
  window.addEventListener("pagehide", () => { if (previewURL) URL.revokeObjectURL(previewURL); });
  void api("/api/status").then((status) => { historyConfigured = status.history_configured; syncControls(); historyControls(); }).catch(() => {});
  updateForm();
  if (ocrJob) { showTab(true); void readImage(); }
})();
