"use strict";

const byId = (id) => document.getElementById(id);
const form = byId("check-form");
const message = byId("message");
const submitButton = byId("submit-button");
const examples = {
  otp: "เจ้าหน้าที่ธนาคารแจ้งว่าบัญชีของคุณถูกระงับ กรุณาส่งรหัส OTP ที่ได้รับมาให้เจ้าหน้าที่ภายใน 5 นาที เพื่อปลดล็อกบัญชี",
  reward: "คุณได้รับรางวัล 50,000 บาท กรุณาโอนค่าธรรมเนียม 500 บาทก่อนรับรางวัลภายในวันนี้ มิฉะนั้นจะถูกตัดสิทธิ์",
  normal: "พรุ่งนี้เจอกันที่ร้านกาแฟตอนสิบโมงนะ ถ้ามาถึงแล้วโทรบอกด้วย",
};
const stages = {
  parsing: [8, "กำลังอ่านข้อความ", "แยกเนื้อหาและค้นหาลิงก์ในข้อความ"],
  links: [25, "กำลังตรวจลิงก์กับ VirusTotal", "ค้นหารายงานความปลอดภัย ลิงก์ใหม่อาจต้องส่งสแกนและรอผล"],
  knowledge_base: [48, "กำลังเทียบ Knowledge Base", "ค้นหาคำและวลีที่ตรงกับฐานข้อมูล"],
  ai: [70, "Gemini กำลังวิเคราะห์บริบท", "ประเมินพฤติกรรมและเลือกหลักฐานจากข้อความต้นฉบับ"],
  scoring: [94, "กำลังสรุปคะแนนและหลักฐาน", "รวมผลวิเคราะห์ข้อความกับผลตรวจลิงก์"],
};
const factorLabels = {
  harm: "การขอข้อมูล / เงิน / การข่มขู่",
  deception: "การหลอกอ้าง",
  pressure: "การกดดัน",
  link_risk: "ลิงก์น่าสงสัย",
};
const factorMax = { harm: 86, deception: 6, pressure: 4, link_risk: 4 };
let busy = false;
let activeJob = null;
try {
  const saved = sessionStorage.getItem("scamchecker-active-job");
  if (saved && /^[A-Za-z0-9_-]{32}$/.test(saved)) activeJob = saved;
} catch { /* Browsers may disable session storage. */ }
let lastStage = null;
let currentReport = null;

function rememberJob() {
  // Only a temporary job reference, never an SMS/history, is stored in the tab.
  try {
    if (activeJob) sessionStorage.setItem("scamchecker-active-job", activeJob);
    else sessionStorage.removeItem("scamchecker-active-job");
  } catch { /* The normal in-memory flow still works. */ }
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function updateForm() {
  const length = Array.from(message.value).length;
  message.setCustomValidity(length > 4000 ? "ข้อความเกิน 4,000 ตัวอักษร กรุณาแก้ไขหรือแบ่งข้อความก่อนตรวจ" : "");
  byId("char-count").textContent = `${length.toLocaleString("en-US")} / 4,000`;
  const locked = busy || Boolean(activeJob) || Boolean(window.ScamFeatures?.ocrLocked());
  message.disabled = locked;
  byId("clear-button").disabled = locked || !message.value;
  document.querySelectorAll(".example-button").forEach((button) => { button.disabled = locked; });
  submitButton.disabled = busy || Boolean(window.ScamFeatures?.ocrLocked());
  submitButton.querySelector("span").textContent = busy ? "กำลังตรวจสอบ..." : activeJob ? "ติดตามผลอีกครั้ง" : "ตรวจสอบข้อความ";
  window.ScamFeatures?.syncControls();
}

function setBusy(value) {
  busy = value;
  byId("result-region").setAttribute("aria-busy", String(value));
  updateForm();
}

function showState(id) {
  for (const state of ["empty-state", "loading-state", "error-state", "report"]) {
    byId(state).hidden = state !== id;
  }
  syncScamNotice();
}

function syncScamNotice() {
  const notice = byId("scam-notice");
  const level = currentReport?.risk?.risk_level;
  const matchesDraft = currentReport?.input_text?.trim() === message.value.trim();
  const visible = !byId("check-workspace").hidden && !byId("report").hidden && matchesDraft
    && (level === "สูง" || level === "ปานกลาง");
  if (!visible) {
    notice.hidden = true;
    return;
  }
  const high = level === "สูง";
  notice.className = `scam-notice ${high ? "high" : "medium"}`;
  byId("scam-notice-title").textContent = high
    ? "ข้อความนี้มีความเสี่ยงสูงที่จะเป็น Scam"
    : "ข้อความนี้มีสัญญาณน่าสงสัย — อาจเป็น Scam";
  byId("scam-notice-detail").textContent = high
    ? "หยุดก่อนคลิกลิงก์ โอนเงิน หรือส่งรหัส OTP ตรวจสอบผู้ส่งผ่านช่องทางที่คุณรู้จัก"
    : "ตรวจสอบตัวตนผู้ส่งและรายละเอียดให้แน่ใจก่อนคลิกลิงก์หรือทำรายการ";
  notice.hidden = false;
}

function updateStage(stage) {
  const info = stages[stage] || stages.parsing;
  if (lastStage === stage) return;
  lastStage = stage;
  byId("loading-progress").value = info[0];
  byId("loading-title").textContent = info[1];
  byId("loading-detail").textContent = info[2];
  const stageOrder = ["links", "knowledge_base", "ai", "scoring"];
  const index = stageOrder.indexOf(stage);
  document.querySelectorAll(".stage-list li").forEach((li, i) => {
    li.className = i < index ? "done" : i === index ? "current" : "";
    li.querySelector("span").textContent = i < index ? "✓" : String(i + 1);
  });
}

function showError(text) {
  byId("error-message").textContent = text;
  byId("retry-button").firstChild.textContent = activeJob ? "ติดตามผลอีกครั้ง " : "ลองอีกครั้ง ";
  showState("error-state");
}

async function api(path, options) {
  let response;
  try {
    response = await fetch(path, { ...options, signal: AbortSignal.timeout(15000) });
  } catch {
    const error = new Error("เชื่อมต่อเว็บไม่ได้ ตรวจว่าเซิร์ฟเวอร์ยังเปิดอยู่ แล้วลองติดตามผลอีกครั้ง");
    error.network = true;
    throw error;
  }
  let body;
  try { body = await response.json(); }
  catch { throw new Error("ได้รับข้อมูลไม่สมบูรณ์ กรุณาลองอีกครั้ง"); }
  if (!response.ok) {
    const error = new Error(body.error || "ตรวจสอบไม่สำเร็จ กรุณาลองใหม่");
    error.status = response.status;
    throw error;
  }
  return body;
}

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function pollJob() {
  let connectionFailures = 0;
  while (activeJob) {
    let job;
    try {
      job = await api(`/api/jobs/${encodeURIComponent(activeJob)}`);
      connectionFailures = 0;
    } catch (error) {
      if (error.network && ++connectionFailures <= 3) {
        byId("loading-detail").textContent = "การเชื่อมต่อสะดุด กำลังติดตามผลเดิมให้อีกครั้ง...";
        await pause(1500);
        continue;
      }
      if (error.status === 404) { activeJob = null; rememberJob(); }
      throw error;
    }
    if (job.status === "done") {
      activeJob = null;
      rememberJob();
      if (!message.value) {
        message.value = job.result.input_text;
        window.ScamFeatures?.restoreSource(job.result.metadata?.source_type);
      }
      currentReport = job.result;
      renderReport(job.result);
      return job.result;
    }
    if (job.status === "error") {
      activeJob = null;
      rememberJob();
      throw new Error(job.error || "ตรวจสอบไม่สำเร็จ กรุณาลองใหม่อีกครั้ง");
    }
    document.querySelector('.stage-list li[data-stage="links"]').lastChild.textContent = job.url_count ? "ตรวจลิงก์" : "ไม่พบลิงก์";
    updateStage(job.stage);
    await pause(1000);
  }
}

async function analyze(override) {
  if (window.ScamFeatures?.ocrLocked()) throw new Error("กรุณารอหรือกลับไปติดตามงานอ่านภาพให้เสร็จก่อน");
  if (busy) throw new Error("กำลังตรวจสอบข้อความอยู่ กรุณารอผล");
  if (override !== undefined) {
    if (activeJob) throw new Error("มีรายการที่ยังรอผลอยู่ กรุณาติดตามผลเดิมก่อน");
    if (typeof override !== "string" || !override.trim() || Array.from(override).length > 4000) {
      throw new Error("ใส่ข้อความ 1–4,000 ตัวอักษร");
    }
    message.value = override;
    window.ScamFeatures?.resetSource();
  }
  updateForm();
  if (!activeJob && !form.reportValidity()) return;
  lastStage = null;
  currentReport = null;
  setBusy(true);
  showState("loading-state");
  updateStage("parsing");
  if (window.matchMedia("(max-width: 760px)").matches) {
    byId("result-region").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  try {
    if (!activeJob) {
      const submitted = await api("/api/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message: message.value.trim(), source_type: window.ScamFeatures?.sourceType() || "text" }) });
      activeJob = submitted.job_id;
      rememberJob();
    }
    return await pollJob();
  } catch (error) {
    showError(error.message || "ตรวจสอบไม่สำเร็จ กรุณาลองใหม่");
    throw error;
  } finally {
    setBusy(false);
  }
}

function renderReport(result) {
  const risk = result.risk;
  const ai = result.ai_result;
  const kb = result.kb_result;
  const aiAvailable = ai.analysis_status !== "unavailable";
  const kbAvailable = kb.kb_status !== "unavailable";
  const low = risk.risk_level === "ต่ำ";
  const level = risk.risk_level === "สูง" ? "high" : risk.risk_level === "ปานกลาง" ? "medium" : low ? "low" : "unknown";
  const titles = { high: "มีสัญญาณเสี่ยงสูง", medium: "ควรตรวจสอบเพิ่มเติม", low: "ยังไม่พบสัญญาณเด่นชัด", unknown: "ข้อมูลยังไม่เพียงพอ" };
  const advice = {
    high: "หยุดก่อนคลิก ส่งรหัส หรือโอนเงิน ติดต่อผู้ส่งผ่านช่องทางที่คุณยืนยันได้ก่อนทำรายการ",
    medium: "ตรวจสอบตัวตนผู้ส่งและรายละเอียดผ่านช่องทางที่คุณรู้จัก ก่อนเปิดลิงก์หรือทำรายการ",
    low: "จากข้อมูลที่มี ความเสี่ยงอยู่ในระดับต่ำ หากผู้ส่งไม่คุ้นเคย ควรยืนยันตัวตนก่อนทำรายการ",
    unknown: "ยังสรุปความเสี่ยงไม่ได้ กรุณาตรวจสอบผู้ส่งและลองตรวจอีกครั้งเมื่อบริการพร้อม",
  };
  byId("risk-card").className = `risk-card ${level}`;
  byId("risk-badge").textContent = level === "unknown" ? "ยังประเมินไม่ได้" : `ความเสี่ยง${risk.risk_level}`;
  byId("risk-title").textContent = titles[level];
  byId("risk-score").textContent = risk.risk_score ?? "—";
  byId("risk-meter").value = risk.risk_score ?? 0;
  byId("risk-meter").hidden = risk.risk_score === null;
  document.querySelector(".scale-labels").hidden = risk.risk_score === null;
  byId("scam-type").textContent = low ? "ประเมินจากข้อความและผลตรวจที่มี" : risk.scam_type;
  byId("risk-advice").textContent = advice[level];
  const warning = byId("partial-warning");
  const incompleteLinks = (result.vt_results || []).some((row) => row.verdict === "unknown");
  warning.hidden = aiAvailable && !incompleteLinks && kbAvailable;
  warning.textContent = !aiAvailable
    ? "Gemini ไม่พร้อมใช้งาน ผลนี้ใช้เฉพาะฐานข้อมูลและผลลิงก์ที่มี ไม่ใช่ผลวิเคราะห์จาก AI"
    : "ผลตรวจลิงก์บางรายการยังไม่พร้อม จึงยังยืนยันความปลอดภัยของลิงก์เหล่านั้นไม่ได้";
  if (!kbAvailable) warning.textContent = `${aiAvailable && !incompleteLinks ? "" : warning.textContent + " "}โหลด Knowledge Base ไม่สำเร็จ ผลนี้ไม่มีข้อมูลจากฐานคำประกอบ`;
  byId("ai-score").textContent = aiAvailable ? `AI ${ai.ai_confidence} / 100` : "AI ไม่พร้อมใช้งาน";
  byId("ai-summary").textContent = ai.ai_summary;

  const evidenceList = byId("evidence-list");
  evidenceList.replaceChildren();
  byId("evidence-details").hidden = !aiAvailable || !ai.risk_assessment;
  byId("evidence-details").open = false;
  if (aiAvailable && ai.risk_assessment) {
    for (const [name, label] of Object.entries(factorLabels)) {
      const factor = ai.risk_assessment[name];
      if (!factor) continue;
      const section = element("div", "evidence-item");
      const heading = element("div", "evidence-heading");
      heading.append(element("strong", "", label), element("span", "", `${ai.score_breakdown?.[name] ?? 0} / ${factorMax[name]} คะแนน`));
      section.append(heading, element("div", "evidence-level", `ระดับหลักฐาน ${factor.level} / 4`), element("p", "", factor.reason));
      for (const quote of factor.evidence || []) section.append(element("blockquote", "", quote));
      evidenceList.append(section);
    }
  }
  const reasons = byId("risk-reasons");
  reasons.replaceChildren(...(risk.reasons || []).map((reason) => element("li", "", reason)));
  byId("kb-score").textContent = kbAvailable ? `${kb.kb_score} / 100` : "ฐานข้อมูลไม่พร้อม";
  byId("kb-summary").textContent = !kbAvailable
    ? "โหลดฐานข้อมูลคำไม่สำเร็จ กรุณาตรวจไฟล์ knowledge_base/scam_phrases.json แล้วตรวจใหม่"
    : result.analysis_mode === "independent_ai"
    ? aiAvailable
      ? "ไม่พบคำตรงกับฐานข้อมูล ให้ Gemini วิเคราะห์บริบทเองร่วมกับผลลิงก์ คะแนน KB ที่เป็นศูนย์ไม่ได้แปลว่าปลอดภัย"
      : "ไม่พบคำตรงกับฐานข้อมูล และ Gemini ยังไม่พร้อม จึงยังไม่มีผลวิเคราะห์บริบทจาก AI"
    : `พบคำหรือวลีที่ตรงกับฐานข้อมูล ${kb.matched_phrases.length} รายการ ใช้ประกอบการวิเคราะห์บริบท การพบคำไม่ได้แปลว่าเป็นสแกมทันที`;
  byId("kb-phrases").replaceChildren(...(kb.matched_phrases || []).map((phrase) => element("span", "phrase", phrase)));

  const urls = result.vt_results || [];
  byId("url-count").textContent = `${urls.length} ลิงก์`;
  const urlResults = byId("url-results");
  urlResults.replaceChildren();
  if (!urls.length) urlResults.append(element("p", "no-links", "ไม่พบลิงก์ที่ระบบรองรับ จึงไม่ได้เรียกตรวจ VirusTotal"));
  for (const row of urls) {
    const section = element("div", "url-item");
    const status = element("div", "url-status");
    const verdictLabels = { malicious: "ลิงก์นี้มีความเสี่ยงสูง", suspicious: "ลิงก์นี้อาจไม่ปลอดภัย", safe: "ยังไม่พบคำเตือนว่าลิงก์อันตราย", unknown: "ยังไม่มีผลตรวจที่ยืนยันได้" };
    const verdict = ["malicious", "suspicious", "safe", "unknown"].includes(row.verdict) ? row.verdict : "unknown";
    status.append(element("span", `url-verdict ${verdict}`, verdictLabels[verdict]));
    let explanation = "ยังไม่มีรายงานการตรวจลิงก์";
    if (row.total_engines > 0) {
      explanation = row.malicious_count > 0
        ? `ตรวจด้วยโปรแกรมความปลอดภัย ${row.total_engines} ตัว มี ${row.malicious_count} ตัวเตือนว่าลิงก์นี้อาจอันตราย`
        : `ตรวจด้วยโปรแกรมความปลอดภัย ${row.total_engines} ตัว ยังไม่มีตัวใดแจ้งเตือนว่าอันตราย`;
    }
    // Suspicious URLs stay plain text; clicking the report never opens them.
    section.append(status, element("p", "url-check-explanation", explanation), element("code", "", row.url));
    let note = "ผลจาก VirusTotal เป็นข้อมูลประกอบ ควรพิจารณาบริบทของข้อความร่วมด้วย";
    if (verdict === "suspicious") note = "ยังไม่ยืนยันว่าเป็นลิงก์หลอกลวง ควรตรวจสอบผู้ส่งก่อนเปิดลิงก์";
    if (verdict === "malicious") note = "มีระบบตรวจลิงก์แจ้งเตือนว่าเสี่ยง ควรหลีกเลี่ยงการเปิดลิงก์และตรวจสอบกับผู้ส่งก่อน";
    if (verdict === "safe") note = "ระบบตรวจลิงก์ยังไม่แจ้งเตือน แต่ไม่ได้รับประกันว่าปลอดภัย";
    if (verdict === "unknown") note = row.error ? "ตรวจลิงก์ไม่สำเร็จ อาจเกิดจากการเชื่อมต่อหรือข้อจำกัดของ API" : row.scan_submitted ? "ส่งลิงก์สแกนแล้ว แต่รายงานยังไม่พร้อม ลองตรวจอีกครั้งภายหลัง" : "ยังไม่มีข้อมูลเพียงพอ ผลนี้ไม่ได้หมายถึงลิงก์ปลอดภัย";
    section.append(element("p", "url-note", note));
    urlResults.append(section);
  }
  byId("report-time").textContent = result.metadata?.analyzed_at ? `ตรวจสอบเมื่อ ${new Intl.DateTimeFormat("th-TH", { hour: "2-digit", minute: "2-digit", day: "numeric", month: "short", year: "numeric" }).format(new Date(result.metadata.analyzed_at))}` : "รายงานเดิมไม่มีข้อมูลเวลาตรวจ";
  window.ScamFeatures?.onReport(result);
  showState("report");
  byId("risk-title").focus({ preventScroll: true });
}

form.addEventListener("submit", (event) => { event.preventDefault(); void analyze().catch(() => {}); });
message.addEventListener("input", updateForm);
message.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") { event.preventDefault(); form.requestSubmit(); }
});
byId("clear-button").addEventListener("click", () => {
  message.value = "";
  currentReport = null;
  showState("empty-state");
  updateForm();
  message.focus();
});
document.querySelectorAll(".example-button").forEach((button) => {
  button.addEventListener("click", () => {
    message.value = examples[button.dataset.example];
    currentReport = null;
    showState("empty-state");
    updateForm();
    message.focus();
  });
});
byId("retry-button").addEventListener("click", () => { void analyze().catch(() => {}); });

async function checkConnection() {
  const badge = byId("connection-status");
  try {
    const status = await api("/api/status");
    badge.classList.toggle("unavailable", !status.gemini || !status.virustotal || status.knowledge_base === false);
    badge.lastElementChild.textContent = !status.gemini ? "ยังไม่ได้ตั้งค่า Gemini" : status.knowledge_base === false ? "Knowledge Base ยังไม่พร้อม" : !status.virustotal ? "VirusTotal ยังไม่พร้อม" : "พร้อมตรวจสอบ";
  } catch {
    badge.classList.add("unavailable");
    badge.lastElementChild.textContent = "เชื่อมต่อไม่ได้";
  }
}

// Optional browser agent capability uses the same validated form/API as people.
const modelContext = document.modelContext;
if (modelContext?.registerTool) {
  const lifecycle = new AbortController();
  void Promise.resolve(modelContext.registerTool({
    name: "check_suspicious_message",
    title: "ตรวจข้อความน่าสงสัย",
    description: "Analyze a Thai SMS or message with Gemini, the existing knowledge base and VirusTotal. Sends message text to Gemini and extracted URLs to VirusTotal. Returns the actual risk report and evidence.",
    inputSchema: { type: "object", properties: { message: { type: "string", minLength: 1, maxLength: 4000 } }, required: ["message"], additionalProperties: false },
    annotations: { readOnlyHint: false, untrustedContentHint: true },
    execute: async (input) => {
      if (!input || typeof input !== "object" || typeof input.message !== "string") throw new Error("message is required");
      return await analyze(input.message);
    },
  }, { signal: lifecycle.signal })).catch(() => {});
  window.addEventListener("pagehide", () => lifecycle.abort(), { once: true });
}

updateForm();
void checkConnection();
if (activeJob) void analyze().catch(() => {});
