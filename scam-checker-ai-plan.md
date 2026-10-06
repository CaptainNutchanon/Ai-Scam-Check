# แผนงาน: ระบบ AI ตรวจสอบข้อความ/ลิงก์สแกม (เฉพาะส่วน AI — ยังไม่รวมเว็บ)

## 0. สิ่งที่ต้องเตรียมเองก่อนส่งให้ agent (agent ทำแทนไม่ได้)

- [ ] **VirusTotal API key** — สมัครที่ virustotal.com แล้วคัดลอก key มาเตรียมไว้
- [ ] **AI API key** — Claude API หรือ OpenAI API
- [ ] ตัดสินใจ: จะใช้ dataset สำเร็จรูปสำหรับ knowledge base ไหม หรือให้ agent ช่วยรวบรวม/สร้างตัวอย่างคำหลอกลวงภาษาไทยขึ้นมาเอง (แนะนำแบบหลัง เพราะ public dataset ภาษาไทยหายาก)
- [ ] เตรียมเครื่อง: Python 3.10+, pip, และ virtual environment

---

## 1. โครงสร้างโปรเจกต์

```
scam-checker-ai/
├── .env                    # เก็บ API keys (ห้าม commit)
├── .env.example            # ตัวอย่างไฟล์ .env ไม่มีค่าจริง
├── .gitignore
├── requirements.txt
├── config.py                # โหลดค่าจาก .env
├── parser.py                 # ขั้นตอนที่ 1: แยกลิงก์/ข้อความ
├── virustotal_checker.py     # ขั้นตอนที่ 2: เช็คลิงก์
├── knowledge_base/
│   ├── scam_phrases.json     # รายการคำ/วลีหลอกลวงแยกหมวด
│   └── kb_checker.py         # ขั้นตอนที่ 3: เทียบข้อความกับ KB
├── ai_analyzer.py            # ขั้นตอนที่ 4: เรียก AI API วิเคราะห์+สรุป
├── risk_engine.py            # ขั้นตอนที่ 5: รวมผล + ให้คะแนนความเสี่ยง
├── main.py                   # ฟังก์ชันหลักที่เรียกทุกขั้นตอนตามลำดับ
└── tests/
    ├── test_cases.json       # ข้อความตัวอย่าง (สแกมจริง + ปกติ) ไว้ทดสอบ
    └── test_main.py          # unit test แต่ละโมดูล
```

**เหตุผลที่แยกไฟล์แบบนี้:** แต่ละโมดูลทดสอบแยกได้ ถ้าโมดูลไหนพังไม่กระทบตัวอื่น และย้ายไปต่อเว็บทีหลังได้ทันทีโดยไม่ต้องแก้โครงสร้าง

---

## 2. รายละเอียดงานแต่ละโมดูล

### 2.1 `parser.py`
**Input:** ข้อความดิบ (string)
**Output:** `{"urls": [...], "text_only": "..."}`

- ใช้ regex จับ URL ให้ครอบคลุมทั้งแบบมี `http(s)://` และไม่มี (เช่น `bit.ly/xxx`, `www.xxx.com`)
- ดักรูปแบบพรางลิงก์เบื้องต้น เช่น `hxxp://`, `[.]` แทนจุด แล้วแปลงกลับเป็น URL ปกติก่อนส่งเช็ค
- เขียน unit test อย่างน้อย 5 เคส (ลิงก์ปกติ, หลายลิงก์ในข้อความเดียว, ไม่มีลิงก์, ลิงก์พราง, ลิงก์ปนอยู่กลางประโยค)

### 2.2 `virustotal_checker.py`
**Input:** URL เดียว
**Output:** `{"url", "malicious_count", "total_engines", "verdict"}`

- Implement ทั้ง submit URL และ retrieve report (2 endpoint ของ VT API)
- ใส่ **rate limiting** (แผนฟรี ~4 req/นาที) ด้วย `time.sleep` หรือ token bucket ง่ายๆ
- ใส่ **retry with backoff** กรณี network error/timeout (ลองใหม่ไม่เกิน 3 ครั้ง)
- ใส่ **cache** ผลลัพธ์ (dict ในหน่วยความจำพอสำหรับช่วงทดสอบ) กัน request ซ้ำ URL เดิม
- ถ้า API ล้มเหลวทุกครั้ง ต้อง return ค่า verdict = "unknown" ไม่ใช่ error ที่ทำให้โปรแกรมค้าง/พัง
- ห้าม hardcode API key ในไฟล์นี้ ต้องดึงจาก `config.py`

### 2.3 `knowledge_base/scam_phrases.json`
โครงสร้างไฟล์:
```json
{
  "urgency": ["ด่วนที่สุด", "หมดเขตวันนี้", "..."],
  "money_reward": ["คุณได้รับรางวัล", "โอนเงินมัดจำ", "..."],
  "personal_info": ["แจ้งรหัส OTP", "ยืนยันบัญชี", "..."],
  "impersonation": ["ธนาคาร...", "กรมสรรพากร...", "..."]
}
```
- ให้ agent ช่วย generate ตัวอย่างเริ่มต้นอย่างน้อยหมวดละ 15-20 วลี โดยอ้างอิงรูปแบบสแกมไทยที่พบจริง (SMS/LINE/call center)
- เก็บเป็นไฟล์แยกจากโค้ด เพื่อแก้ไข/เพิ่มทีหลังได้โดยไม่แตะโค้ด

### 2.4 `knowledge_base/kb_checker.py`
**Input:** `text_only`
**Output:** `{"matched_categories": [...], "matched_phrases": [...], "kb_score": 0-100}`

- เริ่มจาก keyword/substring matching ก่อน (ง่าย ทดสอบเร็ว)
- คำนวณ kb_score ตามสัดส่วนหมวดที่ match (เช่น match 1 หมวด = 30, 2 หมวด = 60, 3+ หมวด = 90)
- เขียนแบบ modular ให้สลับไปใช้ embedding similarity ได้ทีหลังโดยไม่ต้องแก้ interface (เผื่ออนาคต)

### 2.5 `ai_analyzer.py`
**Input:** ข้อความเต็ม + ผลจาก VT + ผลจาก KB
**Output:** `{"ai_summary": "...", "ai_confidence": 0-100}`

- เขียน prompt ที่ **บังคับให้ AI ตอบกลับเป็น JSON เท่านั้น** ระบุ schema ชัดเจนใน prompt กัน AI ตอบมั่ว
- ส่ง context ทั้งหมด (ผล VT, ผล KB) เข้าไปใน prompt ด้วย ไม่ใช่ให้ AI เดาเอง
- ใส่ try/except รอบการ parse JSON จาก AI response กันแตก ถ้า parse ไม่ได้ ให้ fallback เป็นค่า default พร้อม log error
- จัดการ rate limit/error ของ AI API เหมือนข้อ 2.2

### 2.6 `risk_engine.py`
**Input:** ผลจาก VT, KB, AI
**Output:** `{"risk_level": "ต่ำ/ปานกลาง/สูง", "risk_score": 0-100, "reasons": [...]}`

ใช้ **rule-based** ชัดเจน อธิบายได้ (ไม่ใช่ black box) เช่น:
- ถ้า VT verdict = malicious → risk_level = สูง ทันที (VT ให้น้ำหนักสูงสุดเพราะยืนยันจากข้อมูลจริง)
- ถ้า VT = safe/unknown แต่ kb_score สูง (>60) → risk_level = สูง
- ถ้า VT = safe และ kb_score ปานกลาง (30-60) → risk_level = ปานกลาง
- อื่นๆ → ต่ำ

ระบุ logic นี้เป็น comment ในโค้ดชัดเจน เพราะต้องใช้อธิบายตอน present งาน

### 2.7 `main.py`
รวมทุกโมดูลเป็นฟังก์ชันเดียว:
```python
def check_message(text: str) -> dict:
    parsed = parse(text)
    vt_results = [check_virustotal(u) for u in parsed["urls"]]
    kb_result = check_kb(parsed["text_only"])
    ai_result = analyze_with_ai(text, vt_results, kb_result)
    final = combine_risk(vt_results, kb_result, ai_result)
    return final
```

---

## 3. การทดสอบ

ต้องสร้าง `tests/test_cases.json` ครอบคลุม:
- ข้อความสแกมชัดเจน (มีลิงก์อันตราย + คำหลอกลวง)
- ข้อความสแกมแบบแนบเนียน (ไม่มีคำต้องสงสัยตรงๆ)
- ข้อความปกติที่มีคำใกล้เคียง (เช่น "โอนเงิน" ในบริบทปกติ) — กันระบบ false positive
- ข้อความที่มีลิงก์ปลอดภัยจริง (เช่นเว็บธนาคารจริง)
- ข้อความไม่มีลิงก์เลย

แล้วรัน `main.py` กับทุกเคส ตรวจว่า risk_level ออกมาสมเหตุสมผล

---

## 4. ลำดับที่ให้ agent ลงมือทำ (ห้ามข้ามลำดับ)

1. สร้างโครงโปรเจกต์ + `requirements.txt` + `.env.example`
2. เขียน `parser.py` + test ให้ผ่านก่อน
3. เขียน `virustotal_checker.py` + ทดสอบด้วย URL จริง 2-3 อัน (1 อันตราย, 1 ปลอดภัย)
4. สร้าง `scam_phrases.json` + `kb_checker.py` + ทดสอบ
5. เขียน `ai_analyzer.py` + ทดสอบ prompt ว่าได้ JSON กลับมาจริง
6. เขียน `risk_engine.py` รวมผลทั้งหมด
7. เขียน `main.py` เชื่อมทุกอย่าง
8. รันชุดทดสอบทั้งหมดใน `tests/` แล้วรายงานผล

---

## 5. สิ่งที่ต้องกำชับ agent เป็นพิเศษ

- **ห้ามใส่ API key ในโค้ดตรงๆ** ต้องใช้ `.env` เท่านั้น และต้องสร้าง `.gitignore` กัน `.env` หลุดขึ้น git
- ทุกฟังก์ชันที่เรียก API ภายนอก (VT, AI) ต้องมี error handling ครบ ห้าม assume ว่า API จะตอบสำเร็จเสมอ
- โค้ดต้องมี docstring/comment อธิบายว่าแต่ละฟังก์ชันทำอะไร (จำเป็นตอนอธิบายโปรเจกต์)
- ให้ agent สรุปผลตอนจบเป็นรายงานสั้นๆ ว่าไฟล์ไหนทำอะไร ทดสอบผ่านกี่เคสจากทั้งหมด
