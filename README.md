# 🛡️ Scam Checker AI

ระบบ AI ตรวจสอบข้อความและลิงก์สแกม/ฟิชชิ่งภาษาไทย (Backend & AI Core Engine)

---

## 📌 โครงสร้างโปรเจกต์

```
projecteiei/
├── .env                     # เก็บ API keys (ห้าม commit)
├── .env.example             # ตัวอย่างการตั้งค่า Environment
├── .gitignore               # ป้องกันไฟล์สำคัญหลุดขึ้น git
├── requirements.txt         # รายการ dependencies
├── config.py                # โหลดและตรวจสอบ API keys
├── parser.py                # ขั้นตอนที่ 1: แยกลิงก์/ข้อความ (Deobfuscation)
├── virustotal_checker.py    # ขั้นตอนที่ 2: เช็คความปลอดภัยลิงก์กับ VirusTotal API v3
├── knowledge_base/
│   ├── scam_phrases.json    # ฐานข้อมูลคำและวลีหลอกลวง 4 หมวด
│   └── kb_checker.py        # ขั้นตอนที่ 3: เทียบข้อความกับฐานข้อมูล
├── ai_analyzer.py           # ขั้นตอนที่ 4: วิเคราะห์บริบทด้วย Google Gemini (Structured Output)
├── risk_engine.py           # ขั้นตอนที่ 5: ประเมินและรวมคะแนนความเสี่ยง (Rule-based)
├── main.py                  # Entry point เชื่อมต่อ pipeline ทั้งหมด + CLI
├── run_test_cases.py        # สคริปต์รันชุดทดสอบพร้อมรายงานผล
└── tests/
    ├── test_parser.py       # Unit tests สำหรับ parser (9 เคส)
    ├── test_virustotal.py   # Unit tests สำหรับ virustotal_checker (6 เคส)
    ├── test_kb.py           # Unit tests สำหรับ kb_checker (6 เคส)
    ├── test_ai_analyzer.py  # Unit tests สำหรับ ai_analyzer (5 เคส)
    ├── test_risk_engine.py  # Unit tests สำหรับ risk_engine (5 เคส)
    ├── test_main.py         # Integration tests สำหรับ main pipeline (3 เคส)
    └── test_cases.json      # ชุดทดสอบ 8 สถานการณ์สแกมจริง
```

---

## 🚀 วิธีการใช้งาน

### 1. ติดตั้ง Dependencies
```bash
pip install -r requirements.txt
```

### 2. ตั้งค่า API Keys ใน `.env`
คัดลอกไฟล์ `.env.example` เป็น `.env` แล้วใส่คีย์:
```ini
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
```

### เปิดหน้าเว็บ (UX/UI)

รันจากโฟลเดอร์โปรเจกต์:

```bash
python web_server.py
```

เปิด <http://127.0.0.1:8000> ในเบราว์เซอร์ หรือดับเบิลคลิก `run_web.bat` บน Windows เพื่อเปิดเซิร์ฟเวอร์
หากพอร์ตถูกใช้อยู่ให้ใช้ `python web_server.py --port 8001` แล้วเปิด <http://127.0.0.1:8001>
หยุดเซิร์ฟเวอร์ด้วย `Ctrl+C` หน้าเว็บใช้ dependencies และ `.env` เดิม ไม่ต้องติดตั้ง Node.js

หน้าเว็บรองรับมือถือ มีตัวอย่างข้อความ และแสดงขั้นตอนทำงานจริง พร้อมคะแนนรวม เหตุผล/หลักฐานของ Gemini คำที่พบใน Knowledge Base และผลลิงก์จาก VirusTotal

ฟีเจอร์ที่เพิ่ม:
- **ไฮไลต์หลักฐาน** บนข้อความต้นฉบับ เลือกส่วนที่มีสีเพื่ออ่านเหตุผล เปิด/ปิดไฮไลต์ได้ ใช้ผล AI เดิมโดยไม่เรียกเพิ่ม รองรับหลักฐานซ้อนทับกันและข้อความซ้ำ
- **ภาพหน้าจอ** เลือกหรือลาก PNG/JPEG/WebP แบบภาพนิ่ง ครั้งละหนึ่งภาพ ไม่เกิน 5 MiB / 16 ล้านพิกเซล กดอ่านข้อความด้วย Gemini แล้วตรวจแก้ข้อความก่อนกดวิเคราะห์ ไม่มีการตัดข้อความที่เกิน 4,000 ตัวอักษรทิ้งอัตโนมัติ
- **ประวัติ Supabase** กดบันทึกเอง ค้นหา กรองระดับ/วันที่ ทำรายการสำคัญ เปิดรายงานฉบับที่บันทึก นำข้อความมาตรวจใหม่ และลบประวัติได้ เปิดผลเก่าโดยไม่เรียก AI/VirusTotal ซ้ำ

ประวัติต้องตั้งค่า Supabase และรัน SQL migration ก่อน ดู [คู่มือตั้งค่า Supabase](supabase/SETUP.md) หากยังไม่ตั้งค่า การตรวจข้อความ/ภาพยังใช้งานได้และหน้าเว็บแจ้งว่าประวัติไม่พร้อม

หากใช้ virtual environment ที่เตรียมไว้ รัน `.venv\Scripts\python.exe web_server.py` หรือใช้ `run_web.bat` ซึ่งเลือก `.venv` เมื่อมีอยู่ ติดตั้ง dependencies เพิ่มเติมด้วย `.venv\Scripts\python.exe -m pip install -r requirements.txt`
Knowledge Base จับวลีได้แม้เว้นวรรคต่างกัน เช่น `แจ้งรหัสOTP`, `แจ้ง รหัส OTP` หรือ `O.T.P.` รองรับอักษรแฝงและ Unicode จากการคัดลอกข้อความ และโหลดรายการใหม่เมื่อไฟล์ฐานคำเปลี่ยน
ถ้าไฟล์ฐานคำหายหรืออ่านไม่ได้ หน้าเว็บจะแจ้งว่าฐานข้อมูลไม่พร้อม แยกจากกรณีฐานข้อมูลทำงานแต่ไม่มีคำตรงกัน
ใช้ pipeline เดียวกับ CLI: เมื่อไม่พบคำในฐานข้อมูล Gemini วิเคราะห์บริบทเอง คะแนนเป็นคะแนนตามเกณฑ์ ไม่ใช่เปอร์เซ็นต์ความแม่นยำ
ตรวจได้ครั้งละ 4,000 ตัวอักษร / 3 ลิงก์ และตรวจทีละรายการเพื่อเคารพข้อจำกัด API
หากบริการไม่พร้อมจะแจ้งว่าเป็นผลบางส่วนหรือยังประเมินไม่ได้ ไม่สร้างผล AI จำลอง

เซิร์ฟเวอร์เปิดเฉพาะเครื่องนี้ (`127.0.0.1`) คีย์ API อยู่ฝั่ง Python ไม่ส่งให้เบราว์เซอร์
ข้อความและภาพที่เลือกส่งอ่านส่งให้ Gemini ลิงก์ส่งให้ VirusTotal เฉพาะเมื่อกดตรวจข้อความ ผลชั่วคราวเก็บในหน่วยความจำสูงสุด 15 นาที / 32 งาน งาน OCR และงานวิเคราะห์ใช้ช่องประมวลผลเดียวกันทีละงาน
เมื่อกด “บันทึกผลนี้” ข้อความฉบับที่ตรวจและรายงานจะเก็บใน Supabase บนคลาวด์ ไม่มีประวัติถาวรบนเครื่องและไม่เก็บภาพต้นฉบับในประวัติ ประวัติรุ่นนี้เป็นประวัติร่วมของแอป ผู้ที่เข้าถึงเว็บ local เดียวกันเปิดดูได้
Secret key ของ Supabase อยู่เฉพาะ Python backend; ยังไม่มีระบบเข้าสู่ระบบหรือแยกเจ้าของข้อมูลรายบุคคล ดูรายละเอียดสิทธิ์ในคู่มือตั้งค่า
รายงานลิงก์ใช้ cache ในหน่วยความจำของโมดูล VirusTotal เดิมตลอดอายุเซิร์ฟเวอร์
ไฟล์หน้าเว็บอยู่ใน `web/` และตัวเซิร์ฟเวอร์อยู่ใน `web_server.py`
ส่วนที่เพิ่มคือ `history_store.py`, `evidence_highlights.py`, `image_reader.py`, `ocr_analyzer.py`, `web/features.js`, `web/features.css` และ SQL ใน `supabase/migrations/`

ทดสอบฟีเจอร์ใหม่รวมกับ tests เดิมด้วย `.venv\Scripts\python.exe -m pytest tests/ -q` การทดสอบ provider ใช้ mock ส่วน `tests/test_supabase_integration.py` ใช้ Supabase test project จริงเมื่อกำหนดค่าตามคู่มือแล้ว มิฉะนั้นจะ skip

### 3. รันตรวจสอบข้อความผ่าน Command Line
```bash
python main.py "ด่วนที่สุด! คุณได้รับรางวัล 100,000 บาท กดรับที่ https://bit.ly/scam-test"
```

หรือเปิดโหมดโต้ตอบ:
```bash
python main.py
```

หากต้องการผลลัพธ์เป็น JSON:
```bash
python main.py "ข้อความที่ต้องการตรวจสอบ" --json
```

### 4. รันชุดทดสอบ Unit Tests ทั้งหมด
```bash
pytest tests/ -v
```

### 5. รันชุดทดสอบ Test Cases อัตโนมัติ
```bash
python run_test_cases.py
```

---

## 🧠 การทำงานของแต่ละโมดูล (Data Flow)

1. **Parser (`parser.py`)**:
   - ถอดรหัสพรางลิงก์ (Deobfuscate): แปลง `hxxp://` เป็น `http://`, `[.]` เป็น `.`
   - สกัด URLs ทั้งหมด (รองรับ `http`, `https`, `www.`, shorteners เช่น `bit.ly`)
   - แยกข้อความบริสุทธิ์ (`text_only`) ออกจากลิงก์

2. **VirusTotal Checker (`virustotal_checker.py`)**:
   - เชื่อมต่อกับ VirusTotal API v3
   - มี **Rate Limiting** ป้องกันเกิน 4 requests/นาที (Free Tier)
   - มี **In-memory Caching** ไม่เรียกซ้ำ URL เดิม
   - มี **Exponential Backoff Retry** หากเกิดปัญหาเครือข่าย

3. **Knowledge Base Checker (`kb_checker.py`)**:
   - ตรวจสอบคำและวลีหลอกลวง 4 หมวด:
     1. `urgency` (ความเร่งด่วน/กดดัน)
     2. `money_reward` (เงินรางวัล/เงินกู้)
     3. `personal_info` (ขอ OTP/ข้อมูลส่วนตัว)
     4. `impersonation` (แอบอ้างสถาบัน/หน่วยงาน)
   - คำนวณคะแนนตามสัดส่วนหมวดและจำนวนคำที่พบ (0-100)

4. **AI Analyzer (`ai_analyzer.py`)**:
   - ใช้โมเดล **Google Gemini** วิเคราะห์บริบทภาษาไทยเชิงลึก
   - บังคับผลลัพธ์เป็น **Structured Output** ด้วย Pydantic Schema
   - รองรับ Multi-model fallback และ Retry อัตโนมัติ

5. **Risk Engine (`risk_engine.py`)**:
   - ผสมผสานแบบ Rule-based + Weighted Scoring:
     - หากพบ URL อันตรายจาก VirusTotal → ตัดสิน **"สูง"** ทันที (Override Rule)
     - ถ่วงน้ำหนัก: VirusTotal 40% + Knowledge Base 30% + AI 30% (กรณีมีลิงก์)
     - ถ่วงน้ำหนัก: Knowledge Base 50% + AI 50% (กรณีไม่มีลิงก์)
   - ให้ผลลัพธ์: ระดับความเสี่ยง (`ต่ำ`, `ปานกลาง`, `สูง`), คะแนน (0-100), พร้อมเหตุผลอธิบายเป็นภาษาไทย


## การทำงานปกติ: ใช้ Knowledge Base และให้ Gemini วิเคราะห์เพิ่มเติม

### คะแนน AI จากหลักฐาน

Gemini ส่งระดับหลักฐาน 0–4 พร้อมข้อความอ้างอิงจริงใน 4 ด้าน: `harm`, `deception`, `pressure`, `link_risk`
โค้ดคำนวณ `ai_confidence` เอง ไม่ใช้เลขรวมที่ Gemini เสนอโดยตรง
`harm` ระดับ 0/1/2/3/4 มีคะแนนฐาน 0/18/42/68/86 ตามลำดับ
อีก 3 ด้านเพิ่มคะแนนตามระดับ: `deception` สูงสุด 6, `pressure` สูงสุด 4, `link_risk` สูงสุด 4
ผล JSON มี `risk_assessment`, `score_breakdown` และ `scoring_method` เพื่อดูที่มาของคะแนน
หลักฐานต้องมีอยู่ในข้อความจริง การอ้างว่าลิงก์ suspicious/malicious ต้องมีรายงาน VirusTotal รองรับ
Gemini เลือกรหัสส่วนข้อความจากรายการที่ระบบเตรียมไว้ แล้วระบบดึงคำต้นฉบับมาแสดงเอง เพื่อป้องกันการคัดลอกผิดหรือเรียบเรียงคำอ้างอิงใหม่
สูตรนี้เป็นเกณฑ์ประเมินทดลอง ไม่ใช่ความน่าจะเป็นที่สอบเทียบด้วยข้อมูลจริง
ข้อความที่มีหลักฐานใกล้กันอาจได้คะแนนเท่ากันได้ ไม่มีการสุ่มหรือบังคับให้ทุกข้อความได้เลขต่างกัน
การรวมความเสี่ยงยังใช้ KB และ VT แต่กฎ AI เสี่ยงสูงใช้คะแนน AI กับเกณฑ์ระดับ 65 แทนการปัดทุกกรณีเป็นขั้นต่ำ 75

คำสั่ง `python main.py` ใช้ VirusTotal + Knowledge Base + Gemini ตามปกติ
เมื่อพบคำใน KB จะส่งผลจับคู่ให้ Gemini ประกอบการวิเคราะห์และใช้การรวมคะแนนเดิม
Gemini สามารถตรวจพบรูปแบบหรือคำใหม่ที่อยู่นอก KB ได้ด้วย
ถ้า KB ไม่พบคำ จะใช้ prompt วิเคราะห์บริบทโดยตรงร่วมกับผล VirusTotal
และใช้คะแนน Gemini โดยไม่ถ่วงรวมกับ KB ที่เป็นศูนย์ กฎลิงก์อันตรายยังมีผลเหมือนเดิม
ผล JSON ระบุ `analysis_mode` เป็น `kb_assisted` หรือ `independent_ai`
หาก KB ไม่พบคำและ Gemini ไม่พร้อมใช้งาน จะรายงานว่าประเมินไม่ได้ แทนการสรุปว่าปลอดภัย

```bash
python main.py "ข้อความที่ต้องการตรวจ"
python main.py "ข้อความที่ต้องการตรวจ" --json
python run_test_cases.py
```

## ทดสอบ Gemini อย่างเดียว (ไม่ใช้ Knowledge Base)

โหมดนี้ส่งข้อความดิบตรงให้ Gemini โดยไม่เรียก Knowledge Base, VirusTotal หรือ Risk Engine
prompt ไม่มีคะแนนหรือคำที่จับคู่จาก KB และไม่มีผลตรวจลิงก์ คะแนนใช้ `ai_confidence` ตรง ๆ
แบ่งระดับเพื่อเทียบชุดตัวอย่าง: ต่ำ 0–34, ปานกลาง 35–64, สูง 65–100
การเรียก API ล้มเหลวถือเป็นข้อผิดพลาด ไม่ใช้คะแนนสำรองจาก KB
ใช้เฉพาะ `GEMINI_API_KEY` และ `GEMINI_MODEL` จาก `.env`

```bash
python run_ai_only.py "แจ้งจากธนาคาร: กรุณาส่งรหัส OTP เพื่อยืนยันบัญชี"
python run_ai_only.py
python run_ai_only.py --cases
python run_ai_only.py --cases --json
```

ผลการทดสอบ 8 ตัวอย่างเป็นการตรวจเบื้องต้น ไม่ใช่ค่าความแม่นยำของระบบในภาพรวม

## ทดสอบ Gemini + VirusTotal โดยไม่ใช้ Knowledge Base

แยก URL (รวมลิงก์พราง) และตรวจผ่าน VirusTotal ก่อนส่งผลตรวจร่วมกับข้อความให้ Gemini
ไม่โหลด Knowledge Base และไม่มีคะแนน KB ใน prompt หรือการตัดสิน
รายงาน `vt_results` แยกจาก `ai_result` โดย `ai_confidence` เป็นคะแนนประเมินของโมเดล ไม่ใช่ค่าความแม่นยำที่วัดได้
ระดับความเสี่ยงใช้เกณฑ์คะแนน AI 35/65 เดิม ถ้า VirusTotal พบ `malicious` จะตัดสินสูง
โดยไม่แก้คะแนน AI และระบุ `decision_source` ว่าใช้กฎนี้
ผล `unknown` หมายถึงยังยืนยันลิงก์ไม่ได้ ส่วน `safe` หมายถึงไม่พบการตรวจจับในรายงาน ไม่รับประกันว่าปลอดภัย
ต้องตั้ง `GEMINI_API_KEY` และ `VIRUSTOTAL_API_KEY` ใน `.env` การตรวจ URL ใหม่อาจใช้เวลาเพราะการสแกนและ rate limit

```bash
python run_gemini_vt.py "ข้อความและ https://example.com ที่ต้องการตรวจ"
python run_gemini_vt.py --cases
python run_gemini_vt.py --cases --json --output gemini_vt_results.json
```
