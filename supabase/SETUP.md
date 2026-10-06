# ตั้งค่าประวัติ Supabase

โค้ดประวัติพร้อมเชื่อม แต่ต้องสร้างตารางและตั้งค่าฝั่งเซิร์ฟเวอร์ก่อนใช้งานจริง หากยังไม่ตั้งค่า การตรวจข้อความ ภาพ และไฮไลต์ยังทำงานได้ ปุ่มบันทึกจะแจ้งว่าประวัติไม่พร้อม

## 1. เตรียม project และ schema

สร้าง Supabase project สำหรับแอปนี้ หรือเลือก project ที่ยังไม่มีตาราง `public.checks` ที่ใช้งานเพื่ออย่างอื่น ประวัติเป็นข้อมูลร่วมของแอป ผู้ที่เข้าถึงเว็บ localhost เดียวกันเปิดดูได้

ไฟล์ migration เริ่มต้นคือ `migrations/20261004000100_saved_checks.sql` สร้าง:

- ตาราง `public.checks` และ indexes สำหรับเวลา ระดับความเสี่ยง และรายการสำคัญ
- unique constraint บน `job_id` เพื่อป้องกันบันทึกซ้ำ
- ฟังก์ชัน `public.search_checks` สำหรับค้นหาข้อความตรงตัว รวมภาษาไทยและอักขระ `%`, `_`, `*` พร้อมแบ่งหน้า
- RLS และสิทธิ์ CRUD/ค้นหาเฉพาะ `service_role`; ถอนสิทธิ์ `anon` และ `authenticated`

สำหรับการตั้งค่าครั้งแรก เปิด SQL Editor ของ Supabase แล้วรันเนื้อหาไฟล์ migration นี้ทั้งไฟล์หนึ่งครั้ง ระบบไม่รัน migration อัตโนมัติเมื่อเปิดเว็บ หากใช้ Supabase CLI และ migration workflow อยู่แล้ว ให้นำไฟล์นี้เข้า workflow เดิมและ apply ตามปกติ ไม่รันซ้ำผ่าน SQL Editor

ถ้าขึ้นว่าตารางมีอยู่แล้ว ให้ตรวจว่าเป็นตารางของแอปนี้และ migration เคยรันแล้วหรือไม่ ห้ามลบตารางที่มีข้อมูลเพื่อแก้ปัญหาโดยไม่ตรวจสอบ

## 2. ตั้งค่า `.env`

ใน Dashboard ของ project ดู Project URL และ Secret key ที่หน้า API Keys จากนั้นเพิ่มค่าต่อไปนี้ใน `.env` ที่โฟลเดอร์โปรเจกต์:

```ini
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SECRET_KEY=sb_secret_YOUR_KEY
```

ใช้ Secret key ฝั่ง Python backend เท่านั้น ไม่ใส่ใน `web/` และไม่ส่งคีย์ในแชต ถ้ามี `.env` ที่เก็บ Gemini/VirusTotal อยู่แล้ว ให้เพิ่มสองบรรทัดนี้ลงไฟล์เดิม หากยังไม่มี ให้คัดลอก `.env.example` เป็น `.env` แล้วตั้งค่าทั้ง Gemini, VirusTotal และ Supabase

ปิดและเปิด `web_server.py` ใหม่หลังแก้ `.env` เพราะ config ถูกโหลดเมื่อเริ่มโปรแกรม

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe web_server.py
```

หรือใช้ `run_web.bat` ถ้าไม่ได้ใช้ virtual environment ให้ใช้ `python` แทน `.venv\Scripts\python.exe` หลังติดตั้ง dependencies ใน Python ที่ใช้งาน

## 3. ตรวจการเชื่อม

1. เปิดหน้าเว็บ ตรวจข้อความหนึ่งรายการ แล้วกด “บันทึกผลนี้”
2. เปิดเมนู “ประวัติ” ดูรายงาน ค้นหาข้อความ และลองทำรายการสำคัญ
3. เปิดเซิร์ฟเวอร์ใหม่แล้วยืนยันว่าประวัติยังอยู่
4. ตรวจ Dashboard ว่ามีข้อมูลเฉพาะรายการที่ผู้ใช้กดบันทึก

`history_configured` ใน `/api/status` ระบุว่ามี URL/คีย์ในการตั้งค่า ไม่ได้ยืนยันว่าตารางหรือการเชื่อมต่อพร้อม การบันทึกหรือเปิดประวัติจะตรวจการเชื่อมจริงและแจ้งข้อผิดพลาด

ข้อความและรายงานบันทึกบนคลาวด์ใน Supabase ภาพต้นฉบับไม่ถูกอัปโหลดเข้า Supabase Storage ภาพที่ใช้ OCR ส่งให้ Gemini แบบ inline เฉพาะตอนกดอ่านข้อความ

## 4. ทดสอบกับ Supabase จริง

Unit/API/browser tests ใช้ข้อมูลสังเคราะห์และ Data API transport จำลอง จึงไม่ยืนยัน SQL migration หรือสิทธิ์ของ project จริง

ใช้ project สำหรับทดสอบแยกจากข้อมูลใช้งานจริง รัน migration แล้วตั้งค่าตัวแปร environment ฝั่งเครื่อง:

```ini
SCAMCHECKER_TEST_SUPABASE_URL=https://YOUR_TEST_PROJECT.supabase.co
SCAMCHECKER_TEST_SUPABASE_SECRET_KEY=sb_secret_TEST_KEY
SCAMCHECKER_TEST_SUPABASE_PUBLISHABLE_KEY=sb_publishable_TEST_KEY
```

ทดสอบด้วย:

```powershell
.venv\Scripts\python.exe -m pytest tests/test_supabase_integration.py -q
```

การทดสอบสร้างข้อมูลสังเคราะห์ ตรวจการบันทึกซ้ำ เปิดผล ค้นหาตรงตัว ทำรายการสำคัญ และยืนยันว่า publishable key อ่านตาราง/เรียกฟังก์ชันค้นหาไม่ได้ จากนั้นลบเฉพาะรายการที่ตัวทดสอบสร้าง ไม่ล้างตารางทั้งหมด หากไม่ได้ตั้งค่า test project การทดสอบนี้จะ skip

## 5. ขอบเขตสิทธิ์รุ่นนี้

Secret key ทำงานด้วย `service_role` และข้าม RLS การเข้าถึงผ่านแอปจึงพึ่งการตรวจ Host/Origin และการเปิดเฉพาะ `127.0.0.1` ของ Python backend ประวัติยังไม่แยกตามบัญชีผู้ใช้

ก่อนเปิดให้ผู้ใช้หลายคนผ่านอินเทอร์เน็ต ต้องเพิ่ม Supabase Auth, `user_id`, การตรวจ JWT และ policy สำหรับเจ้าของข้อมูลในทุกเส้นทางประวัติ การมี Supabase อย่างเดียวไม่ได้ทำให้ข้อมูลแยกตามผู้ใช้

เอกสารอ้างอิง: [API keys](https://supabase.com/docs/guides/getting-started/api-keys), [RLS](https://supabase.com/docs/guides/database/postgres/row-level-security), [Python SDK](https://supabase.com/docs/reference/python/initializing), [Database migrations](https://supabase.com/docs/guides/deployment/database-migrations)
