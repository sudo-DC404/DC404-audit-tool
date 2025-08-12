# DC404-audit-tool
**DC404 Audit Tool** is an ethical web vulnerability and information leak scanner with a GUI.   It is intended for **authorized penetration testing only** and should never be used without explicit permission from the target owner.
<img width="1920" height="1080" alt="audittool" src="https://github.com/user-attachments/assets/6e502dc9-4f60-4786-84bf-44379b23f12d" />

<img width="1920" height="899" alt="test2" src="https://github.com/user-attachments/assets/56df8b79-0f19-411a-910e-ad0c738c4b76" />






## ✨ Features
- Full website crawling & sitemap parsing
- YARA rules support
- Same-origin asset scanning
- **Credential leak detection**
- **Username/Password pair detection**
- PII scanning
- Export to HTML, JSON, or PDF
- GUI toggles for scanning options

## 📦 Requirements
- Python 3.9+
- PySide6
- requests
- beautifulsoup4
- html5lib
- pdfkit (requires wkhtmltopdf installed)
- yara-python

Install dependencies:
```bash
pip install -r requirements.txt

 Usage

python3 audit.py

    Set your target in the GUI.

    Use Scanning settings to enable/disable:

        Include full credentials in report

        Scan for username/password pairs

⚠️ Disclaimer

This tool is for ethical security testing only.
Unauthorized scanning is illegal and may result in criminal charges.

