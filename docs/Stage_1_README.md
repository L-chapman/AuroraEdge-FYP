# Stage 1 — DNS Scanner Skeleton (Granny pace)

Checks **SPF, MX, DMARC** for one or more domains and writes results to `reports/`.

## 1) Install dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 2) Run a single domain
```powershell
.\scripts\run.ps1 --domain example.com
```

## 3) Run a list of domains
Create `domains.txt` with one domain per line, then:
```powershell
@"
example.com
openai.com
bbc.co.uk
"@ | Set-Content .\domains.txt -Encoding UTF8

.\scripts\run.ps1 --domains .\domains.txt
```

Notes:
- DNS timeouts are ~3s per query.
- SPF lookup count is **approximate** in Stage 1; will be refined in Stage 2.
