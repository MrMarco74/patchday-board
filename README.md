# 🛡️ Patchday Board

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Language](https://img.shields.io/badge/language-HTML-informational.svg) ![AI generated](https://img.shields.io/badge/AI-generated-8A2BE2.svg)

> **Automated Monthly Security & Patch Tuesday Intelligence Report Generator powered by LLMs.**

`patchday-board` fetches monthly Patch Tuesday security advisories directly from official vendor APIs (**Microsoft MSRC CVRF v3.0** & **Red Hat Security Data API**), prioritizes CVEs according to **SSVC (Stakeholder-Specific Vulnerability Categorization)**, and utilizes Large Language Models (via **Ollama** or OpenAI-compatible endpoints) to generate executive security summaries in **HTML, Markdown, PDF, and XLSX** formats.

---

## ✨ Features

- **Direct Vendor API Ingestion**: Fetches CVRF/CSAF advisories directly from Microsoft MSRC & Red Hat APIs without third-party database dependencies.
- **SSVC Risk Categorization**: Automatically tags vulnerabilities (`Act`, `Attend`, `Track*`, `Track`) based on active exploitation, RCE attack vectors, and CVSS scores.
- **LLM-Powered Summaries**: Generates executive summaries grouped by enterprise product stacks (Windows Server, Client, Red Hat Linux, Exchange/SharePoint, Microsoft 365, Developer Runtimes, SQL Server).
- **Multi-Format Export**: Generates `.html`, `.md`, `.eml`, and multi-sheet `.xlsx` workbooks.
- **Modern Web Interface**: Responsive Cyberpunk / Glassmorphism UI with real-time SSE progress tracking.
- **Docker & Container Ready**: Quick setup using Docker & `docker-compose`.

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.10+
- An [Ollama](https://ollama.com) instance running locally or remotely (e.g. `ollama pull qwen3:32b` or `ollama pull llama3:70b`).

### 2. Local Setup

```bash
# Clone repository
git clone https://github.com/MrMarco74/patchday-board.git
cd patchday-board

# Create virtual environment & install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start backend
python patchday_backend.py
```

Open your browser at `http://localhost:5099`.

---

## 🐳 Docker Setup

```bash
docker compose up -d
```

Access the UI at `http://localhost:5099`.

---

## ⚙️ Configuration (`.env`)

Copy `.env.example` to `.env` to customize settings:

```env
# Ollama Endpoint
OLLAMA_URL=http://localhost:11434

# Server Port
LISTEN_PORT=5099

# Optional SearXNG Integration
SEARXNG_URL=

# E-Mail Notifications
REPORT_FROM=patchday-report@example.com
REPORT_TO=security@example.com
```

---

## 📐 SSVC Rating

How a finding gets its Act / Attend / Track\* / Track level — which feed
fields feed in, the exact decision function, and what the heuristic
deliberately does not model — is documented in
**[`docs/SSVC.md`](docs/SSVC.md)**.

`ssvc_doku.html` is generated from it and published next to each report, so
the legend in the report header links straight to the explanation:

```bash
python3 scripts/build_ssvc_doc.py
```

Edit the Markdown, not the HTML.

---

## 🗂️ Product Inventory (`groups.json`)

Which products the report covers is configuration, not code. Copy the
committed example and edit your copy — `groups.json` is gitignored, so your
estate never lands in the repository:

```bash
cp groups.example.json groups.json
```

Without a `groups.json`, the example is used as-is.

Each entry under `product_groups` becomes one section of the report:

```jsonc
{
  "name": "Windows Client",
  "versions": "Windows 11 24H2, 25H2 (x64)",   // shown in the section header
  "cp_source": "msrc",                          // msrc | rhel
  "keywords": ["windows shell", "windows 11"],  // matched against the CVE title
  "excludes": ["windows server"],
  "product_filter": [                           // optional, see below
    "windows 11 version 24h2 for x64",
    "windows 11 version 25h2 for x64"
  ]
}
```

**`keywords` decide the section, `product_filter` decides the version.** A CVE
title names the component ("Windows Hyper-V", "Microsoft Word"), never the
build — so restricting a group to specific releases needs the vendor's product
list, which is what `product_filter` matches against, case-insensitively and as
a substring. MSRC product names read `Windows 11 Version 24H2 for x64-based
Systems`; Red Hat versions are derived from the `.elN` suffix of the package
NVRs.

Findings that carry **no** product data are kept regardless. At Red Hat that is
most of them, and in a security report an uncertain inclusion beats a silent
loss.

**`retired_platforms`** applies across every group:

```json
"retired_platforms": ["windows server 2012", "windows 10", "rhel 7"]
```

Those entries disappear from every "affected" line, and a CVE that affects
*only* such platforms never enters the report. A CVE that also affects a
supported platform is kept in full. Use this rather than adding a
`product_filter` to the catch-all group — that group is the last stop for
anything unmatched, so filtering it would drop CVEs from the report entirely.

---

## 📡 API Endpoints

- `GET /` — Web Dashboard UI
- `GET /api/models` — List available LLM models from Ollama
- `GET /api/reports` — List generated reports
- `GET /generate?month=August&year=2026&model=qwen3:32b` — SSE stream for report generation
- `POST /cancel` — Cancel ongoing generation

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
