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

## 📡 API Endpoints

- `GET /` — Web Dashboard UI
- `GET /api/models` — List available LLM models from Ollama
- `GET /api/reports` — List generated reports
- `GET /generate?month=August&year=2026&model=qwen3:32b` — SSE stream for report generation
- `POST /cancel` — Cancel ongoing generation

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
