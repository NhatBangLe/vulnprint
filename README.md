# 📑 Vulnprint

**Vulnprint** is an open-source tool for parsing vulnerability metadata and building reproducible penetration testing lab environments. 

It connects to a live Metasploit RPC daemon (`msfrpcd`), extracts module details and documentation, uses a Language Model (LLM) to convert unstructured descriptions into structured target software configurations, stores records in a local SQLite database, and generates Markdown lab blueprint manuals.

---

## 🔬 Paper & Evaluation Reproduction

This project is the implementation accompanying our paper:
> **"Vulnprint: Automated Lab Blueprint Generation with LLM Agents for Exploit Reproduction from Metasploit Modules"**

### Reproducing the Evaluation

The benchmark dataset evaluated in the paper is stored in [`evaluation_data/msf_paths.json`](evaluation_data/msf_paths.json), which contains the list of Metasploit module paths evaluated in the study.

To reproduce the evaluation pipeline:

1. **Start Metasploit RPC Daemon**:
   Ensure `msfrpcd` is running (see [Installation & Setup](#-installation--setup) for setup details):
   ```bash
   msfrpcd -f -P <your_rpc_password>
   ```

2. **Run Vulnprint Evaluation Batch**:
   Execute `search` using the `-f` flag pointing to `evaluation_data/msf_paths.json`:
   ```bash
   python src/main.py search -f evaluation_data/msf_paths.json
   ```
   This processes all benchmark modules through Vulnprint's extraction and blueprint generation pipeline.

3. **Verify Results**:
   View database analytics:
   ```bash
   python src/main.py db analytics
   ```

---

## 🎯 Overview & Problem Solved

- **The Problem:** Setting up vulnerable test environments manually requires reading unstructured write-ups, identifying specific software versions, and guessing required configuration settings.
- **The Solution:** Vulnprint automates the extraction of target software parameters, vulnerable versions, and setup steps from Metasploit modules. It standardizes target specifications, reuses common OS/software setup guidelines, and outputs Markdown manuals for building lab VMs.

---

## 🛠️ Architecture & Tech Stack

Vulnprint runs locally and can operate with local LLM servers (such as Ollama) or OpenAI-compatible cloud APIs. It also supports Model Context Protocol (MCP) servers for fetching external search context during guideline generation.

```
[CLI Command]
      │
      ▼
┌───────────────┐        MSF RPC        ┌─────────────────┐
│ Vulnprint Core│ ────────────────────> │  msfrpcd Daemon │
└───────────────┘                       └─────────────────┘
      │
      ├───────────────────┬───────────────────┐
      ▼ (JSON Specs)      ▼ (Tools via MCP)   ▼ (Persist Records)
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  LLM Endpoint │   │  MCP Server   │   │SQLite Database│
│(Ollama/OpenAI)│   │ (Search Tool) │   │ (lab_hub.db)  │
└───────────────┘   └───────────────┘   └───────────────┘
      │
      ▼
┌───────────────┐
│ Lab Blueprints│
│  & MD Reports │
└───────────────┘
```

- **Runtime:** Python 3.10+
- **Module Source:** Metasploit Framework RPC daemon (`msfrpcd`) via `pymetasploit3`
- **LLM Interface:** OpenAI Python SDK / LangChain (compatible with Ollama, OpenRouter, or OpenAI endpoints)
- **Tool Integration:** Model Context Protocol (MCP) via `langchain-mcp-adapters`
- **Database:** SQLite (`sqlite3`)
- **CLI Framework:** Python standard `argparse`

---

## 🚀 Key Features

### 1. Metasploit RPC Module Extraction
Queries loaded Metasploit modules by keyword, platform, or disclosure date. It retrieves metadata (CVEs, exploit rank, disclosure date, platform) and reads corresponding Markdown documentation files included with Metasploit.

### 2. Structured LLM Extraction
Uses JSON mode to extract technical target specifications from unstructured module docs and descriptions:
- Target software name and vulnerable versions
- Required OS platforms and dependencies
- Software configuration options (ports, flags, environment variables)

### 3. Guidelines & Lab Blueprint Manuals
Generates step-by-step setup manuals for building vulnerable lab environments:
- Reuses common OS setup guidelines across targets on the same platform
- Reuses software installation steps for overlapping applications
- Outputs clean Markdown files into the `vulnprint_blueprints/` directory

### 4. Database Querying & Interactive Review
- **Search & Catalog:** Search stored vulnerabilities by software name, OS platform, or exploit rank.
- **Interactive Review:** Interactively review, modify, approve, or reject generated installation guidelines before applying them to lab builds.

### 5. Terminal Metrics & Analytics Dashboard
Displays ASCII visual panels summarizing stored vulnerabilities by platform distribution, exploit reliability rank, software catalog counts, and guideline verification status.

### 6. Model Context Protocol (MCP) Tool Integration
Integrates with external search services using Model Context Protocol (MCP). AI agents query configured MCP HTTP tool endpoints (up to a configurable limit) to retrieve external context when identifying software setups and building installation guidelines.

---

## 📦 Installation & Setup

### 1. Prerequisites
- **Python 3.10+**
- **Metasploit Framework** (with `msfrpcd` installed)
- **LLM Endpoint** (Local Ollama server or an OpenAI/OpenRouter API key)
- **MCP Search Server (Optional)** (HTTP endpoint for external context lookup)

### 2. Start Metasploit RPC Daemon
Run `msfrpcd` in a terminal:
```bash
msfrpcd -P your_rpc_password -n -f -a 127.0.0.1 -p 55553
```

### 3. Clone and Configure Vulnprint
```bash
git clone https://github.com/yourusername/vulnprint.git
cd vulnprint
pip install -r requirements.txt
```

Create a `.env` file in the root directory:
```env
# Metasploit RPC Configuration
MSF_RPC_HOST=127.0.0.1
MSF_RPC_PORT=55553
MSF_RPC_PASSWORD=your_rpc_password

# LLM Endpoint Configuration (Ollama / OpenRouter / OpenAI)
AI_BASE_URL=http://localhost:11434/v1
AI_MODEL=llama3
AI_API_KEY=local-engine

# Engine Outputs
BLUEPRINTS_DIR=vulnprint_blueprints
DATABASE_PATH=lab_hub.db

# MCP Server Configuration
MCP_SEARCH_URL=http://localhost:8000/mcp
MCP_MAX_TOOL_CALLS=5
```

---

## ⌨️ CLI Usage

### 1. Ingest Metasploit Modules & Generate Blueprints
Query Metasploit RPC for matching modules, parse technical specs using LLM, and generate lab manuals:

```bash
# Basic keyword search with result limit:
python src/main.py search "apache tomcat" --limit 5

# Import MSF module paths from a JSONL or JSON file:
python src/main.py search -f paths.jsonl --limit 5

# Search with Metasploit search filter syntax and date filters:
python src/main.py search "type:exploit platform:linux" --min-date 2024-01-01 --sort-date desc
```

### 2. View Database Metrics & Analytics
Display terminal ASCII dashboards for stored vulnerability data and software statistics:

```bash
# View terminal metrics dashboard:
python src/main.py db analytics

# Export analytics report to a Markdown file:
python src/main.py db analytics -o reports/metrics.md

# View software catalog list:
python src/main.py db list

# View technology breakdown summary:
python src/main.py db summary
```

### 3. Search Local Vulnerability Database
Search local database records using wildcard syntax and filter criteria:

```bash
# Search cataloged software with wildcards:
python src/main.py db search "apache*"

# Filter search by OS platform and exploit rank, saving output to a file:
python src/main.py db search "apache*" --platform linux --rank excellent -o reports/apache_linux.txt
```

### 4. Interactive Guideline Review
Review and manage unverified software and OS installation guidelines stored in the database:

```bash
python src/main.py review
```

### 5. Export Installation Guidelines
Export specific VM installation guides or OS guidelines to Markdown files:

```bash
# Export guideline by database VM ID:
python src/main.py export guide 1 -o reports/tomcat_guide.md

# Export guideline by Metasploit module path:
python src/main.py export guide "exploit/multi/http/tomcat_mgr_deploy" -o reports/tomcat_mgr.md

# Export OS base guideline by OS ID:
python src/main.py export os 1 -o reports/os_guide.md

# Export all Metasploit module paths in current database as a JSON string array:
python src/main.py export msf-paths -o reports/msf_paths.json
```

### 6. Access Generated Lab Manuals
Generated lab blueprint Markdown files are written to the directory configured in `BLUEPRINTS_DIR` (default: `vulnprint_blueprints/`):

```bash
cat vulnprint_blueprints/CVE-2020-1938.md
```

---

## 🔒 Privacy & Local Processing

When configured with a local LLM server (such as Ollama or LocalAI), Vulnprint processes all module documentation, vulnerability descriptions, and database queries strictly on your local machine. No vulnerability data or system telemetry is sent externally.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE.md).
