Here is a comprehensive, production-ready `README.md` for your Git repository. It is designed to be visually clean, professional, and clear about the project's architecture and philosophy.

---

# 📑 Vulnprint

**Vulnprint** is a 100% self-hosted, open-source **Vulnerability Intelligence Analytics & Lab Blueprint Engine**. It bridges the gap between active threat framework intelligence and local penetration testing labs.

Instead of relying on brittle, automated infrastructure scripts that constantly break due to legacy software dependency hell, Vulnprint treats vulnerability discovery analytically. It dynamically queries a live Metasploit instance via RPC, uses a local Small Language Model (SLM) to extract structured application configurations, logs the metrics into a local database ledger, and generates high-fidelity **Lab Blueprint Manuals** and **Statistical Reports**.

---

## 🎯 The Problem & The Solution

- **The Problem:** Building replication labs for vulnerability validation usually involves hours of guessing configuration settings, manual parsing of unstructured write-ups, and dealing with broken, hardcoded automation scripts that fail on legacy software.
- **The Solution:** Vulnprint delegates the boring, heavy-lifting text parsing to a completely local, privacy-respecting AI. It organizes your attack surface into statistical metrics and generates step-by-step lab manuals so human operators can build target environments flawlessly.

---

## 🛠️ System Architecture & Stack

Vulnprint is architected for absolute data privacy and air-gapped capability. **No metrics, data profiles, or vulnerability descriptions ever leave your local machine.**

```
[User CLI Query]
        │
        ▼
┌───────────────┐        RPC Calls        ┌─────────────────┐
│ Python Engine │ ──────────────────────> │  msfrpcd Daemon │
└───────────────┘                         └─────────────────┘
        │
        ├─────────────────────────────────────────┐
        ▼ (Send Clean Description)                ▼ (Store Structured Analytics)
┌─────────────────┐                     ┌─────────────────┐
│ Local SLM Server│                     │  SQLite Ledger  │
│ (Ollama/LocalAI)│                     │  (lab_hub.db)   │
└─────────────────┘                     └─────────────────┘
        │
        ▼
┌─────────────────┐
│  Lab Blueprints │
│ & Tech Reports  │
└─────────────────┘

```

- **Language Environment:** Python 3.10+
- **Exploit Source Registry:** Metasploit Framework via the background RPC Daemon (`msfrpcd`)
- **Framework Interface:** `pymetasploit3` (Reads directly from Metasploit's loaded RAM cache)
- **AI Integration:** Official `openai` Python SDK (Using an OpenAI-compatible interface)
- **Local Inference Engine:** Ollama / LocalAI (Running `llama3`, `mistral`, or `phi3` natively)
- **Central Ledger:** SQLite (`sqlite3`)

---

## 🚀 Key Features

### 1. On-Demand Metasploit Querying

Queries active memory modules inside Metasploit via RPC based on user-defined CLI criteria (e.g., targeting specific platforms or disclosure dates). It isolates and extracts only the relevant text blocks, discarding UI fluff to optimize AI token context windows.

### 2. Structured LLM Inference (Native JSON Mode)

Leverages local models using an OpenAI-compatible abstraction layer. It forces the local AI to operate in a strict `json_object` mode, ensuring clean, programmatically predictable output:

```json
{
  "software_name": "Apache Tomcat",
  "vulnerable_versions": ["9.0.0.M1", "9.0.30"],
  "required_configs": ["AJP connector enabled on port 8009"]
}
```

### 3. Persistent Analytics Ledger

Maintains a local SQLite database tracking historical inquiries, CVE maps, target versions, and configuration flags—making it a custom intelligence platform tailored to your specific testing goals.

### 4. Interactive Dashboard & Blueprints

Generates clean terminal ASCII charts visualizing technology density distributions across your query parameters (so you know which core systems to build first). It outputs clean Markdown manuals outlining legacy archive download requirements, setup configurations, and validation lifecycles.

---

## 📦 Installation & Setup

### Prerequisites

1. **Metasploit Framework** installed.
2. **Ollama** installed and running locally.

### 1. Initialize the Local SLM

Pull and spin up your preferred open-source model:

```bash
ollama pull llama3

```

### 2. Start the Metasploit RPC Daemon

Run the RPC server in a background terminal session:

```bash
msfrpcd -P your_secure_password -n -f -a 127.0.0.1

```

### 3. Clone and Configure Vulnprint

Clone this repository to your host:

```bash
git clone https://github.com/yourusername/vulnprint.git
cd vulnprint
pip install -r requirements.txt

```

Create a `.env` file in the root directory:

```env
MSF_RPC_PASSWORD=your_secure_password
MSF_RPC_PORT=55553
AI_BASE_URL=http://localhost:11434/v1
AI_MODEL=llama3

```

---

## ⌨️ Usage

### Generate Intelligence & Build Blueprints

Execute a targeted query against the framework engine:

```bash
python -m vulnprint.main --search "type:exploit platform:linux date:2025"

```

### View Technology Analytics Dashboard

Display statistical distribution breakdowns from the SQLite ledger:

```bash
python -m vulnprint.analytics --summary

```

### Access Your Lab Manuals

Check the generated manuals folder for your manual configuration layout guide:

```bash
cat vulnprint_blueprints/CVE-2020-1938.md

```

---

## 🛡️ Privacy & Guardrails

Vulnprint enforces strict privacy isolation. Under no circumstances are network requests, vulnerability identifiers, or telemetry files sent to external cloud APIs, public web trackers, or third-party analytical models.

---

## 📄 License

This project is open-source and distributed under the **MIT License**. See `LICENSE` for more information.
