# PhishAI CLI

AI-powered phishing analysis agent for the terminal. Built on top of [phishai-engine](https://github.com/apt-0/phishai-engine).

## Install

```bash
pip install phishai-cli
```

For full features (enrichment, LLM, URL analysis with Playwright):

```bash
pip install phishai-cli[agent]
```

## Quick Start

```bash
# Scan an email (fast, local-only)
phishai scan suspicious.eml

# Analyze a URL
phishai url https://example.com/login

# Verify a sender
phishai sender security@paypal.com

# Let the AI agent decide what to do
phishai agent suspicious.eml
```

## Commands

### `phishai scan`

Fast local-only email analysis. No external API calls, runs in < 2 seconds.
Executes: parse → red flags → content triggers → NLP signals → risk scoring.

```bash
phishai scan email.eml
```

### `phishai analyze`

Full deep analysis with enrichment (WHOIS, DNS, VirusTotal) and optional LLM verdict.

```bash
# Basic (WHOIS + DNS only)
phishai analyze email.eml

# With VirusTotal
phishai analyze email.eml --vt-key YOUR_API_KEY

# With LLM verdict (local GGUF model)
phishai analyze email.eml --llm-model path/to/model.gguf --llm-mode deep

# Custom enrichment services
phishai analyze email.eml --services whois dns virustotal abuseipdb
```

| Flag | Description |
|------|-------------|
| `--services` | Enrichment services to query (default: `whois dns`) |
| `--vt-key` | VirusTotal API key |
| `--llm-model` | Path to GGUF model file for LLM analysis |
| `--llm-mode` | LLM depth: `quick` (3 calls) or `deep` (12 calls) |

### `phishai url`

Analyze a URL for phishing indicators. Uses a headless browser (Playwright) to render the page, capture a screenshot, detect login forms, and identify brand impersonation.

```bash
# Basic URL analysis
phishai url https://example.com/login

# With AI Vision (Ollama + llava)
phishai url https://example.com/login \
  --vision-provider ollama \
  --vision-model llava

# With AI Vision (OpenAI)
phishai url https://example.com/login \
  --vision-provider openai \
  --vision-model gpt-4o \
  --vision-url https://api.openai.com/v1
```

| Flag | Description |
|------|-------------|
| `--vision-provider` | Vision LLM provider: `ollama`, `openai`, `openrouter`, `lmstudio` |
| `--vision-model` | Vision model name (e.g. `llava`, `gpt-4o`) |
| `--vision-url` | Vision API base URL (uses provider default if omitted) |
| `--timeout` | Navigation timeout in seconds (default: 20) |

### `phishai sender`

Verify a sender domain via WHOIS, DNS records, and BIMI brand verification.

```bash
phishai sender security@paypal.com
phishai sender google.com
```

### `phishai report`

Run a full analysis and generate a self-contained HTML report.

```bash
phishai report email.eml -o report.html
phishai report email.eml -o report.html --llm-model path/to/model.gguf
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Output file path (default: `report.html`) |
| `--llm-model` | Path to GGUF model for LLM-enhanced report |

### `phishai agent`

AI agent mode. The LLM autonomously decides which tools to call based on your input.

```bash
# Single-shot: give it a file, URL, or domain
phishai agent suspicious.eml
phishai agent https://login-paypal.xyz
phishai agent security@paypal.com

# Natural language
phishai agent "analyze this email and check all URLs inside"

# Interactive chat
phishai agent -i
```

The agent uses OpenAI-compatible tool-calling API. Configure the LLM provider:

```bash
# Ollama (default)
phishai agent suspicious.eml --provider ollama --model qwen2.5

# OpenAI
phishai agent suspicious.eml --provider openai --model gpt-4o --api-key sk-...

# OpenRouter
phishai agent suspicious.eml --provider openrouter --model meta-llama/llama-3-8b-instruct --api-key sk-...

# LM Studio
phishai agent suspicious.eml --provider lmstudio --model local-model
```

| Flag | Description |
|------|-------------|
| `--provider` | LLM provider: `ollama`, `openai`, `openrouter`, `lmstudio` (default: `ollama`) |
| `--model` | Model name |
| `--base-url` | Custom API base URL |
| `--api-key` | API key (required for `openai`, `openrouter`) |
| `-i`, `--interactive` | Interactive chat mode |

## How the Agent Works

```
User input
  ↓
Agent (LLM with tool-calling)
  ├── calls quick_scan()       → gets overview + red flags
  ├── finds suspicious URLs    → calls analyze_url() on each
  ├── weak authentication?     → calls verify_sender()
  ├── needs enrichment?        → calls deep_analyze()
  └── produces verdict in natural language
```

The agent autonomously decides the analysis strategy. For an email file, it typically:

1. Runs `quick_scan` to get a first-pass risk assessment
2. Inspects any URLs found with `analyze_url` (headless browser + brand detection)
3. Verifies the sender domain if SPF/DKIM/DMARC look weak
4. Escalates to `deep_analyze` if indicators warrant deeper investigation
5. Returns a clear verdict: **phishing**, **suspicious**, or **legitimate**

## Architecture

```
phishai-cli (this repo)
  └── imports phishai-engine (the analysis library)
        ├── parser         — email parsing, IOC extraction
        ├── red_flags      — deterministic rule checks
        ├── content        — trigger pattern matching
        ├── nlp            — MiniLM-based NLP signals
        ├── ml             — TF-IDF + ONNX classification
        ├── llm            — LLM analysis (GGUF, Ollama, OpenAI, ...)
        ├── enrichment     — WHOIS, DNS, VirusTotal, AbuseIPDB, BIMI
        ├── url            — Playwright browser, form detection, brand DB
        └── report         — HTML report generation
```

## Development

```bash
git clone https://github.com/apt-0/phishai-cli.git
cd phishai-cli
pip install -e ".[dev]"
```

## License

MIT
