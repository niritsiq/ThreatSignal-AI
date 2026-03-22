# ThreatSignal AI

> Automated cyber incident risk estimation — Shodan attack surface + OpenAI embeddings + GPT reasoning + SerpAPI news signals + Polymarket crowd prediction.

**Live API:** `https://threatsignal-api.lemongrass-f695ae95.francecentral.azurecontainerapps.io`

---

## What it does

Given a domain name, ThreatSignal AI estimates the probability that a company will suffer a cyber incident within a given time window by combining multiple data sources:

| Layer | Source | What it contributes |
|---|---|---|
| Attack surface | Shodan API | Open ports, CVEs, services, org, IPs |
| Historical similarity | OpenAI embeddings + FAISS | Top-3 most similar past breach cases |
| News signal | SerpAPI Google News | Recent cyber headlines → risk boost 0–15% |
| LLM reasoning | GPT-4 function calling | Structured probability + explanation |
| Crowd signal | Polymarket Gamma API | Prediction market probability (if available) |
| Risk trend | Local JSON reports | INCREASING / DECREASING / STABLE / NEW vs last scan |

---

## Quick Start

```bash
# 1. Clone and create virtual environment
git clone https://github.com/niritsiq/ThreatSignal-AI
cd ThreatSignal-AI
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/Mac

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys — create a .env file
OPENAI_API_KEY=sk-...
SHODAN_API_KEY=...
SERP_API_KEY=...      # optional — enables news signal

# 4. Build breach similarity index (one-time setup)
python scripts/build_index.py

# 5. Analyze a domain
python -m threatsignal analyze --domain okta.com
python -m threatsignal analyze --domain github.com --horizon 60
python -m threatsignal analyze --domain microsoft.com --no-save

# 6. Or start the API server
python -m threatsignal serve --port 8000
# Then POST to: http://localhost:8000/analyze
```

---

## CLI Output — 7 sections

```
+----------------------------------------------+
| ThreatSignal AI — Risk Report                |
| Target  : okta.com                           |
| Horizon : 30 days                            |
+----------------------------------------------+

[1] ATTACK SURFACE SUMMARY
  IPs found        : 3.169.71.25, 3.169.71.21
  Open ports       : [80, 443]
  CVE indicators   : CVE-2022-0778
  Attack Surface Score: 4.2/10

[2] SIMILAR HISTORICAL BREACHES
  1. Okta 2022 Support System Breach (LAPSUS$)   — similarity: 0.41
  2. Capital One 2019 Cloud Misconfiguration      — similarity: 0.34
  3. Log4Shell (CVE-2021-44228) Mass Exploitation — similarity: 0.33

[3] LLM RISK ASSESSMENT
  Risk Level  : MEDIUM
  Probability : 20.00% chance within 30 days
  Confidence  : 75.00%
  Explanation : Okta exhibits low attack surface but high historical
                breach similarity. Recent news activity increases risk.

[4] NEWS SIGNAL (SerpAPI)
  Articles found : 10
  Risk boost     : +15%
  Recent headlines:
    - Okta confirms breach affecting support system...
    - Top Las Vegas hotel is the latest ransomware victim...

[5] POLYMARKET SIGNAL
  Status : NOT FOUND — no active cyber-incident market for 'okta'

[6] FINAL SIGNAL
  Model Probability : 35.00%
  Signal            : MARKET_NOT_AVAILABLE
  Interpretation    : No Polymarket data. Model+news estimate only.

[7] RISK TREND
  Direction  : ^ INCREASING   Delta: +10.00%
  Now        : HIGH
  Previously : MEDIUM
```

---

## API Server

```bash
# Start locally
python -m threatsignal serve --port 8000

# Health check
curl http://localhost:8000/health

# Analyze a domain
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain": "okta.com", "time_horizon_days": 30}'
```

**Live on Azure:**
```bash
curl https://threatsignal-api.lemongrass-f695ae95.francecentral.azurecontainerapps.io/health

curl -X POST https://threatsignal-api.lemongrass-f695ae95.francecentral.azurecontainerapps.io/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain": "github.com", "time_horizon_days": 30}'
```

---

## Tests

```bash
# Fast unit tests — 92 tests, no API calls, ~2 seconds
python -m pytest -m "not integration" -v

# Integration tests — real Shodan, OpenAI, Polymarket APIs (~15 seconds)
python -m pytest -m integration -v --no-cov

# All 100 tests with coverage report
python -m pytest --cov=threatsignal --cov-report=term-missing
```

---

## Docker

```bash
docker-compose up --build

curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain": "okta.com", "time_horizon_days": 30}'
```

---

## Architecture

```
Domain
  → Shodan API           (ports, CVEs, services, org)
  → OpenAI embeddings    (1536-dim vector via text-embedding-3-small)
  → FAISS index          (cosine similarity over 21 real breach cases)
  → SerpAPI Google News  (recent cyber headlines → risk boost 0-15%)
  → GPT-4 function call  (structured JSON: probability + explanation)
  → Polymarket API       (crowd prediction market signal)
  → SignalAggregator     (model + news boost vs market delta)
  → RiskTrend            (compare vs previous scan)
  → ReportBuilder        (7-section CLI output + JSON export)
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | Yes | OpenAI API key |
| `SHODAN_API_KEY` | Yes | Shodan API key |
| `SERP_API_KEY` | No | SerpAPI key — enables news signal layer |
| `LLM_MODEL` | No | Default: `gpt-4o-mini` |
| `EMBEDDING_MODEL` | No | Default: `text-embedding-3-small` |
| `LOG_LEVEL` | No | Default: `INFO` |
| `AZURE_OPENAI_ENDPOINT` | No | Use Azure OpenAI instead of regular OpenAI |
| `AZURE_OPENAI_API_KEY` | No | Azure OpenAI key |
| `AZURE_OPENAI_API_VERSION` | No | Default: `2024-10-21` |

---

## API Keys

| Key | Where to get |
|---|---|
| `OPENAI_API_KEY` | https://platform.openai.com/api-keys |
| `SHODAN_API_KEY` | https://account.shodan.io |
| `SERP_API_KEY` | https://serpapi.com |

---

## Azure Deployment

```powershell
az acr login --name threatsignalacr
docker build -t threatsignalacr.azurecr.io/threatsignal-ai:latest .
docker push threatsignalacr.azurecr.io/threatsignal-ai:latest
az containerapp update --name threatsignal-api --resource-group threatsignal-rg `
  --image threatsignalacr.azurecr.io/threatsignal-ai:latest
```
