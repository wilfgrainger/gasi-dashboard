# GASI — Global Attack Surface Index

A "single pane of glass" open-source dashboard that acts as a **daily weather report for the internet's threat landscape**. It aggregates free, public cybersecurity data to show security professionals exactly what is being attacked, exploited, and scanned today.

**Cost to run: $0**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  GitHub Actions cron (every 4 hours)                         │
│    fetch_intel.py  ──►  daily_threat_data.json  ──► git push │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
              index.html reads static JSON file
              (no backend, no rate limits, $0 hosting)
```

The GitHub Action runs `fetch_intel.py` every four hours. The script pulls from four free public APIs, merges the data into `daily_threat_data.json`, and commits it back to the repository. The frontend (`index.html`) is a pure static page that only reads that one JSON file — it never touches an API directly.

---

## Data Sources

| Source | What it provides | Auth required |
|--------|-----------------|---------------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities actively exploited by hackers | None |
| [NIST NVD](https://nvd.nist.gov/developers/vulnerabilities) | Every newly disclosed CVE globally | Optional API key for higher rate limits |
| [AbuseIPDB](https://www.abuseipdb.com/) | Most aggressive IPs scanning/attacking servers | Free API key |
| [URLhaus (Abuse.ch)](https://urlhaus.abuse.ch/) | URLs currently hosting malware | None |
| [AlienVault OTX](https://otx.alienvault.com/) | Crowdsourced threat intelligence pulses | Free API key |

---

## Dashboard Widgets

1. **Threat Thermometer** — Composite score (1–10) based on new CISA KEV additions, critical CVE volume, URLhaus activity, and OTX pulse count.
2. **Patch Priority List** — Latest additions to the CISA KEV catalog. If it's on this list, hackers are actively exploiting it right now.
3. **Top 10 Most Aggressive IPs** — AbuseIPDB's most-reported IPs in the last 24 hours, with country and ISP.
4. **Trending Malware Families** — Tag cloud from URLhaus + AlienVault showing which malware is hot today.

---

## Setup

### 1. Fork / clone this repository

### 2. Add GitHub Secrets

Go to **Settings → Secrets and variables → Actions** and add:

| Secret name | Where to get it |
|-------------|-----------------|
| `ABUSEIPDB_KEY` | [abuseipdb.com/register](https://www.abuseipdb.com/register) — free community tier |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) → API key in your profile |
| `NVD_API_KEY` | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) — optional but recommended |

> The dashboard works without `OTX_API_KEY` and `NVD_API_KEY` — those widgets will just show no data.  
> `ABUSEIPDB_KEY` is required for the Top IPs widget.

### 3. Enable GitHub Actions

The workflow at `.github/workflows/fetch_data.yml` runs automatically every 4 hours.  
Trigger it manually the first time: **Actions → Fetch Threat Intelligence Data → Run workflow**.

### 4. Enable GitHub Pages

Go to **Settings → Pages** and set source to **Deploy from a branch → main → / (root)**.  
Your dashboard will be live at `https://<your-username>.github.io/gasi-dashboard/`.

---

## Local development

```bash
pip install -r requirements.txt

# Run data fetch (uses API keys from environment)
ABUSEIPDB_KEY=xxx OTX_API_KEY=yyy python fetch_intel.py

# Serve the dashboard locally
python -m http.server 8080
# open http://localhost:8080
```

---

## License

MIT
