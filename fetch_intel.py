#!/usr/bin/env python3
"""
GASI — Global Attack Surface Index
Data Ingestion Engine

Fetches threat intelligence from multiple free public APIs and outputs a
consolidated daily_threat_data.json file for the static dashboard.

Sources:
  - CISA KEV  (Known Exploited Vulnerabilities) — unauthenticated JSON feed
  - NIST NVD  (National Vulnerability Database) — optional API key
  - AbuseIPDB (Top abusive IPs)                — requires ABUSEIPDB_KEY secret
  - URLhaus   (Abuse.ch malware URLs)           — public feed, no key needed
  - AlienVault OTX (threat pulses)             — requires OTX_API_KEY secret
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Endpoints ─────────────────────────────────────────────────────────────────
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/"
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# ── API Keys (stored in GitHub Secrets) ──────────────────────────────────────
ABUSEIPDB_KEY: str = os.getenv("ABUSEIPDB_KEY", "")
OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

TIMEOUT = 30


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(url: str, headers: Optional[dict] = None, params: Optional[dict] = None) -> Optional[dict]:
    """GET request returning parsed JSON, or None on failure."""
    try:
        resp = requests.get(
            url, headers=headers or {}, params=params or {}, timeout=TIMEOUT
        )
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("GET %s failed: %s", url, exc)
        return None


def _post(url: str, data: Optional[dict] = None, headers: Optional[dict] = None) -> Optional[dict]:
    """POST request returning parsed JSON, or None on failure."""
    try:
        resp = requests.post(
            url, headers=headers or {}, data=data or {}, timeout=TIMEOUT
        )
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("POST %s failed: %s", url, exc)
        return None


# ── CISA KEV ──────────────────────────────────────────────────────────────────

def fetch_cisa_kev() -> dict:
    """Fetch the CISA Known Exploited Vulnerabilities catalog."""
    log.info("Fetching CISA KEV…")
    data = _get(CISA_KEV_URL)
    if not data:
        return {"total_catalog_count": 0, "recent_30d_count": 0, "recent": []}

    vulns = data.get("vulnerabilities", [])
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    recent = []

    for v in vulns:
        date_added = v.get("dateAdded", "")
        try:
            dt = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if dt >= cutoff:
            recent.append(
                {
                    "cve_id": v.get("cveID", ""),
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "date_added": date_added,
                    "due_date": v.get("dueDate", ""),
                    "description": (v.get("shortDescription", "") or "")[:200],
                    "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                }
            )

    recent.sort(key=lambda x: x["date_added"], reverse=True)

    return {
        "total_catalog_count": len(vulns),
        "recent_30d_count": len(recent),
        "recent": recent[:20],
    }


# ── NIST NVD ──────────────────────────────────────────────────────────────────

def fetch_nvd_recent() -> dict:
    """Fetch CVEs published in the last 24 hours from NIST NVD."""
    log.info("Fetching NIST NVD recent CVEs…")
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    data = _get(NVD_API_URL, headers=headers, params=params)
    if not data:
        return {"total": 0, "critical_count": 0, "high_count": 0, "cves": []}

    cves: list[dict] = []
    critical_count = 0
    high_count = 0

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        severity = "UNKNOWN"
        base_score = None

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                base_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or entries[0].get(
                    "baseSeverity", "UNKNOWN"
                )
                break

        if severity == "CRITICAL":
            critical_count += 1
        elif severity == "HIGH":
            high_count += 1

        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        cves.append(
            {
                "cve_id": cve.get("id", ""),
                "severity": severity,
                "base_score": base_score,
                "description": desc[:200],
                "published": cve.get("published", ""),
            }
        )

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    cves.sort(key=lambda x: (sev_order.get(x["severity"], 4), -(x["base_score"] or 0)))

    return {
        "total": data.get("totalResults", len(cves)),
        "critical_count": critical_count,
        "high_count": high_count,
        "cves": cves[:20],
    }


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def fetch_abuseipdb() -> dict:
    """Fetch the top abusive IPs from AbuseIPDB."""
    log.info("Fetching AbuseIPDB blacklist…")
    if not ABUSEIPDB_KEY:
        log.warning("ABUSEIPDB_KEY not set — skipping.")
        return {"ips": [], "total": 0}

    data = _get(
        ABUSEIPDB_URL,
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"confidenceMinimum": 90, "limit": 25, "plaintext": False},
    )
    if not data:
        return {"ips": [], "total": 0}

    ips = [
        {
            "ip": e.get("ipAddress", ""),
            "confidence": e.get("abuseConfidenceScore", 0),
            "country": e.get("countryCode", "??"),
            "usage_type": e.get("usageType", "Unknown"),
            "isp": e.get("isp", "Unknown"),
            "total_reports": e.get("totalReports", 0),
            "last_reported": e.get("lastReportedAt", ""),
        }
        for e in data.get("data", [])[:10]
    ]
    return {"ips": ips, "total": len(ips)}


# ── URLhaus ───────────────────────────────────────────────────────────────────

def fetch_urlhaus() -> dict:
    """Fetch recent malicious URLs from URLhaus (Abuse.ch)."""
    log.info("Fetching URLhaus recent URLs…")
    data = _post(URLHAUS_RECENT_URL)
    if not data:
        data = _get(URLHAUS_RECENT_URL)
    if not data:
        return {"url_count": 0, "malware_families": [], "tags": []}

    urls = data.get("urls", [])
    tag_counts: dict[str, int] = {}

    for url in urls:
        for tag in url.get("tags") or []:
            tag = tag.strip().lower()
            if tag:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

    sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
    return {
        "url_count": len(urls),
        "malware_families": [{"name": t[0], "count": t[1]} for t in sorted_tags[:20]],
        "tags": [t[0] for t in sorted_tags[:20]],
    }


# ── AlienVault OTX ────────────────────────────────────────────────────────────

def fetch_otx_pulses() -> dict:
    """Fetch recent threat pulses from AlienVault OTX."""
    log.info("Fetching AlienVault OTX pulses…")
    if not OTX_API_KEY:
        log.warning("OTX_API_KEY not set — skipping.")
        return {"pulses": [], "total": 0, "malware_families": []}

    since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    data = _get(
        OTX_API_URL,
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        params={"limit": 20, "modified_since": since},
    )
    if not data:
        return {"pulses": [], "total": 0, "malware_families": []}

    tag_counts: dict[str, int] = {}
    pulses = []

    for pulse in data.get("results", [])[:10]:
        for tag in pulse.get("tags", []):
            tag = tag.strip()
            if tag:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        pulses.append(
            {
                "name": pulse.get("name", ""),
                "description": (pulse.get("description", "") or "")[:150],
                "author": (pulse.get("author") or {}).get("username", ""),
                "indicator_count": pulse.get("indicator_count", 0),
                "tags": pulse.get("tags", [])[:5],
                "modified": pulse.get("modified", ""),
                "tlp": pulse.get("tlp", "white"),
            }
        )

    sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
    return {
        "pulses": pulses,
        "total": data.get("count", len(pulses)),
        "malware_families": [{"name": t[0], "count": t[1]} for t in sorted_tags[:15]],
    }


# ── Threat Score ──────────────────────────────────────────────────────────────

def calculate_threat_score(kev: dict, nvd: dict, urlhaus: dict, otx: dict) -> dict:
    """
    Calculate a composite threat score (1–10).

    Scoring breakdown (max 10 points):
      - KEV recent 30d additions : up to 3 pts
      - NVD critical CVEs (24h)  : up to 3 pts
      - URLhaus active URL count : up to 2 pts
      - OTX recent pulse count   : up to 2 pts
    """
    score = 0.0
    factors = []

    # KEV factor (max 3)
    kev_recent = kev.get("recent_30d_count", 0)
    if kev_recent >= 15:
        kev_score = 3.0
    elif kev_recent >= 10:
        kev_score = 2.5
    elif kev_recent >= 5:
        kev_score = 2.0
    elif kev_recent >= 2:
        kev_score = 1.5
    elif kev_recent >= 1:
        kev_score = 1.0
    else:
        kev_score = 0.5
    score += kev_score
    factors.append({"name": "Active Exploits (CISA KEV)", "value": kev_recent, "score": kev_score, "max": 3})

    # NVD factor (max 3)
    critical = nvd.get("critical_count", 0)
    total_nvd = nvd.get("total", 0)
    if critical >= 10:
        nvd_score = 3.0
    elif critical >= 5:
        nvd_score = 2.5
    elif critical >= 2:
        nvd_score = 2.0
    elif critical >= 1:
        nvd_score = 1.5
    elif total_nvd >= 10:
        nvd_score = 1.0
    else:
        nvd_score = 0.5
    score += nvd_score
    factors.append({"name": "Critical CVEs (24h)", "value": critical, "score": nvd_score, "max": 3})

    # URLhaus factor (max 2)
    url_count = urlhaus.get("url_count", 0)
    if url_count >= 100:
        url_score = 2.0
    elif url_count >= 50:
        url_score = 1.5
    elif url_count >= 20:
        url_score = 1.0
    else:
        url_score = 0.5
    score += url_score
    factors.append({"name": "Malware URLs (URLhaus)", "value": url_count, "score": url_score, "max": 2})

    # OTX factor (max 2)
    pulse_count = otx.get("total", 0)
    if pulse_count >= 50:
        otx_score = 2.0
    elif pulse_count >= 20:
        otx_score = 1.5
    elif pulse_count >= 5:
        otx_score = 1.0
    else:
        otx_score = 0.5
    score += otx_score
    factors.append({"name": "Threat Campaigns (OTX)", "value": pulse_count, "score": otx_score, "max": 2})

    final_score = round(min(max(score, 1.0), 10.0), 1)

    if final_score >= 8.0:
        level, level_color = "CRITICAL", "critical"
    elif final_score >= 6.0:
        level, level_color = "HIGH", "high"
    elif final_score >= 4.0:
        level, level_color = "ELEVATED", "elevated"
    else:
        level, level_color = "MODERATE", "moderate"

    return {
        "score": final_score,
        "level": level,
        "level_color": level_color,
        "factors": factors,
    }


# ── Malware Family Merge ───────────────────────────────────────────────────────

def merge_malware_families(urlhaus: dict, otx: dict) -> list[dict]:
    """Merge and de-duplicate malware families from URLhaus and OTX."""
    combined: dict[str, int] = {}
    for item in urlhaus.get("malware_families", []):
        name = item["name"].lower()
        combined[name] = combined.get(name, 0) + item["count"]
    for item in otx.get("malware_families", []):
        name = item["name"].lower()
        combined[name] = combined.get(name, 0) + item["count"]
    return [
        {"name": n, "count": c}
        for n, c in sorted(combined.items(), key=lambda x: x[1], reverse=True)[:25]
    ]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("=== GASI Data Ingestion Starting ===")

    kev = fetch_cisa_kev()
    nvd = fetch_nvd_recent()
    abuse = fetch_abuseipdb()
    urlhaus = fetch_urlhaus()
    otx = fetch_otx_pulses()

    threat_score = calculate_threat_score(kev, nvd, urlhaus, otx)
    malware_families = merge_malware_families(urlhaus, otx)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threat_score": threat_score,
        "cisa_kev": kev,
        "nvd": nvd,
        "top_ips": abuse,
        "malware_families": malware_families,
        "urlhaus": {"url_count": urlhaus.get("url_count", 0)},
        "otx": {
            "pulse_count": otx.get("total", 0),
            "pulses": otx.get("pulses", []),
        },
    }

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "daily_threat_data.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)

    log.info("Written → %s", out_path)
    log.info(
        "Score: %s (%s) | KEV 30d: %d | NVD crit: %d | IPs: %d | URLs: %d",
        threat_score["score"],
        threat_score["level"],
        kev.get("recent_30d_count", 0),
        nvd.get("critical_count", 0),
        len(abuse.get("ips", [])),
        urlhaus.get("url_count", 0),
    )


if __name__ == "__main__":
    main()
