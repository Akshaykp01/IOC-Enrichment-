"""
IOC Enrichment Tool
-------------------
Reads a list of indicators of compromise (IPs, domains, file hashes),
looks each one up in VirusTotal and AbuseIPDB, and writes a CSV report
with a simple verdict: MALICIOUS, SUSPICIOUS, CLEAN, or UNKNOWN.

This automates the "alert enrichment" step a SOC analyst does by hand.

Usage:
    python enrich.py iocs.txt                # writes enrichment_report.csv
    python enrich.py iocs.txt -o out.csv     # custom output file

API keys are read from environment variables (never hard-code them):
    VT_API_KEY         - VirusTotal API key
    ABUSEIPDB_API_KEY  - AbuseIPDB API key
"""

import argparse
import csv
import ipaddress
import os
import re
import sys
import time

import requests

VT_URL = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_FREE_DELAY = 15  # VirusTotal free tier allows 4 requests per minute

# Verdict thresholds - tune these to reduce false positives
VT_MALICIOUS_MIN = 5      # engines flagging malicious -> MALICIOUS
ABUSE_MALICIOUS_MIN = 75  # AbuseIPDB confidence score -> MALICIOUS
ABUSE_SUSPICIOUS_MIN = 25


# ---------- 1. Identify what kind of indicator we have ----------
def classify(ioc):
    """Return 'ip', 'hash', 'domain', or None if unrecognized."""
    try:
        ip = ipaddress.ip_address(ioc)
        return "ip" if ip.is_global else "private_ip"  # skip internal and reserved ranges
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
        return "hash"  # MD5, SHA-1, or SHA-256
    if re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", ioc):
        return "domain"
    return None


# ---------- 2. Look the indicator up in each service ----------
def vt_lookup(ioc, ioc_type, key):
    """Query VirusTotal. Returns a dict of detection counts, or None if not found."""
    path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[ioc_type]
    resp = requests.get(f"{VT_URL}/{path}/{ioc}", headers={"x-apikey": key}, timeout=30)
    if resp.status_code == 404:
        return None  # VirusTotal has never seen it
    resp.raise_for_status()
    stats = resp.json()["data"]["attributes"].get("last_analysis_stats", {})
    return {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
    }


def abuseipdb_lookup(ip, key):
    """Query AbuseIPDB (IP addresses only)."""
    resp = requests.get(
        ABUSE_URL,
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=30,
    )
    resp.raise_for_status()
    d = resp.json()["data"]
    return {
        "abuse_score": d.get("abuseConfidenceScore", 0),
        "abuse_reports": d.get("totalReports", 0),
        "country": d.get("countryCode", ""),
        "isp": d.get("isp", ""),
    }


# ---------- 3. Turn the raw numbers into a verdict ----------
def verdict(row):
    vt_mal = row.get("vt_malicious") or 0
    vt_sus = row.get("vt_suspicious") or 0
    abuse = row.get("abuse_score") or 0
    if row.get("vt_found") is False and "abuse_score" not in row:
        return "UNKNOWN"
    if vt_mal >= VT_MALICIOUS_MIN or abuse >= ABUSE_MALICIOUS_MIN:
        return "MALICIOUS"
    if vt_mal >= 1 or vt_sus >= 1 or abuse >= ABUSE_SUSPICIOUS_MIN:
        return "SUSPICIOUS"
    return "CLEAN"


# ---------- 4. Main loop ----------
def enrich(iocs, vt_key, abuse_key):
    results = []
    for i, ioc in enumerate(iocs):
        ioc_type = classify(ioc)
        row = {"ioc": ioc, "type": ioc_type or "unrecognized"}

        if ioc_type in (None, "private_ip"):
            row["verdict"] = "SKIPPED"
            row["note"] = "Private or reserved IP (not sent to APIs)" if ioc_type else "Not an IP, domain, or hash"
            results.append(row)
            continue

        try:
            vt = vt_lookup(ioc, ioc_type, vt_key)
            row["vt_found"] = vt is not None
            row.update(vt or {})
            if ioc_type == "ip":
                row.update(abuseipdb_lookup(ioc, abuse_key))
            row["verdict"] = verdict(row)
        except requests.RequestException as e:
            row["verdict"] = "ERROR"
            detail = str(e)
            if getattr(e, "response", None) is not None:  # show the service's own explanation
                detail = f"HTTP {e.response.status_code} from {e.response.url.split('?')[0]}: {e.response.text[:150]}"
            row["note"] = detail[:250]

        print(f"[{i + 1}/{len(iocs)}] {ioc:<45} {row['verdict']}")
        if row["verdict"] == "ERROR":
            print(f"      -> {row['note']}")
        results.append(row)

        if i < len(iocs) - 1:
            time.sleep(VT_FREE_DELAY)  # stay inside the free-tier rate limit
    return results


def write_csv(results, path):
    fields = ["ioc", "type", "verdict", "vt_found", "vt_malicious", "vt_suspicious",
              "vt_harmless", "abuse_score", "abuse_reports", "country", "isp", "note"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)


def load_iocs(path):
    """Read one indicator per line; ignore blanks, comments, and duplicates."""
    seen, iocs = set(), []
    with open(path) as f:
        for line in f:
            ioc = line.strip()
            if ioc and not ioc.startswith("#") and ioc.lower() not in seen:
                seen.add(ioc.lower())
                iocs.append(ioc)
    return iocs


def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs with VirusTotal and AbuseIPDB")
    parser.add_argument("input", help="Text file with one IOC per line")
    parser.add_argument("-o", "--output", default="enrichment_report.csv")
    args = parser.parse_args()

    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if not vt_key or not abuse_key:
        sys.exit("Set VT_API_KEY and ABUSEIPDB_API_KEY environment variables first.")

    iocs = load_iocs(args.input)
    print(f"Enriching {len(iocs)} indicators (about {len(iocs) * VT_FREE_DELAY // 60 + 1} min on the free tier)...\n")
    results = enrich(iocs, vt_key, abuse_key)
    write_csv(results, args.output)

    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"\nDone. Report saved to {args.output}")
    print("Summary:", ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
