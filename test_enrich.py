"""Offline tests - run with:  python -m pytest -q   (no API keys or internet needed)"""
from unittest.mock import patch

import enrich


def test_classify():
    assert enrich.classify("8.8.8.8") == "ip"
    assert enrich.classify("10.0.0.5") == "private_ip"
    assert enrich.classify("example.com") == "domain"
    assert enrich.classify("44d88612fea8a8f36de82e1278abb02f") == "hash"
    assert enrich.classify("not an ioc!") is None


def test_verdict_thresholds():
    assert enrich.verdict({"vt_found": True, "vt_malicious": 5}) == "MALICIOUS"
    assert enrich.verdict({"vt_found": True, "vt_malicious": 1}) == "SUSPICIOUS"
    assert enrich.verdict({"vt_found": True, "vt_malicious": 0, "abuse_score": 80}) == "MALICIOUS"
    assert enrich.verdict({"vt_found": True, "vt_malicious": 0, "abuse_score": 30}) == "SUSPICIOUS"
    assert enrich.verdict({"vt_found": True, "vt_malicious": 0}) == "CLEAN"
    assert enrich.verdict({"vt_found": False}) == "UNKNOWN"


@patch("enrich.time.sleep")
@patch("enrich.abuseipdb_lookup", return_value={"abuse_score": 90, "abuse_reports": 40, "country": "XX", "isp": "Test"})
@patch("enrich.vt_lookup", return_value={"vt_malicious": 0, "vt_suspicious": 0, "vt_harmless": 70})
def test_enrich_pipeline(vt, abuse, sleep):
    rows = enrich.enrich(["8.8.4.4", "192.168.1.1", "???"], "k1", "k2")
    assert [r["verdict"] for r in rows] == ["MALICIOUS", "SKIPPED", "SKIPPED"]
    vt.assert_called_once()  # private and unrecognized IOCs are never sent to the APIs
