"""
RDPShield - VirusTotal enrichment
=================================
Thin client for the VirusTotal v3 API. Two lookups:

  vt_lookup_hash(sha256) -> reputation for a file hash (a YARA finding)
  vt_lookup_ip(ip)       -> reputation for an attacker IP

Both return a small, flat dict that's easy to show on the dashboard, and both
fail soft: if no API key is configured, the IP/hash is unknown to VT, or the
request errors/rate-limits, they return {"found": False, ...} instead of raising.

Free tier: 4 requests/min, 500/day. Keep lookups on-demand (button click), not
automatic, to stay within quota.
"""

import requests

import settings  # DB-backed key (overrides config.py)


def _enabled():
    return bool(settings.vt_api_key())


def _stats(attributes):
    """Flatten last_analysis_stats from a VT object into our shape."""
    s = attributes.get("last_analysis_stats", {}) or {}
    malicious = s.get("malicious", 0)
    suspicious = s.get("suspicious", 0)
    harmless = s.get("harmless", 0)
    undetected = s.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
    }


def _get(path):
    """GET a VT v3 endpoint. Returns the parsed json or None on any problem."""
    if not _enabled():
        return None
    try:
        resp = requests.get(
            f"{settings.vt_url()}/{path}",
            headers={"x-apikey": settings.vt_api_key()},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return {"_notfound": True}
        print(f"[VT] HTTP {resp.status_code} for {path}")
        return None
    except Exception as e:
        print(f"[VT] error for {path}: {e}")
        return None


def vt_lookup_hash(sha256):
    """
    Look up a file hash on VirusTotal.

    Returns:
        {"found": True, "malicious": n, "suspicious": n, "total": n,
         "permalink": url}  on success,
        {"found": False, "reason": "..."}  otherwise.
    """
    if not sha256:
        return {"found": False, "reason": "no hash"}
    if not _enabled():
        return {"found": False, "reason": "VirusTotal API key not configured"}

    data = _get(f"files/{sha256}")
    if data is None:
        return {"found": False, "reason": "lookup failed"}
    if data.get("_notfound"):
        return {"found": False, "reason": "not seen by VirusTotal"}

    attrs = data.get("data", {}).get("attributes", {})
    result = {"found": True, "sha256": sha256}
    result.update(_stats(attrs))
    result["permalink"] = f"https://www.virustotal.com/gui/file/{sha256}"
    print(f"[VT] {sha256[:12]} -> {result['malicious']}/{result['total']} malicious")
    return result


def vt_lookup_ip(ip):
    """
    Look up an IP address on VirusTotal.

    Returns:
        {"found": True, "malicious": n, "suspicious": n, "total": n,
         "reputation": int, "country": cc, "permalink": url}  on success,
        {"found": False, "reason": "..."}  otherwise.
    """
    if not ip:
        return {"found": False, "reason": "no ip"}
    if not _enabled():
        return {"found": False, "reason": "VirusTotal API key not configured"}

    data = _get(f"ip_addresses/{ip}")
    if data is None:
        return {"found": False, "reason": "lookup failed"}
    if data.get("_notfound"):
        return {"found": False, "reason": "not seen by VirusTotal"}

    attrs = data.get("data", {}).get("attributes", {})
    result = {"found": True, "ip": ip}
    result.update(_stats(attrs))
    result["reputation"] = attrs.get("reputation", 0)
    result["country"] = attrs.get("country", "")
    result["permalink"] = f"https://www.virustotal.com/gui/ip-address/{ip}"
    print(f"[VT] {ip} -> {result['malicious']}/{result['total']} malicious")
    return result


if __name__ == "__main__":
    # Quick smoke test: python virustotal.py
    print("VT enabled:", _enabled())
    print(vt_lookup_ip("8.8.8.8"))
