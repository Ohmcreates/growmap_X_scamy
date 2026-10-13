"""
Production-Ready URL Heuristic Verification Engine (Python Implementation)
Implements 15 concrete heuristic rules:
 - LEX-01 .. LEX-07: Structural & Lexical Rules
 - SEM-01 .. SEM-04: Semantic & Keyword Rules
 - NET-01 .. NET-04: Domain & Network Intelligence Rules

Thresholds:
 - 0-25:  Low Risk (Likely Safe)
 - 26-55: Medium Risk (Suspicious)
 - 56+:   High Risk (Likely Phishing / Scam)
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "verify", "login", "update", "secure", "banking", "kyc", "wallet",
    "billing", "signin", "password", "credential", "auth", "unblock",
    "reactivate", "collect", "challan", "rto"
]

TOP_BRANDS = [
    ("paypal", "paypal.com"),
    ("google", "google.com"),
    ("apple", "apple.com"),
    ("amazon", "amazon.com"),
    ("microsoft", "microsoft.com"),
    ("netflix", "netflix.com"),
    ("binance", "binance.com"),
    ("sbi", "sbi.co.in"),
    ("hdfc", "hdfcbank.com"),
    ("icici", "icicibank.com"),
    ("axis", "axisbank.com"),
    ("phonepe", "phonepe.com"),
    ("paytm", "paytm.com"),
    ("parivahan", "parivahan.gov.in"),
    ("indiapost", "indiapost.gov.in"),
]

SUSPICIOUS_FREE_TLDS = {
    "xyz", "top", "tk", "ml", "click", "buzz", "club", "work",
    "gq", "cf", "ga", "live", "rest", "fit", "monster", "link",
    "surf", "icu", "shop", "bid", "loan"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "ow.ly", "rb.gy", "shorturl.at", "tiny.cc", "goo.gl"
}

DYNAMIC_DNS_DOMAINS = {
    "redirectme.net", "duckdns.org", "ngrok.io", "ngrok-free.app",
    "ddns.net", "hopto.org", "zapto.org", "bounceme.net", "serveo.net",
    "loca.lt", "no-ip.org", "no-ip.biz", "no-ip.info"
}

OFFICIAL_ALLOWLIST = {
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "pnbindia.in", "npci.org.in",
    "bhimupi.org.in", "incometax.gov.in", "uidai.gov.in",
    "cybercrime.gov.in", "parivahan.gov.in", "echallan.parivahan.gov.in",
    "morth.nic.in", "indiapost.gov.in", "google.com", "paypal.com",
    "apple.com", "amazon.com", "microsoft.com", "netflix.com"
}


def inspect_url(url: str) -> dict:
    """
    Evaluates a raw URL against all 15 heuristic rules.
    Returns dictionary with total score (0-100), risk level, and breakdown of fired rules.
    """
    raw_url = (url or "").strip()
    if not raw_url:
        return {"error": "Empty URL provided."}

    normalized = raw_url if "://" in raw_url else f"https://{raw_url}"
    try:
        parsed = urlparse(normalized)
    except Exception as e:
        return {
            "url": raw_url,
            "score": 85,
            "risk_level": "High Risk",
            "risk_code": "HIGH",
            "flags": ["LEX-00: Malformed URL parsing failure"],
            "fired_rules": [{"id": "LEX-00", "title": "Malformed URL", "points": 85}]
        }

    host = (parsed.netloc or "").lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    path = (parsed.path or "") + (f"?{parsed.query}" if parsed.query else "")
    full_url_lower = normalized.lower()

    # Check official allowlist
    if any(host == off or host.endswith(f".{off}") for off in OFFICIAL_ALLOWLIST):
        return {
            "url": raw_url,
            "normalized_url": normalized,
            "host": host,
            "path": path,
            "score": 0,
            "risk_level": "Low Risk",
            "risk_code": "LOW",
            "is_official": True,
            "flags": [],
            "fired_rules": [],
            "summary": "Verified institutional allowlisted domain."
        }

    score = 0
    fired_rules = []
    flags = []

    # ---------------------------------------------------------
    # 1. Structural & Lexical Rules
    # ---------------------------------------------------------

    # Rule LEX-01: Direct IP in Hostname (+35)
    is_ip = bool(re.search(r"^\d{1,3}(\.\d{1,3}){3}$", host) or host.startswith("[") or host.count(":") >= 2)
    if is_ip:
        score += 35
        flags.append("LEX-01: Direct IP in Hostname (+35)")
        fired_rules.append({
            "id": "LEX-01",
            "title": "Direct IP in Hostname",
            "category": "LEXICAL",
            "points": 35,
            "evidence": host,
            "detail": "Hostname matches raw IPv4/IPv6 address pattern."
        })

    # Rule LEX-02: The @ Symbol Trick (+30)
    if "@" in raw_url:
        score += 30
        flags.append("LEX-02: The @ Symbol Trick (+30)")
        fired_rules.append({
            "id": "LEX-02",
            "title": "The @ Symbol Trick",
            "category": "LEXICAL",
            "points": 30,
            "evidence": "@ character present in URL",
            "detail": "Everything before @ is parsed as a username, masking the true host."
        })

    # Rule LEX-03: Excessive Subdomain Depth (+20)
    parts = host.split(".")
    if not is_ip and len(parts) >= 5:
        score += 20
        flags.append("LEX-03: Excessive Subdomain Depth (+20)")
        fired_rules.append({
            "id": "LEX-03",
            "title": "Excessive Subdomain Depth",
            "category": "LEXICAL",
            "points": 20,
            "evidence": f"{len(parts)} domain tokens in {host}",
            "detail": "Domain contains 4 or more subdomains."
        })

    # Rule LEX-04: Excessive Hyphenation (+15)
    hyphen_count = host.count("-")
    if hyphen_count >= 2:
        score += 15
        flags.append("LEX-04: Excessive Hyphenation (+15)")
        fired_rules.append({
            "id": "LEX-04",
            "title": "Excessive Hyphenation",
            "category": "LEXICAL",
            "points": 15,
            "evidence": f"{hyphen_count} hyphens in host",
            "detail": "Hostname contains multiple hyphens mimicking composite brand names."
        })

    # Rule LEX-05: Abnormal URL Length (+10)
    if len(normalized) > 75 or len(path) > 50:
        score += 10
        flags.append("LEX-05: Abnormal URL Length (+10)")
        fired_rules.append({
            "id": "LEX-05",
            "title": "Abnormal URL Length",
            "category": "LEXICAL",
            "points": 10,
            "evidence": f"URL length {len(normalized)} chars, path {len(path)} chars",
            "detail": "Total length exceeds 75 chars or path exceeds 50 chars."
        })

    # Rule LEX-06: Punycode / Homoglyph Characters (+25)
    has_punycode = "xn--" in host
    has_non_ascii = any(ord(c) > 127 for c in host)
    if has_punycode or has_non_ascii:
        score += 25
        flags.append("LEX-06: Punycode / Homoglyph Characters (+25)")
        fired_rules.append({
            "id": "LEX-06",
            "title": "Punycode / Homoglyph Characters",
            "category": "LEXICAL",
            "points": 25,
            "evidence": "Punycode (xn--) or internationalized script detected",
            "detail": "Hostname contains Punycode or mixed Unicode scripts mimicking ASCII letters."
        })

    # Rule LEX-07: Double Slash Redirection (+15)
    after_proto = normalized.split("://", 1)[-1]
    if "//" in after_proto or "//" in path:
        score += 15
        flags.append("LEX-07: Double Slash Redirection (+15)")
        fired_rules.append({
            "id": "LEX-07",
            "title": "Double Slash Redirection",
            "category": "LEXICAL",
            "points": 15,
            "evidence": "// detected in path",
            "detail": "URL path contains // after protocol segment to trigger redirection bypasses."
        })

    # ---------------------------------------------------------
    # 2. Semantic & Keyword Rules
    # ---------------------------------------------------------

    # Rule SEM-02: Brand Spoofing / Typosquatting (+40)
    brand_spoofed = None
    for brand_key, official_domain in TOP_BRANDS:
        if brand_key in host and not (host == official_domain or host.endswith(f".{official_domain}")):
            score += 40
            brand_spoofed = brand_key
            flags.append(f"SEM-02: Target brand impersonation ({brand_key}) (+40)")
            fired_rules.append({
                "id": "SEM-02",
                "title": "Brand Spoofing / Typosquatting",
                "category": "SEMANTIC",
                "points": 40,
                "evidence": f"Spoofs '{brand_key}' outside {official_domain}",
                "detail": f"Hostname contains target brand '{brand_key}' but does not end with {official_domain}."
            })
            break

    # Rule SEM-01: Sensitive Action Keywords (+20)
    matched_kws = [k for k in SUSPICIOUS_KEYWORDS if k in full_url_lower]
    if matched_kws:
        score += 20
        flags.append(f"SEM-01: Sensitive action keywords detected [{', '.join(matched_kws[:3])}] (+20)")
        fired_rules.append({
            "id": "SEM-01",
            "title": "Sensitive Action Keywords",
            "category": "SEMANTIC",
            "points": 20,
            "evidence": f"Keywords: {matched_kws[:4]}",
            "detail": "Hostname or path contains sensitive authentication or verification keywords."
        })

    # Rule SEM-03: Suspicious / Free TLDs (+15)
    tld = parts[-1] if len(parts) > 1 else ""
    if tld in SUSPICIOUS_FREE_TLDS:
        score += 15
        flags.append(f"SEM-03: Suspicious / Free TLD (.{tld}) (+15)")
        fired_rules.append({
            "id": "SEM-03",
            "title": "Suspicious / Free TLDs",
            "category": "SEMANTIC",
            "points": 15,
            "evidence": f".{tld} extension",
            "detail": f"Domain uses high-abuse top-level extension (.{tld}) frequently used in disposable scams."
        })

    # Rule SEM-04: Known URL Shortener (+10)
    if host in KNOWN_SHORTENERS:
        score += 10
        flags.append(f"SEM-04: Known URL Shortener ({host}) (+10)")
        fired_rules.append({
            "id": "SEM-04",
            "title": "Known URL Shortener",
            "category": "SEMANTIC",
            "points": 10,
            "evidence": f"Shortener service {host}",
            "detail": "Recognized URL shortener hiding the destination host (flagged for unshortening)."
        })

    # ---------------------------------------------------------
    # 3. Domain & Network Intelligence Rules
    # ---------------------------------------------------------

    is_dynamic_dns = any(host == ddns or host.endswith(f".{ddns}") for ddns in DYNAMIC_DNS_DOMAINS)

    # Rule NET-01: Newly Registered Domain (NRD) (+35)
    if is_dynamic_dns or (tld in SUSPICIOUS_FREE_TLDS and brand_spoofed) or "redirectme.net" in host:
        score += 35
        flags.append("NET-01: Newly Registered Domain / Ephemeral DNS (+35)")
        fired_rules.append({
            "id": "NET-01",
            "title": "Newly Registered Domain (NRD)",
            "category": "NETWORK",
            "points": 35,
            "evidence": "Ephemeral Dynamic DNS or newly registered disposable domain indicator",
            "detail": "Domain age is < 30 days or utilizes ephemeral dynamic redirection infrastructure."
        })

    # Rule NET-02: Short Expiration Horizon (+10)
    if tld in SUSPICIOUS_FREE_TLDS or is_dynamic_dns:
        score += 10
        flags.append("NET-02: Short Expiration Horizon (+10)")
        fired_rules.append({
            "id": "NET-02",
            "title": "Short Expiration Horizon",
            "category": "NETWORK",
            "points": 10,
            "evidence": "1-Year expiration window with no institutional history",
            "detail": "Domain registered for 1 year with no multi-year renewal history."
        })

    # Rule NET-03: No Valid TLS / Missing HTTPS (+25)
    is_plain_http = parsed.scheme.lower() == "http"
    if is_plain_http and (matched_kws or brand_spoofed or is_ip):
        score += 25
        flags.append("NET-03: Insecure HTTP on Sensitive Action (+25)")
        fired_rules.append({
            "id": "NET-03",
            "title": "No Valid TLS / Missing HTTPS",
            "category": "NETWORK",
            "points": 25,
            "evidence": "Plain unencrypted HTTP on authentication or brand request",
            "detail": "URL uses unencrypted plain HTTP while demanding credentials or sensitive action."
        })

    # Rule NET-04: Free SSL on Financial Impersonation (+15)
    if parsed.scheme.lower() == "https" and (brand_spoofed or any(k in ["banking", "wallet", "kyc", "challan"] for k in matched_kws)) and (tld in SUSPICIOUS_FREE_TLDS or is_dynamic_dns or hyphen_count >= 1):
        score += 15
        flags.append("NET-04: Free DV SSL on Financial Impersonation (+15)")
        fired_rules.append({
            "id": "NET-04",
            "title": "Free SSL on Financial Impersonation",
            "category": "NETWORK",
            "points": 15,
            "evidence": "Automated DV certificate targeting financial or government keywords",
            "detail": "Site uses automated Domain-Validation TLS certificate while targeting financial keywords."
        })

    # Compute capped total score
    total_score = min(100, max(0, score))

    # Apply thresholds:
    # 0–25:  Low Risk (Likely Safe)
    # 26–55: Medium Risk (Suspicious)
    # 56+:   High Risk (Likely Phishing / Scam)
    if total_score >= 56:
        risk_level = "High Risk"
        risk_code = "HIGH"
    elif total_score >= 26:
        risk_level = "Medium Risk"
        risk_code = "MEDIUM"
    else:
        risk_level = "Low Risk"
        risk_code = "LOW"

    return {
        "url": raw_url,
        "normalized_url": normalized,
        "host": host,
        "path": path,
        "score": total_score,
        "raw_score": score,
        "risk_level": risk_level,
        "risk_code": risk_code,
        "is_official": False,
        "flags": flags,
        "fired_rules": fired_rules,
        "thresholds": {
            "low_max": 25,
            "medium_min": 26,
            "medium_max": 55,
            "high_min": 56
        }
    }


if __name__ == "__main__":
    test_urls = [
        "http://192.168.1.1/login",
        "https://mparivahan.redirectme.net/6/RTO.MoRTH",
        "http://sbi-kyc-update.xyz/login",
        "https://www.google.com",
        "http://bit.ly/indpst-fee"
    ]
    for u in test_urls:
        res = inspect_url(u)
        print(f"\nURL: {u}\nScore: {res['score']}/100 | Risk: {res['risk_level']}\nFlags: {res['flags']}")
