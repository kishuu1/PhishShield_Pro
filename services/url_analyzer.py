"""
PhishShield Pro — Explainable URL Analyzer Service

Analyzes submitted URLs using explainable heuristic-based detection rules
and checks against local threat intelligence indicators.
NEVER makes network connections or fetches submitted URLs.
"""

import ipaddress
import re
from urllib.parse import urlparse, unquote

# ---------------------------------------------------------------------------
# Constants & Heuristic Reference Lists
# ---------------------------------------------------------------------------

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "signin", "credential",
    "wallet", "authenticate", "validation", "support-billing"
]

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "short.io",
    "tiny.cc", "cutt.ly"
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".buzz", ".club", ".work",
    ".country", ".kim", ".stream", ".gdn"
}

DISCLAIMER = (
    "This score is an explainable heuristic indicator based on static URL characteristics. "
    "It does not guarantee that a URL is definitely safe or definitely malicious. "
    "Always exercise caution and verify identity before entering credentials."
)

_HEX_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")


# ---------------------------------------------------------------------------
# Individual Heuristic Checkers
# ---------------------------------------------------------------------------

def _is_ip_host(hostname: str) -> bool:
    """Check if the hostname is an IPv4 or IPv6 address instead of a domain name."""
    if not hostname:
        return False
    # Strip brackets if IPv6
    clean_host = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def _has_suspicious_keywords(url_lower: str) -> tuple[bool, list[str]]:
    """Detect presence of common phishing/credential harvesting keywords."""
    found = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    return bool(found), found


def _has_excessive_subdomains(hostname: str) -> tuple[bool, int]:
    """Detect excessive subdomains (more than 3 dot-separated labels)."""
    if not hostname or _is_ip_host(hostname):
        return False, 0
    dot_count = hostname.count(".")
    return dot_count > 3, dot_count


def _has_at_symbol(url: str) -> bool:
    """Detect '@' in URL, often used to obscure genuine destinations in HTTP auth."""
    return "@" in url


def _is_url_shortener(hostname: str) -> bool:
    """Check if URL uses a known URL shortening service."""
    if not hostname:
        return False
    return hostname.lower() in KNOWN_SHORTENERS


def _is_long_url(url: str) -> tuple[bool, int]:
    """Check if URL length exceeds typical threshold (75 characters)."""
    return len(url) > 75, len(url)


def _is_insecure_http(scheme: str) -> bool:
    """Check if scheme is plain HTTP rather than encrypted HTTPS."""
    return scheme.lower() == "http"


def _has_suspicious_tld(hostname: str) -> tuple[bool, str]:
    """Check if the TLD belongs to historically abuse-prone top-level domains."""
    if not hostname or _is_ip_host(hostname):
        return False, ""
    host_lower = hostname.lower()
    for tld in SUSPICIOUS_TLDS:
        if host_lower.endswith(tld):
            return True, tld
    return False, ""


def _has_double_slashes_in_path(path: str) -> bool:
    """Detect '//' in the URL path, commonly used in open-redirect attacks."""
    return "//" in path


def _has_hex_encoded_chars(url: str) -> tuple[bool, int]:
    """Detect hex-encoded (%xx) characters used to obfuscate URLs."""
    matches = _HEX_ENCODED_RE.findall(url)
    return bool(matches), len(matches)


# ---------------------------------------------------------------------------
# Public Analysis API
# ---------------------------------------------------------------------------

def normalize_url(raw_url: str) -> tuple[str, str]:
    """
    Validates and normalizes raw URL.
    Returns (cleaned_url, normalized_url).
    """
    trimmed = raw_url.strip()
    if not trimmed:
        return "", ""

    # Add default http scheme if missing for parsing
    if not re.match(r"^https?://", trimmed, re.IGNORECASE):
        cleaned_url = "http://" + trimmed
    else:
        cleaned_url = trimmed

    parsed = urlparse(cleaned_url)
    normalized = parsed.geturl()
    return cleaned_url, normalized


def analyze_url(url: str, rules: list, threat_indicators: list = None) -> dict:
    """
    Analyzes a URL against heuristic rules and optional local threat intelligence.

    Parameters:
    -----------
    url : str
        The raw URL submitted by the user.
    rules : list[dict]
        Active detection rules loaded from MongoDB detection_rules collection.
    threat_indicators : list[dict], optional
        Active indicators loaded from MongoDB threat_intelligence collection.

    Returns:
    --------
    dict
        Structured analysis containing risk_score, risk_level, triggered_rules,
        threat_intel_matches, analysis_details, and disclaimer.
    """
    trimmed = url.strip()
    if not trimmed:
        return _empty_result(url)

    cleaned_url, normalized_url = normalize_url(trimmed)
    parsed = urlparse(cleaned_url)

    hostname = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    path = parsed.path or ""
    url_lower = cleaned_url.lower()

    # Rule weights map from database
    rule_map = {}
    for r in rules:
        r_id = r.get("rule_id")
        if r_id and r.get("enabled", True):
            rule_map[r_id] = {
                "name": r.get("name") or r.get("rule_name") or r_id,
                "weight": int(r.get("weight", 0)),
                "description": r.get("description", "")
            }

    triggered_rules = []
    total_score = 0

    # 1. IP Address as Host
    if "ip_address_host" in rule_map and _is_ip_host(hostname):
        w = rule_map["ip_address_host"]["weight"]
        triggered_rules.append({
            "rule_id": "ip_address_host",
            "rule_name": rule_map["ip_address_host"]["name"],
            "description": f"URL uses raw IP address '{hostname}' instead of a registered domain name.",
            "weight": w
        })
        total_score += w

    # 2. Suspicious Keywords
    if "suspicious_keywords" in rule_map:
        has_kw, found_kws = _has_suspicious_keywords(url_lower)
        if has_kw:
            w = rule_map["suspicious_keywords"]["weight"]
            triggered_rules.append({
                "rule_id": "suspicious_keywords",
                "rule_name": rule_map["suspicious_keywords"]["name"],
                "description": f"URL contains suspicious credential-harvesting keyword(s): {', '.join(found_kws[:4])}.",
                "weight": w
            })
            total_score += w

    # 3. Excessive Subdomains
    if "excessive_subdomains" in rule_map:
        has_sub, dot_count = _has_excessive_subdomains(hostname)
        if has_sub:
            w = rule_map["excessive_subdomains"]["weight"]
            triggered_rules.append({
                "rule_id": "excessive_subdomains",
                "rule_name": rule_map["excessive_subdomains"]["name"],
                "description": f"Hostname contains {dot_count} dots, indicating abnormal subdomain nesting.",
                "weight": w
            })
            total_score += w

    # 4. At Symbol in URL
    if "at_symbol" in rule_map and _has_at_symbol(cleaned_url):
        w = rule_map["at_symbol"]["weight"]
        triggered_rules.append({
            "rule_id": "at_symbol",
            "rule_name": rule_map["at_symbol"]["name"],
            "description": "URL contains '@' symbol, which ignores preceding userinfo and redirects to following host.",
            "weight": w
        })
        total_score += w

    # 5. URL Shortener
    if "url_shortener" in rule_map and _is_url_shortener(hostname):
        w = rule_map["url_shortener"]["weight"]
        triggered_rules.append({
            "rule_id": "url_shortener",
            "rule_name": rule_map["url_shortener"]["name"],
            "description": f"URL relies on link shortener '{hostname}', which obscures the final landing destination.",
            "weight": w
        })
        total_score += w

    # 6. Long URL
    if "long_url" in rule_map:
        is_long, u_len = _is_long_url(cleaned_url)
        if is_long:
            w = rule_map["long_url"]["weight"]
            triggered_rules.append({
                "rule_id": "long_url",
                "rule_name": rule_map["long_url"]["name"],
                "description": f"URL is unusually long ({u_len} characters; threshold > 75).",
                "weight": w
            })
            total_score += w

    # 7. Insecure HTTP
    if "insecure_http" in rule_map and _is_insecure_http(scheme):
        w = rule_map["insecure_http"]["weight"]
        triggered_rules.append({
            "rule_id": "insecure_http",
            "rule_name": rule_map["insecure_http"]["name"],
            "description": "URL uses unencrypted HTTP protocol without TLS/SSL certificate encryption.",
            "weight": w
        })
        total_score += w

    # 8. Suspicious TLD
    if "suspicious_tld" in rule_map:
        has_tld, tld_str = _has_suspicious_tld(hostname)
        if has_tld:
            w = rule_map["suspicious_tld"]["weight"]
            triggered_rules.append({
                "rule_id": "suspicious_tld",
                "rule_name": rule_map["suspicious_tld"]["name"],
                "description": f"URL uses TLD '{tld_str}', known for frequent abuse and low registration costs.",
                "weight": w
            })
            total_score += w

    # 9. Double Slashes in Path
    if "double_slashes_in_path" in rule_map and _has_double_slashes_in_path(path):
        w = rule_map["double_slashes_in_path"]["weight"]
        triggered_rules.append({
            "rule_id": "double_slashes_in_path",
            "rule_name": rule_map["double_slashes_in_path"]["name"],
            "description": "Path contains '//' redirection pattern, often used to bypass path-based security filters.",
            "weight": w
        })
        total_score += w

    # 10. Hex-Encoded Characters
    if "hex_encoded_chars" in rule_map:
        has_hex, hex_count = _has_hex_encoded_chars(cleaned_url)
        if has_hex:
            w = rule_map["hex_encoded_chars"]["weight"]
            triggered_rules.append({
                "rule_id": "hex_encoded_chars",
                "rule_name": rule_map["hex_encoded_chars"]["name"],
                "description": f"URL contains {hex_count} hex-encoded (%xx) characters designed to evade textual pattern matching.",
                "weight": w
            })
            total_score += w

    # Check Local Threat Intelligence Repository
    threat_intel_matches = []
    if threat_indicators:
        for ind in threat_indicators:
            val = (ind.get("indicator") or "").strip().lower()
            if not val:
                continue
            itype = (ind.get("indicator_type") or ind.get("type") or "domain").lower()
            severity = (ind.get("severity") or "medium").capitalize()
            desc = ind.get("description", "Known suspicious entity")

            matched = False
            if itype == "domain" and (hostname == val or hostname.endswith("." + val)):
                matched = True
            elif itype == "ip" and hostname == val:
                matched = True
            elif itype == "keyword" and val in url_lower:
                matched = True

            if matched:
                threat_intel_matches.append({
                    "indicator": val,
                    "type": itype,
                    "severity": severity,
                    "description": desc,
                    "feed": "Local Threat Repository (User-Maintained, Non-External Feed)"
                })

        if threat_intel_matches:
            ti_weight = 40
            triggered_rules.append({
                "rule_id": "local_threat_intel_match",
                "rule_name": "Local Threat Intelligence Hit",
                "description": f"Matched {len(threat_intel_matches)} indicator(s) in local repository: " +
                               ", ".join([m["indicator"] for m in threat_intel_matches[:3]]) +
                               ". [Source: Local user-maintained indicators, not an external threat feed].",
                "weight": ti_weight
            })
            total_score += ti_weight

    # Calculate bounded score (0 - 100)
    risk_score = min(total_score, 100)

    # Risk level classification
    if risk_score <= 33:
        risk_level = "Low"
    elif risk_score <= 66:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return {
        "url": url,
        "normalized_url": normalized_url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "triggered_rules": triggered_rules,
        "threat_intel_matches": threat_intel_matches,
        "analysis_details": {
            "hostname": hostname,
            "scheme": scheme,
            "path": path,
            "port": parsed.port,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "length": len(cleaned_url)
        },
        "disclaimer": DISCLAIMER
    }


def _empty_result(url: str) -> dict:
    """Return a baseline zero-risk result for an empty URL."""
    return {
        "url": url,
        "normalized_url": "",
        "risk_score": 0,
        "risk_level": "Low",
        "triggered_rules": [],
        "threat_intel_matches": [],
        "analysis_details": {
            "hostname": "",
            "scheme": "",
            "path": "",
            "port": None,
            "query": "",
            "fragment": "",
            "length": 0
        },
        "disclaimer": DISCLAIMER
    }
