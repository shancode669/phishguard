"""
features.py
Extracts numerical features from a URL for phishing detection.
Each function returns -1 (phishing signal), 0 (neutral), or 1 (legitimate signal).
"""

import re
import urllib.parse


def get_features(url: str) -> dict:
    """Extract all features from a URL and return as a dict."""
    features = {}

    features["has_ip"]              = has_ip(url)
    features["url_length"]          = url_length(url)
    features["has_shortening"]      = has_shortening_service(url)
    features["has_at_symbol"]       = has_at_symbol(url)
    features["double_slash_redirect"]= double_slash_redirect(url)
    features["has_dash_in_domain"]  = has_dash_in_domain(url)
    features["subdomain_count"]     = subdomain_count(url)
    features["has_https"]           = has_https(url)
    features["domain_length"]       = domain_length(url)
    features["has_port"]            = has_port(url)
    features["https_in_domain"]     = https_in_domain_name(url)
    features["slash_count"]         = slash_count(url)
    features["has_query_string"]    = has_query_string(url)
    features["has_anchor"]          = has_anchor(url)
    features["suspicious_words"]    = suspicious_words(url)
    features["digit_ratio"]         = digit_ratio(url)
    features["special_char_count"]  = special_char_count(url)

    return features


def features_to_list(features: dict) -> list:
    """Convert features dict to ordered list for model input."""
    return list(features.values())


# ── INDIVIDUAL FEATURE FUNCTIONS ──────────────────────────────────────────────

def has_ip(url: str) -> int:
    """Check if URL uses an IP address instead of a domain name."""
    ip_pattern = re.compile(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    )
    return -1 if ip_pattern.search(url) else 1


def url_length(url: str) -> int:
    """Phishing URLs tend to be longer."""
    l = len(url)
    if l < 54:
        return 1
    elif l <= 75:
        return 0
    else:
        return -1


def has_shortening_service(url: str) -> int:
    """Check for known URL shortening services."""
    shorteners = [
        "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co",
        "ow.ly", "t.co", "tinyurl.com", "tr.im", "is.gd",
        "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc",
        "url4.eu", "twit.ac", "su.pr", "twurl.nl", "snipurl.com"
    ]
    return -1 if any(s in url for s in shorteners) else 1


def has_at_symbol(url: str) -> int:
    """@ symbol in URL forces browser to ignore everything before it."""
    return -1 if "@" in url else 1


def double_slash_redirect(url: str) -> int:
    """Check for // redirect after the protocol."""
    pos = url.rfind("//")
    return -1 if pos > 6 else 1


def has_dash_in_domain(url: str) -> int:
    """Dashes in domain name are a common phishing trick."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        return -1 if "-" in domain else 1
    except Exception:
        return 0


def subdomain_count(url: str) -> int:
    """More subdomains = more suspicious."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        dots = domain.count(".")
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        else:
            return -1
    except Exception:
        return 0


def has_https(url: str) -> int:
    """Legitimate sites usually use HTTPS."""
    return 1 if url.startswith("https://") else -1


def domain_length(url: str) -> int:
    """Longer domain names are more suspicious."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        l = len(domain)
        if l < 20:
            return 1
        elif l <= 35:
            return 0
        else:
            return -1
    except Exception:
        return 0


def has_port(url: str) -> int:
    """Non-standard port in URL is suspicious."""
    try:
        port = urllib.parse.urlparse(url).port
        return -1 if port and port not in (80, 443) else 1
    except Exception:
        return 1


def https_in_domain_name(url: str) -> int:
    """Phishers sometimes put 'https' in the domain name itself."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        return -1 if "https" in domain else 1
    except Exception:
        return 1


def slash_count(url: str) -> int:
    """Too many slashes can indicate a deep redirect path."""
    count = url.count("/")
    if count <= 4:
        return 1
    elif count <= 6:
        return 0
    else:
        return -1


def has_query_string(url: str) -> int:
    """Query strings aren't inherently bad but common in phishing."""
    try:
        query = urllib.parse.urlparse(url).query
        return 0 if query else 1
    except Exception:
        return 1


def has_anchor(url: str) -> int:
    """Anchors (#) used to hide the real destination."""
    return -1 if "#" in url else 1


def suspicious_words(url: str) -> int:
    """Check for commonly used phishing keywords."""
    keywords = [
        "login", "signin", "verify", "update", "secure", "account",
        "banking", "confirm", "password", "credential", "suspend",
        "unusual", "access", "wallet", "free", "lucky", "winner",
        "click", "urgent", "alert", "limited", "offer"
    ]
    url_lower = url.lower()
    count = sum(1 for k in keywords if k in url_lower)
    if count == 0:
        return 1
    elif count == 1:
        return 0
    else:
        return -1


def digit_ratio(url: str) -> int:
    """High ratio of digits in domain = suspicious."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        if not domain:
            return 0
        ratio = sum(c.isdigit() for c in domain) / len(domain)
        if ratio < 0.1:
            return 1
        elif ratio < 0.3:
            return 0
        else:
            return -1
    except Exception:
        return 0


def special_char_count(url: str) -> int:
    """Count special characters that don't belong in clean URLs."""
    specials = re.findall(r'[!$&\'()*+,;=~`|^{}\\<>]', url)
    count = len(specials)
    if count == 0:
        return 1
    elif count <= 2:
        return 0
    else:
        return -1
