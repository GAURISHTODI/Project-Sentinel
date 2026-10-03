"""Lexical features computed from the URL string alone.

Shared by training and live detection so both see identical features. Input is untrusted: it is
length-capped before parsing, and anything unparseable yields a features dict with `invalid` set
rather than raising.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

MAX_URL_CHARS = 2048
_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "num_dots", "num_hyphens", "num_digits",
    "digit_ratio", "num_special", "special_ratio", "num_subdomains", "tld_len", "is_ip_host",
    "has_https", "has_at", "has_port", "num_eq", "num_qmark", "num_amp", "num_pct", "path_depth",
    "entropy_url", "entropy_host", "longest_host_token", "has_www", "invalid",
]  # fmt: skip


def host_of(raw: str) -> str:
    try:
        text = raw[:MAX_URL_CHARS].strip()
        return (urlsplit(text if "://" in text else f"http://{text}").hostname or "").lower()
    except ValueError:
        return ""


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def url_features(raw: str) -> dict[str, float]:
    url = raw[:MAX_URL_CHARS].strip()
    try:
        parsed = urlsplit(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        port_given = parsed.port is not None
    except ValueError:
        return {name: 0.0 for name in FEATURE_NAMES} | {"invalid": 1.0}

    labels = [p for p in host.split(".") if p]
    tld = labels[-1] if len(labels) > 1 else ""
    is_ip = bool(_IPV4.fullmatch(host))
    digits = sum(ch.isdigit() for ch in url)
    specials = sum(not ch.isalnum() and ch not in ":/." for ch in url)
    n = max(len(url), 1)
    path = parsed.path
    return {
        "url_len": float(len(url)),
        "host_len": float(len(host)),
        "path_len": float(len(path)),
        "query_len": float(len(parsed.query)),
        "num_dots": float(url.count(".")),
        "num_hyphens": float(host.count("-")),
        "num_digits": float(digits),
        "digit_ratio": digits / n,
        "num_special": float(specials),
        "special_ratio": specials / n,
        "num_subdomains": float(max(len(labels) - 2, 0)),
        "tld_len": float(len(tld)),
        "is_ip_host": float(is_ip),
        "has_https": float(parsed.scheme == "https"),
        "has_at": float("@" in url),
        "has_port": float(port_given),
        "num_eq": float(url.count("=")),
        "num_qmark": float(url.count("?")),
        "num_amp": float(url.count("&")),
        "num_pct": float(url.count("%")),
        "path_depth": float(path.strip("/").count("/") + 1 if path.strip("/") else 0),
        "entropy_url": shannon_entropy(url),
        "entropy_host": shannon_entropy(host),
        "longest_host_token": float(max((len(t) for t in re.split(r"[.-]", host)), default=0)),
        "has_www": float(host.startswith("www.")),
        "invalid": 0.0,
    }
