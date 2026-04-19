from __future__ import annotations

import datetime as dt
import re
import socket
import urllib
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from urllib.parse import urljoin, urlparse

import numpy as np
import requests
import tldextract
import whois
from bs4 import BeautifulSoup


SHORTENER_DOMAINS = {
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "adf.ly",
    "cutt.ly",
    "tiny.cc",
    "shorturl.at",
    "rebrand.ly",
}

_IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")


def _normalize_url(url: str) -> str:
    candidate = (url or "").strip()
    if not candidate:
        raise ValueError("URL is required.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"http://{candidate}"
    return candidate


def _safe_hostname(parsed) -> str:
    return (parsed.hostname or "").lower().strip(".")


def _registered_domain_from_host(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if not ext.domain:
        return hostname
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return ext.domain.lower()


def _registered_domain_from_url(raw_url: str) -> str:
    try:
        parsed = urlparse(raw_url)
        return _registered_domain_from_host(_safe_hostname(parsed))
    except Exception:
        return ""


def _is_external_url(raw_target: str, base_registered_domain: str) -> bool:
    if not raw_target:
        return True
    target = raw_target.strip().lower()
    if target in {"#", "#content", "#skip", "javascript:void(0)", "javascript:;"}:
        return True
    if target.startswith(("javascript:", "mailto:")):
        return True

    parsed = urlparse(target)
    if not parsed.netloc:
        return False
    return _registered_domain_from_host(parsed.hostname or "") != base_registered_domain


def _safe_get(url: str, timeout: int = 3):
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecureShieldAI/1.0)"},
        )
        return response, None
    except Exception as exc:
        return None, exc


def _safe_whois(hostname: str, timeout: int = 3):
    def _runner():
        return whois.whois(hostname)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(_runner).result(timeout=timeout)
        return result, None
    except TimeoutError as exc:
        return None, exc
    except Exception as exc:
        return None, exc


def _safe_datetime(value):
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, dt.datetime):
        return value
    if isinstance(value, dt.date):
        return dt.datetime.combine(value, dt.time.min)
    return None


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return (numerator / denominator) * 100.0


def _is_ip_address(hostname: str) -> bool:
    if _IPV4_PATTERN.match(hostname):
        return True
    if ":" in hostname and _IPV6_PATTERN.match(hostname):
        return True
    return False


def extract_features(url: str) -> np.ndarray:
    """Return UCI-style 30 features with values in {-1, 1}, shape (1, 30)."""
    features = np.ones(30, dtype=int)

    try:
        normalized_url = _normalize_url(url)
    except Exception:
        return (-1 * np.ones((1, 30), dtype=int))

    parsed = urlparse(normalized_url)
    hostname = _safe_hostname(parsed)
    registered_domain = _registered_domain_from_host(hostname)
    lower_url = normalized_url.lower()

    # Network data (best effort)
    response, response_error = _safe_get(normalized_url, timeout=3)
    html = response.text if response is not None else ""
    soup = BeautifulSoup(html, "html.parser") if html else None

    whois_data, whois_error = _safe_whois(hostname, timeout=3)
    dns_ok = True
    try:
        socket.gethostbyname(hostname)
    except Exception:
        dns_ok = False

    creation_date = _safe_datetime(getattr(whois_data, "creation_date", None)) if whois_data is not None else None
    expiration_date = _safe_datetime(getattr(whois_data, "expiration_date", None)) if whois_data is not None else None
    whois_domain = (getattr(whois_data, "domain_name", "") if whois_data is not None else "")
    if isinstance(whois_domain, list) and whois_domain:
        whois_domain = whois_domain[0]
    whois_domain = (str(whois_domain).lower() if whois_domain else "")

    # ---------------- Group 1: URL structure (0..11) ----------------
    try:  # [0] having_IP_Address
        features[0] = -1 if _is_ip_address(hostname) else 1
    except Exception:
        features[0] = -1

    try:  # [1] URL_Length
        features[1] = -1 if len(normalized_url) >= 54 else 1
    except Exception:
        features[1] = -1

    try:  # [2] Shortining_Service
        features[2] = -1 if any(hostname == d or hostname.endswith(f".{d}") for d in SHORTENER_DOMAINS) else 1
    except Exception:
        features[2] = -1

    try:  # [3] having_At_Symbol
        features[3] = -1 if "@" in normalized_url else 1
    except Exception:
        features[3] = -1

    try:  # [4] double_slash_redirect
        features[4] = -1 if normalized_url.rfind("//") > 7 else 1
    except Exception:
        features[4] = -1

    try:  # [5] Prefix_Suffix
        features[5] = -1 if "-" in hostname else 1
    except Exception:
        features[5] = -1

    try:  # [6] having_Sub_Domain
        ext = tldextract.extract(hostname)
        sub = ext.subdomain or ""
        sub_parts = [s for s in sub.split(".") if s and s.lower() != "www"]
        features[6] = -1 if len(sub_parts) >= 2 else 1
    except Exception:
        features[6] = -1

    try:  # [7] SSLfinal_State
        features[7] = 1 if parsed.scheme.lower() == "https" else -1
    except Exception:
        features[7] = -1

    try:  # [8] Domain_registeration_length
        if expiration_date is None:
            features[8] = -1
        else:
            remaining_days = (expiration_date - dt.datetime.utcnow()).days
            features[8] = -1 if remaining_days < 365 else 1
    except Exception:
        features[8] = -1

    try:  # [9] Favicon
        if soup is None:
            features[9] = -1
        else:
            favicons = soup.find_all("link", rel=lambda v: v and "icon" in str(v).lower())
            external_found = False
            for tag in favicons:
                href = (tag.get("href") or "").strip()
                if not href:
                    continue
                full = urljoin(normalized_url, href)
                if _is_external_url(full, registered_domain):
                    external_found = True
                    break
            features[9] = -1 if external_found else 1
    except Exception:
        features[9] = -1

    try:  # [10] port
        port = parsed.port
        features[10] = -1 if (port is not None and port not in (80, 443)) else 1
    except Exception:
        features[10] = -1

    try:  # [11] HTTPS_token
        features[11] = -1 if "https" in hostname else 1
    except Exception:
        features[11] = -1

    # --------------- Group 2: Request & HTML signals (12..22) ---------------
    try:  # [12] Request_URL
        if soup is None:
            features[12] = -1
        else:
            media_tags = soup.find_all(["img", "video", "audio", "source", "embed", "iframe"])
            total = len(media_tags)
            external = 0
            for tag in media_tags:
                src = (tag.get("src") or "").strip()
                if src and _is_external_url(urljoin(normalized_url, src), registered_domain):
                    external += 1
            features[12] = -1 if _ratio(external, total) >= 22 else 1
    except Exception:
        features[12] = -1

    try:  # [13] URL_of_Anchor
        if soup is None:
            features[13] = -1
        else:
            anchors = soup.find_all("a")
            total = len(anchors)
            suspicious = 0
            for a in anchors:
                href = (a.get("href") or "").strip()
                if _is_external_url(urljoin(normalized_url, href), registered_domain):
                    suspicious += 1
            features[13] = -1 if _ratio(suspicious, total) >= 31 else 1
    except Exception:
        features[13] = -1

    try:  # [14] Links_in_tags
        if soup is None:
            features[14] = -1
        else:
            tags = soup.find_all(["meta", "script", "link"])
            total = 0
            external = 0
            for tag in tags:
                ref = (tag.get("src") or tag.get("href") or tag.get("content") or "").strip()
                if not ref:
                    continue
                total += 1
                full = urljoin(normalized_url, ref)
                if _is_external_url(full, registered_domain):
                    external += 1
            features[14] = -1 if _ratio(external, total) >= 17 else 1
    except Exception:
        features[14] = -1

    try:  # [15] SFH
        if soup is None:
            features[15] = -1
        else:
            forms = soup.find_all("form")
            suspicious = False
            for form in forms:
                action = (form.get("action") or "").strip().lower()
                if action in {"", "about:blank"}:
                    suspicious = True
                    break
                if action.startswith("mailto:"):
                    suspicious = True
                    break
                if _is_external_url(urljoin(normalized_url, action), registered_domain):
                    suspicious = True
                    break
            features[15] = -1 if suspicious else 1
    except Exception:
        features[15] = -1

    try:  # [16] Submitting_to_email
        if not html:
            features[16] = -1
        else:
            source = html.lower()
            features[16] = -1 if ("mailto:" in source or "mail()" in source) else 1
    except Exception:
        features[16] = -1

    try:  # [17] Abnormal_URL
        if whois_error is not None or not whois_domain:
            features[17] = -1
        else:
            features[17] = -1 if _registered_domain_from_url(whois_domain) != registered_domain else 1
    except Exception:
        features[17] = -1

    try:  # [18] Redirect
        if response is None:
            features[18] = -1
        else:
            redirects = len(response.history)
            features[18] = -1 if redirects >= 2 else 1
    except Exception:
        features[18] = -1

    try:  # [19] on_mouseover
        if not html:
            features[19] = -1
        else:
            features[19] = -1 if "window.status" in html.lower() else 1
    except Exception:
        features[19] = -1

    try:  # [20] RightClick
        if not html:
            features[20] = -1
        else:
            source = html.lower().replace(" ", "")
            features[20] = -1 if ("event.button==2" in source or "oncontextmenu" in source) else 1
    except Exception:
        features[20] = -1

    try:  # [21] popUpWidnow
        if not html:
            features[21] = -1
        else:
            features[21] = -1 if "prompt(" in html.lower() else 1
    except Exception:
        features[21] = -1

    try:  # [22] Iframe
        if soup is None:
            features[22] = -1
        else:
            suspicious_iframe = False
            for frame in soup.find_all("iframe"):
                frameborder = str(frame.get("frameborder", "")).strip().lower()
                style = str(frame.get("style", "")).strip().lower()
                if frameborder in {"", "0"} or "border:0" in style or "border:none" in style:
                    suspicious_iframe = True
                    break
            features[22] = -1 if suspicious_iframe else 1
    except Exception:
        features[22] = -1

    # ------------ Group 3: Domain & network signals (23..29) ------------
    try:  # [23] age_of_domain
        if creation_date is None:
            features[23] = -1
        else:
            age_days = (dt.datetime.utcnow() - creation_date).days
            features[23] = -1 if age_days < 180 else 1
    except Exception:
        features[23] = -1

    try:  # [24] DNSRecord
        features[24] = -1 if (whois_error is not None or not dns_ok) else 1
    except Exception:
        features[24] = -1

    try:  # [25] web_traffic (proxy rule)
        features[25] = -1 if len(hostname) > 15 else 1
    except Exception:
        features[25] = -1

    try:  # [26] Page_Rank (temporary rule)
        features[26] = 1
    except Exception:
        features[26] = -1

    try:  # [27] Google_Index (temporary rule)
        features[27] = 1
    except Exception:
        features[27] = -1

    try:  # [28] Links_pointing_to_page
        if soup is None:
            features[28] = -1
        else:
            total_links = len(soup.find_all("a"))
            features[28] = -1 if total_links == 0 else 1
    except Exception:
        features[28] = -1

    try:  # [29] Statistical_report (temporary rule)
        features[29] = 1
    except Exception:
        features[29] = -1

    # Enforce only {-1, 1} values and exact shape (1, 30)
    features = np.where(features == -1, -1, 1).astype(int)
    return features.reshape(1, -1)
