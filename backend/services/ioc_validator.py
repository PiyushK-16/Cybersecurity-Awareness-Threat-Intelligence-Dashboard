"""IOC validation & normalisation.

IMPORTANT: validation answers "is this SYNTACTICALLY valid?" - NOT "is it malicious?".
Nothing in this module ever connects to an IP, domain or URL. Values are treated as DATA.
"""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

INDICATOR_TYPES = ("IP", "DOMAIN", "URL", "FILE_HASH", "EMAIL_DOMAIN", "CVE_ID")

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_NAMES = {32: "MD5", 40: "SHA1", 64: "SHA256"}


def refang(value: str) -> str:
    """Undo common 'defanging' (hxxp, [.]) so analysts can paste safe-to-share text."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    return v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@")


def defang(value: str, indicator_type: str) -> str:
    """Make URLs/domains non-clickable for display (http -> hxxp, . -> [.])."""
    if indicator_type in ("URL", "DOMAIN", "EMAIL_DOMAIN"):
        v = re.sub(r"^http", "hxxp", value, flags=re.I)
        return v.replace(".", "[.]")
    return value


def _valid_domain(host: str) -> tuple[bool, str]:
    host = host.lower().rstrip(".")
    if not host or len(host) > 253:
        return False, "Domain is empty or longer than 253 characters."
    labels = host.split(".")
    if len(labels) < 2:
        return False, "Domain needs at least two labels (e.g. name.example.com)."
    for lab in labels:
        if not _LABEL.match(lab):
            return False, f"Invalid label '{lab}' (letters, digits and hyphens only; no leading/trailing hyphen)."
    tld = labels[-1]
    if tld.isdigit() or not (tld.isalpha() or tld.startswith("xn--")) or len(tld) < 2:
        return False, "Top-level label must be alphabetic (or punycode) and at least 2 characters."
    return True, ""


def _result(valid=False, itype=None, normalized=None, notes=None, detail=None):
    return {"valid": valid, "indicator_type": itype, "normalized_value": normalized,
            "format_detail": detail, "validation_notes": notes or []}


def validate_indicator(value, expected_type: str | None = None) -> dict:
    """Validate and normalise one indicator.

    Returns: {valid, indicator_type, normalized_value, format_detail, validation_notes}
    `expected_type` (optional) makes sure the detected type matches what the caller claims.
    """
    if not isinstance(value, str) or not value.strip():
        return _result(notes=["Indicator is empty or not text."])
    raw = refang(value)
    if len(raw) > 2048 or re.search(r"\s", raw):
        return _result(notes=["Indicator contains whitespace or is too long."])

    res = _detect(raw)
    if res["valid"] and expected_type:
        detected = res["indicator_type"]
        ok = detected == expected_type or (expected_type == "EMAIL_DOMAIN" and detected == "DOMAIN")
        if not ok:
            return _result(notes=[f"Expected {expected_type} but value looks like {detected}."])
        res["indicator_type"] = expected_type
    return res


def _detect(raw: str) -> dict:
    # URL
    if "://" in raw:
        return _validate_url(raw)
    # CVE
    if raw.upper().startswith("CVE-"):
        cve = raw.upper()
        if _CVE.match(cve):
            return _result(True, "CVE_ID", cve, ["Valid CVE identifier format."], "CVE")
        return _result(notes=["CVE must look like CVE-YYYY-NNNN (4+ digits)."])
    # Hashes
    if _HEX.match(raw.lower()) and len(raw) in _HASH_NAMES:
        name = _HASH_NAMES[len(raw)]
        notes = [f"Valid {name}-format hash (format check only)."]
        if name in ("MD5", "SHA1"):
            notes.append(f"{name} is a legacy algorithm; prefer SHA-256 for new intelligence.")
        return _result(True, "FILE_HASH", raw.lower(), notes, name)
    # IP
    try:
        ip = ipaddress.ip_address(raw)
        return _result(True, "IP", str(ip), [f"Valid IPv{ip.version} address."], f"IPv{ip.version}")
    except ValueError:
        pass
    if re.fullmatch(r"[\d.]+", raw):
        return _result(notes=["Looks like an IPv4 address but is malformed (octets must be 0-255)."])
    # Email address -> keep ONLY the domain (privacy: discard the local part)
    if "@" in raw:
        if raw.count("@") != 1:
            return _result(notes=["Email value must contain exactly one '@'."])
        domain = raw.split("@", 1)[1]
        ok, why = _valid_domain(domain)
        if not ok:
            return _result(notes=[why])
        return _result(True, "EMAIL_DOMAIN", domain.lower().rstrip("."),
                       ["Valid sender domain. Local part discarded to minimise personal data."], "EMAIL")
    # Domain
    ok, why = _valid_domain(raw)
    if ok:
        return _result(True, "DOMAIN", raw.lower().rstrip("."), ["Valid domain syntax."], "DOMAIN")
    return _result(notes=[why])


def _validate_url(raw: str) -> dict:
    try:
        parts = urlsplit(raw)
        host, port = parts.hostname, parts.port
    except ValueError:
        return _result(notes=["URL could not be parsed."])
    if parts.scheme.lower() not in ("http", "https"):
        return _result(notes=["Only http/https URLs are supported."])
    if parts.username or parts.password:
        return _result(notes=["URLs containing credentials are rejected."])
    if not host:
        return _result(notes=["URL has no host."])
    try:
        ipaddress.ip_address(host)
        host_ok, why = True, ""
    except ValueError:
        host_ok, why = _valid_domain(host)
    if not host_ok:
        return _result(notes=[why])
    netloc = host.lower() if ":" not in host else f"[{host}]"
    if port:
        netloc += f":{port}"
    normalized = urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query, ""))
    return _result(True, "URL", normalized, ["Valid URL syntax. It will never be visited."], "URL")
