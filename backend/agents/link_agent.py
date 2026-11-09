"""Deterministic static URL/file analysis and a non-executing sandbox simulation."""
import hashlib
import ipaddress
import math
import mimetypes
import re
import unicodedata
from urllib.parse import urlparse

BRANDS = ("microsoft", "amazon", "google", "paypal", "apple", "sbi", "hdfc", "netflix")
BAD_TLDS = {"zip", "click", "top", "xyz", "work", "support", "country", "gq", "tk", "rest", "monster"}
PROFILES = {"credential_harvester", "drive_by_download", "benign", "ransomware_dropper"}
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ӏ": "l", "ԁ": "d", "Α": "a", "Ε": "e", "Ο": "o", "Ρ": "p",
})
ASCII_CONFUSABLES = {"rn": "m", "vv": "w", "0": "o", "1": "l"}


def entropy(value):
    if not value:
        return 0.0
    return -sum((value.count(char) / len(value)) * math.log2(value.count(char) / len(value)) for char in set(value))


def domain_skeleton(value):
    value = value.replace("I", "l").translate(HOMOGLYPHS).lower()
    for source, target in ASCII_CONFUSABLES.items():
        value = value.replace(source, target)
    return value


def decode_idna_host(host):
    if not host or not any(label.startswith("xn--") for label in host.split(".")):
        return ""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeEncodeError):
        return "(invalid punycode)"


def _profile_report(host, scenario):
    timeline = [
        {
            "t": second,
            "cpu": round(14 + (second * 7) % 29 + (10 if scenario != "benign" and second > 3 else 0), 1),
            "memory": round(94 + second * 7.8 + (42 if scenario in ("ransomware_dropper", "drive_by_download") and second > 5 else 0), 1),
        }
        for second in range(11)
    ]
    processes = {
        "benign": ["browser.exe", "browser.exe → renderer.exe"],
        "credential_harvester": ["browser.exe", "browser.exe → mshta.exe", "browser.exe → mshta.exe → wscript.exe"],
        "drive_by_download": ["browser.exe", "browser.exe → chrome_update.exe", "browser.exe → chrome_update.exe → powershell.exe"],
        "ransomware_dropper": ["browser.exe", "browser.exe → invoice_viewer.exe", "browser.exe → invoice_viewer.exe → updater.exe"],
    }[scenario]
    c2 = "198.51.100.42:8443" if scenario != "benign" else "203.0.113.10:443"  # RFC 5737 documentation-only IPs.
    return {
        "scenario": scenario,
        "simulation_seconds": 10,
        "timeline": timeline,
        "process_tree": processes,
        "network": [
            {"time": "00:02", "type": "DNS", "detail": host or "uploaded-file.local", "status": "resolved"},
            {"time": "00:04", "type": "TLS", "detail": c2, "status": "simulated" if scenario != "benign" else "expected"},
            {
                "time": "00:07", "type": "HTTP",
                "detail": "POST /collect" if scenario == "credential_harvester" else "GET /payload.bin",
                "status": "simulated" if scenario != "benign" else "blocked by policy",
            },
        ],
        "files": ["%TEMP%\\session.tmp", "%APPDATA%\\update.dat"] if scenario != "benign" else ["%TEMP%\\browser_cache.tmp"],
        "persistence": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate"] if scenario in ("drive_by_download", "ransomware_dropper") else [],
        "backdoor": scenario in ("drive_by_download", "ransomware_dropper"),
        "backdoor_detail": f"Simulated reverse shell to {c2} on an unusual port." if scenario in ("drive_by_download", "ransomware_dropper") else "No reverse shell behavior observed.",
        "honeypot": {
            "device": "Decoy finance workstation",
            "bait": [
                {"name": "fake-credentials.xlsx", "attempted": scenario in ("credential_harvester", "ransomware_dropper"), "interest": "Stored financial logins"},
                {"name": "browser_cookies.sqlite", "attempted": scenario != "benign", "interest": "Authenticated web sessions"},
            ],
        },
        "file": None,
        "profile_badge": "Simulated behavioral profile",
    }


def analyze_url(url, scenario="credential_harvester"):
    reasons = []
    score = 0
    candidate = str(url).strip()
    candidate = candidate if "://" in candidate else "https://" + candidate
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").rstrip(".").lower()
    except ValueError:
        parsed = urlparse("https://invalid")
        host = ""
        reasons.append("URL could not be parsed safely; hostname or port syntax is malformed.")
        score += 25

    if not host:
        reasons.append("URL has no destination hostname.")
        score += 20

    decoded_host = decode_idna_host(host)
    if decoded_host:
        reasons.append(f"Punycode hostname decodes to '{decoded_host}'.")
        score += 35

    analysis_host = decoded_host if decoded_host and not decoded_host.startswith("(") else host
    scripts = set()
    suspicious_chars = []
    for char in analysis_host:
        char_name = unicodedata.name(char, "")
        script = "CYRILLIC" if "CYRILLIC" in char_name else "GREEK" if "GREEK" in char_name else "LATIN" if "LATIN" in char_name else None
        if script:
            scripts.add(script)
        if script in ("CYRILLIC", "GREEK"):
            suspicious_chars.append((char, char_name))
    if suspicious_chars:
        char, char_name = suspicious_chars[0]
        mixed = "mixed-script " if "LATIN" in scripts else "non-Latin "
        reasons.append(f"Hostname contains a {mixed}confusable character: '{char}' U+{ord(char):04X} {char_name}.")
        score += 45 if "LATIN" in scripts else 35

    if len(candidate) > 100:
        reasons.append(f"Unusually long URL ({len(candidate)} characters).")
        score += min(20, (len(candidate) - 100) // 10 + 8)

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        reasons.append(f"URL uses a raw IP host ({host}) instead of a registered domain.")
        score += 35

    labels = host.split(".") if host else []
    if labels and labels[-1] in BAD_TLDS:
        reasons.append(f"High-risk top-level domain: .{labels[-1]}.")
        score += 24

    subdomain_count = max(0, len(labels) - 2) if not is_ip else 0
    if subdomain_count >= 3:
        reasons.append(f"Hostname contains {subdomain_count} subdomain labels, more than the usual two-label host.")
        score += min(20, (subdomain_count - 2) * 7)

    if "@" in parsed.netloc:
        reasons.append("An @ symbol in the URL authority can disguise the actual destination host.")
        score += 30

    entropy_host = analysis_host.replace(".", "")
    host_entropy = entropy(entropy_host)
    if len(entropy_host) >= 16 and host_entropy >= 3.7:
        reasons.append(f"Hostname has high character entropy ({host_entropy:.2f} bits), consistent with a generated host label.")
        score += 15

    analysis_labels = analysis_host.split(".") if analysis_host else []
    registered_core = analysis_labels[-2] if len(analysis_labels) > 1 else (analysis_labels[0] if analysis_labels else "")
    normalized_core = domain_skeleton(registered_core)
    for brand in BRANDS:
        if normalized_core == brand and registered_core.lower() != brand:
            reasons.append(f"Registered hostname label '{registered_core}' is a homoglyph/lookalike for {brand}.com after confusable normalization.")
            score += 50
            break

    if len(analysis_labels) > 2:
        subdomains = analysis_labels[:-2]
        for brand in BRANDS:
            if any(domain_skeleton(label) == brand for label in subdomains) and normalized_core != brand:
                registered_host = ".".join(analysis_labels[-2:])
                reasons.append(f"Brand name '{brand}' appears in a subdomain while the registered host is {registered_host}.")
                score += 35
                break

    if scenario not in PROFILES:
        scenario = "credential_harvester"
    profile_reasons = {
        "credential_harvester": "Behavior profile indicates a credential collection flow.",
        "drive_by_download": "Behavior profile indicates an unsolicited executable download.",
        "ransomware_dropper": "Behavior profile indicates encryption and persistence behavior.",
        "benign": "Behavior profile is consistent with a benign landing page.",
    }
    if scenario != "benign":
        reasons.append(profile_reasons[scenario])
        score += 45 if scenario == "ransomware_dropper" else 35
    elif not reasons:
        reasons.append(profile_reasons[scenario])

    score = min(score, 100)
    verdict = "SAFE" if score < 25 else "SUSPICIOUS" if score < 65 else "MALICIOUS"
    if not reasons:
        reasons.append("No suspicious static indicators were found; destination structure appears ordinary.")
    report = _profile_report(host, scenario)
    return {"verdict": verdict, "risk_score": score, "reasons": reasons, "host": host, "report": report}


def analyze_file(filename, content, scenario="drive_by_download"):
    filename = str(filename or "upload.bin")
    content = bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    eicar = EICAR_SIGNATURE in content
    result = analyze_url("https://uploaded-file.local/download", scenario)
    detected_type = content_type(filename, content, eicar=eicar)
    facts = [
        f"SHA-256: {digest}",
        f"File size: {len(content):,} bytes",
        f"File name: {filename}",
        f"Detected type: {detected_type}",
    ]
    if eicar:
        result["risk_score"] = 100
        result["verdict"] = "MALICIOUS"
        result["reasons"].append("EICAR test signature found inside uploaded file.")
    result["reasons"] = facts + result["reasons"]
    result["report"]["file"] = {"filename": filename, "size": len(content), "sha256": digest, "type": detected_type, "eicar": eicar}
    return result


def content_type(name, content, eicar=False):
    if eicar:
        return "EICAR test signature (plain text)"
    if content.startswith(b"MZ"):
        return "Windows PE executable"
    if content.startswith(b"PK\x03\x04"):
        return "ZIP archive / Office document"
    if content.startswith(b"%PDF"):
        return "PDF document"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if content.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if content.startswith((b"GIF87a", b"GIF89a")):
        return "GIF image"
    guessed, _ = mimetypes.guess_type(name)
    if guessed:
        return guessed
    try:
        content.decode("utf-8")
        return "Plain text"
    except UnicodeDecodeError:
        return "Unknown binary"


class LinkAgent:
    name = "LinkAgent"

    def analyze(self, url, scenario="credential_harvester"):
        return analyze_url(url, scenario)
