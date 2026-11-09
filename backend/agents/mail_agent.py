import re
import unicodedata
from urllib.parse import urlparse

BRANDS = ("microsoft", "amazon", "google", "paypal", "apple", "sbi", "hdfc", "netflix")
CONFUSABLES = {"rn": "m", "vv": "w", "0": "o", "1": "l"}
UNICODE_CONFUSABLES = str.maketrans({"а":"a", "е":"e", "о":"o", "р":"p", "с":"c", "х":"x", "у":"y", "і":"i", "ӏ":"l", "ԁ":"d", "Α":"a", "Ε":"e", "Ο":"o", "Ρ":"p"})
URGENCY = ("urgent", "immediately", "suspended", "expire", "within 24 hours", "final warning", "verify now")
CREDENTIALS = ("password", "login", "sign in", "credentials", "verify your account", "one-time code", "otp")

def levenshtein(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1): current.append(min(current[-1] + 1, previous[j] + 1, previous[j-1] + (ca != cb)))
        previous = current
    return previous[-1]

def skeleton(value):
    value = value.replace("I", "l").translate(UNICODE_CONFUSABLES).lower()
    for src, dst in CONFUSABLES.items(): value = value.replace(src, dst)
    return value

def domain_of(sender):
    candidate = sender.strip()
    if "@" in candidate: candidate = candidate.rsplit("@", 1)[1]
    elif "://" in candidate:
        try: candidate = urlparse(candidate).hostname or ""
        except ValueError: candidate = ""
    return candidate.rstrip(".").lower()

def script_findings(value, location):
    found = []
    scripts = set()
    for char in value:
        name = unicodedata.name(char, "")
        script = "CYRILLIC" if "CYRILLIC" in name else "GREEK" if "GREEK" in name else "LATIN" if "LATIN" in name else None
        if script: scripts.add(script)
    if "LATIN" in scripts and ("CYRILLIC" in scripts or "GREEK" in scripts):
        for char in value:
            name = unicodedata.name(char, "")
            if "CYRILLIC" in name or "GREEK" in name:
                cp = f"U+{ord(char):04X}"
                look = "a" if char.lower() in ("а", "α") else "e" if char.lower() in ("е", "ε") else "o" if char.lower() in ("о", "ο") else ""
                suffix = f", visually identical to Latin '{look}'" if look else ""
                found.append(f"{location} mixes Latin with another script: '{char}' {cp} {name}{suffix}.")
    return found

class MailAgent:
    name = "MailAgent"

    def analyze(self, email: dict) -> dict:
        sender = str(email.get("sender", ""))
        display = str(email.get("display_name", ""))
        subject = str(email.get("subject", ""))
        body = str(email.get("body", ""))
        domain = domain_of(sender)
        reasons, score = [], 0
        for text, label in ((domain, "Sender domain"), (display, "Display name")):
            matches = script_findings(text, label)
            if matches: reasons.extend(matches); score += 65 if label == "Sender domain" else 34
        try:
            unicode_domain = domain.encode("ascii").decode("idna") if domain.startswith("xn--") or ".xn--" in domain else ""
        except (UnicodeError, UnicodeEncodeError): unicode_domain = "(invalid punycode)"
        if unicode_domain: reasons.append(f"Punycode domain decodes to '{unicode_domain}'."); score += 55
        labels = domain.split(".")
        core = labels[-2] if len(labels) > 1 else labels[0]
        norm_core = skeleton(core)
        for brand in BRANDS:
            dist = levenshtein(norm_core, brand)
            if norm_core != core.lower() and dist <= (2 if len(brand) > 5 else 1):
                substitutions = [f"{src}-for-{dst}" for src, dst in CONFUSABLES.items() if src in core.lower() and levenshtein(core.lower().replace(src, dst), brand) < levenshtein(core.lower(), brand)]
                detail = f" after {', '.join(substitutions)} substitution" if substitutions else ""
                reasons.append(f"Domain '{domain}' impersonates {brand}.com{detail} (normalized edit distance {dist}).")
                score += 70
                break
            # IDNA labels must be decoded before brand comparison; a punycode label
            # that resolves to a lookalike is a block-level impersonation signal.
            try: decoded_core = core.encode("ascii").decode("idna").lower() if core.startswith("xn--") else ""
            except (UnicodeError, UnicodeEncodeError): decoded_core = ""
            decoded_skeleton = skeleton(decoded_core)
            if decoded_core and decoded_core != brand and levenshtein(decoded_skeleton, brand) <= (2 if len(brand) > 5 else 1):
                reasons.append(f"Decoded sender domain '{decoded_core}' impersonates {brand}.com (IDNA punycode lookalike).")
                score += 70
                break
        for url in email.get("urls", []):
            candidate = str(url).strip()
            try: parsed = urlparse(candidate if "://" in candidate else "https://" + candidate)
            except ValueError:
                reasons.append(f"Embedded URL is malformed and could not be safely parsed: '{candidate[:80]}'."); score += 20; continue
            host = (parsed.hostname or "").lower()
            if not host: continue
            for finding in script_findings(host, "Embedded URL domain"):
                if finding not in reasons: reasons.append(finding); score += 65
            try: decoded = host.encode("ascii").decode("idna") if host.startswith("xn--") or ".xn--" in host else ""
            except (UnicodeError, UnicodeEncodeError): decoded = "(invalid punycode)"
            if decoded: reasons.append(f"Embedded URL uses punycode and decodes to '{decoded}'."); score += 45
            host_labels = host.split(".")
            host_core = skeleton(host_labels[-2] if len(host_labels) > 1 else host_labels[0])
            for brand in BRANDS:
                dist = levenshtein(host_core, brand)
                if host_core != brand and dist <= (2 if len(brand) > 5 else 1):
                    reasons.append(f"Embedded URL domain '{host}' resembles {brand}.com (normalized edit distance {dist})."); score += 42
                    break
        name = display.lower()
        for brand in BRANDS:
            if brand in name and domain != f"{brand}.com":
                reasons.append(f"Display name claims {brand.title()} support, but sender domain is {domain or 'missing'}.")
                score += 42
                break
        combined = f"{subject} {body}".lower()
        urgent = [word for word in URGENCY if word in combined]
        creds = [word for word in CREDENTIALS if word in combined]
        if urgent: reasons.append(f"Urgency language detected: {', '.join(urgent[:3])}."); score += min(12, 4 * len(urgent))
        if creds: reasons.append(f"Credential-request language detected: {', '.join(creds[:3])}."); score += min(16, 6 * len(creds))
        reply = str(email.get("reply_to", "")).strip()
        if reply and domain_of(reply) != domain:
            reasons.append(f"Reply-To domain {domain_of(reply)} does not match sender domain {domain}."); score += 25
        score = min(score, 100)
        allowlisted = bool(email.get("allowlisted"))
        if allowlisted: reasons.append("Sender is on the operator allowlist after a recorded revoke."); verdict = "ALLOW"
        else: verdict = "BLOCK" if score >= 65 else "QUARANTINE" if score >= 28 else "ALLOW"
        if not reasons: reasons.append(f"No impersonation, script-mixing, urgency, credential, or reply-to indicators found for sender '{sender}' on subject '{subject}'.")
        return {"verdict": verdict, "risk_score": score, "reasons": reasons, "domain": domain}
