# analyzer.py

import re
from ml_model import ml_scam_probability
from hinglish_rules import HINGLISH_RULES
from urllib.parse import urlparse

# 🔗 Regex that finds links inside text
URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

# ─────────────────────────────────────────────
# 🔑 RULES: (regex pattern, points, explanation)
# ─────────────────────────────────────────────
PHISHING_RULES = [
    (r"verify (your )?(account|identity|details)", 15, "Asks you to 'verify' your account"),
    (r"(account|card|upi).{0,20}(suspended|blocked|locked|frozen)", 15, "Threatens to block your account"),
    (r"\botp\b|one.?time password", 10, "Mentions OTP (never share OTPs!)"),
    (r"kyc.{0,20}(expire|update|pending|incomplete)", 15, "Fake KYC update pressure"),
    (r"click (here|the link|below)", 8, "Pushes you to click a link"),
    (r"(urgent|immediately|within \d+ ?(hours|hrs|minutes|mins))", 10, "Creates false urgency"),
    (r"(you have won|lottery|prize|reward|cashback)", 12, "Too-good-to-be-true prize"),
    (r"(password|pin|cvv|card number)", 12, "Asks for sensitive credentials"),
    (r"(refund|tax).{0,20}(pending|claim|process)", 10, "Fake refund/tax claim"),
]

DIGITAL_ARREST_RULES = [
    (r"digital arrest", 40, "Mentions 'digital arrest' (this is NOT a real legal process!)"),
    (r"(cbi|ed|ncb|narcotics|customs|cyber ?crime|police|trai).{0,15}(officer|department|branch|inspector)", 20, "Claims to be a government/police officer"),
    (r"arrest warrant|case (has been )?registered|fir (has been )?(filed|registered)", 25, "Threatens warrant or legal case"),
    (r"parcel.{0,40}(drugs|illegal|contraband|passport|fake)", 30, "Fake 'illegal parcel' story"),
    (r"money laundering|hawala", 20, "Accuses you of money laundering"),
    (r"(do not|don't|dont).{0,15}(tell|inform|disconnect|share)", 25, "Tells you to keep it secret"),
    (r"(stay|remain|keep).{0,15}(on )?(the )?(video )?(call|line|skype|whatsapp)", 20, "Keeps you on a video call"),
    (r"(transfer|send|deposit).{0,40}(verification|rbi|safe account|supreme court)", 35, "Asks you to move money to a 'safe account'"),
    (r"aadhaar.{0,30}(misused|linked|used in)", 20, "Claims your Aadhaar was misused"),
]

MALICIOUS_APP_RULES = [
    (r"\.apk\b", 30, "Links to an APK file (sideloaded Android app)"),
    (r"(install|download).{0,30}(app|apk|software|anydesk|teamviewer|quicksupport)", 20, "Pushes you to install an app"),
    (r"(anydesk|teamviewer|quicksupport|rustdesk)", 25, "Mentions a remote-access tool"),
    (r"(allow|enable).{0,25}(unknown sources|accessibility|screen sharing)", 20, "Asks for risky phone permissions"),
]

# ─────────────────────────────────────────────
# 🔗 URL settings
# ─────────────────────────────────────────────
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".icu", ".tk", ".ml", ".gq", ".cf", ".work", ".zip", ".loan")

# brand keyword -> its REAL domains
BRANDS = {
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com", "amazon.in"),
    "google": ("google.com",),
    "microsoft": ("microsoft.com",),
    "apple": ("apple.com",),
    "netflix": ("netflix.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "paytm": ("paytm.com",),
    "irctc": ("irctc.co.in",),
}


def _run_rules(text, rules, category):
    """Check every rule. Each rule counts ONCE so scores don't explode."""
    findings = []
    for pattern, points, message in rules:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({"category": category, "message": message, "points": points})
    return findings
    findings += _run_rules(text, MALICIOUS_APP_RULES, "Malicious app")
    findings += _run_rules(text, HINGLISH_RULES, "Hinglish/Hindi pattern")   # 🆕


def _check_url(url):
    """Look at ONE url and return a list of red flags. (We never open it!)"""
    findings = []
    if not url.lower().startswith("http"):
        url = "http://" + url          # urlparse needs a scheme to work properly

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    def add(msg, pts):
        findings.append({"category": "Deceptive URL", "message": f"{msg} → {host}", "points": pts})

    if parsed.scheme == "http":
        add("Link is not encrypted (http, not https)", 5)
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add("Uses a raw IP address instead of a domain name", 25)
    if host in SHORTENERS:
        add("Shortened link hides the real destination", 15)
    if host.endswith(SUSPICIOUS_TLDS):
        add("Suspicious domain ending", 15)
    if "@" in parsed.netloc:
        add("Contains '@' trick to disguise the real site", 25)
    if host.startswith("xn--") or ".xn--" in host:
        add("Punycode domain (can imitate look-alike letters)", 25)
    if host.count(".") >= 4:
        add("Too many subdomains", 10)
    if host.count("-") >= 2:
        add("Many hyphens in domain (common in fake sites)", 10)
    if len(url) > 100:
        add("Unusually long URL", 5)
    if parsed.path.lower().endswith(".apk"):
        add("Link downloads an APK file", 30)

    # 🎭 Look-alike brand check
    for brand, real_domains in BRANDS.items():
        if brand in host:
            is_real = any(host == d or host.endswith("." + d) for d in real_domains)
            if not is_real:
                add(f"Pretends to be '{brand}' but is not its real domain", 35)
                break

    return findings


def analyze(text):
    """Main function: text in → score, level, findings out."""
    findings = []
    findings += _run_rules(text, PHISHING_RULES, "Phishing keyword")
    findings += _run_rules(text, DIGITAL_ARREST_RULES, "Digital Arrest pattern")
    findings += _run_rules(text, MALICIOUS_APP_RULES, "Malicious app")
    findings += _run_rules(text, HINGLISH_RULES, "Hinglish/Hindi pattern")

    urls = URL_REGEX.findall(text)
    for url in urls:
        url = url.rstrip(".,);]")
        findings += _check_url(url)

    rule_score = min(100, sum(f["points"] for f in findings))

    # 🤖 Blend with the ML model (if it exists)
    ml_prob = ml_scam_probability(text)
    if ml_prob is None:
        score, ml_percent = rule_score, None
    else:
        score = round(0.7 * rule_score + 0.3 * ml_prob * 100)
        ml_percent = round(ml_prob * 100)

    if score >= 75:
        level, advice = "CRITICAL", "Almost certainly a scam. Do NOT reply, click, or pay. Report it."
    elif score >= 50:
        level, advice = "HIGH", "Very likely a scam. Don't click anything. Verify via the official website or app."
    elif score >= 25:
        level, advice = "MEDIUM", "Suspicious. Verify through an official channel before acting."
    else:
        level, advice = "LOW", "No major red flags found, but stay careful. This tool isn't perfect."

    findings.sort(key=lambda f: f["points"], reverse=True)
    return {
        "score": score, "rule_score": rule_score, "ml_percent": ml_percent,
        "level": level, "advice": advice, "findings": findings, "urls": urls,
    }