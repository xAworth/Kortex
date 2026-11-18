"""HTTP güvenlik başlığı denetimi."""
import urllib.request

REQUIRED_HEADERS = {
    "content-security-policy": ("Content-Security-Policy yok", "XSS riskini azaltmak için CSP ekle."),
    "strict-transport-security": ("HSTS yok", "Strict-Transport-Security ekle (HTTPS zorunluluğu)."),
    "x-content-type-options": ("X-Content-Type-Options yok", "'nosniff' değeriyle ekle."),
    "x-frame-options": ("X-Frame-Options yok", "Clickjacking için DENY veya SAMEORIGIN ekle."),
    "referrer-policy": ("Referrer-Policy yok", "strict-origin-when-cross-origin öner."),
}


def check_headers(url: str, timeout: float = 5.0) -> list[dict]:
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "Kortex/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        present = {k.lower() for k in resp.headers.keys()}
    findings = []
    for header, (issue, fix) in REQUIRED_HEADERS.items():
        if header not in present:
            findings.append({"type": "header", "target": url, "severity": "medium",
                             "issue": issue, "fix": fix})
    return findings
