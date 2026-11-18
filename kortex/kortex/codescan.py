"""Yerel kod tarayıcı. Claude Code / Codex'in okuyacağı kompakt rapor üretir."""
import json
import re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
SCAN_EXTS = {".py", ".js", ".ts", ".php", ".html", ".java", ".go", ".rb", ".lua", ".env.example"}
MAX_FILE_BYTES = 1_000_000

RULES = [
    ("eval-use", "high", re.compile(r"\beval\s*\("), "eval() kullanımı; girdi kontrolsüzse kod enjeksiyonu.", "Veriyi ayrıştırmak için ast.literal_eval veya JSON kullan."),
    ("shell-true", "high", re.compile(r"shell\s*=\s*True"), "subprocess shell=True; komut enjeksiyonu riski.", "Argümanları liste olarak ver, shell=False kullan."),
    ("sql-concat", "high", re.compile(r"""execute\(\s*f["']|execute\(.*\+\s*\w"""), "SQL sorgusu string birleştirme ile kuruluyor.", "Parametreli sorgu kullan (?, %s)."),
    ("innerhtml", "medium", re.compile(r"\.innerHTML\s*="), "innerHTML ataması; XSS riski.", "textContent kullan veya çıktıyı kaçışla (escape)."),
    ("tls-verify-off", "high", re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false"), "TLS sertifika doğrulaması kapalı.", "Doğrulamayı aç, gerekiyorsa CA sertifikası ekle."),
    ("debug-on", "medium", re.compile(r"debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True"), "Debug modu açık görünüyor.", "Üretimde debug'ı kapat, ortam değişkeninden oku."),
    ("weak-hash", "medium", re.compile(r"\b(md5|sha1)\s*\("), "Zayıf hash algoritması (MD5/SHA1).", "Şifreler için bcrypt/argon2, bütünlük için SHA-256 kullan."),
    ("yaml-unsafe", "high", re.compile(r"yaml\.load\((?![^)]*Loader)"), "yaml.load güvensiz yükleyici ile çağrılıyor.", "yaml.safe_load kullan."),
    ("hardcoded-secret", "high", re.compile(r"""(?i)(password|passwd|api[_-]?key|secret|token)\s*[:=]\s*["'][^"']{6,}["']"""), "Kodda sabit yazılmış gizli bilgi olabilir.", "Değeri ortam değişkeninden oku; anahtarı yenile."),
]


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and (path.suffix in SCAN_EXTS or path.name.endswith(".env.example")):
            if path.stat().st_size <= MAX_FILE_BYTES:
                yield path


def scan_code(root: str) -> list[dict]:
    base = Path(root).resolve()
    findings = []
    for path in _iter_files(base):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        rel = str(path.relative_to(base))
        for lineno, line in enumerate(lines, start=1):
            for rule_id, severity, pattern, issue, fix in RULES:
                if pattern.search(line):
                    findings.append({"type": "code", "rule": rule_id, "file": rel,
                                     "line": lineno, "severity": severity,
                                     "issue": issue, "fix": fix})
    return findings


def to_compact_json(findings: list[dict]) -> str:
    """Token tasarrufu için kısa, sıralı JSON çıktısı."""
    order = {"high": 0, "medium": 1, "low": 2}
    ordered = sorted(findings, key=lambda f: order.get(f["severity"], 3))
    return json.dumps({"count": len(ordered), "findings": ordered},
                      ensure_ascii=False, separators=(",", ":"))
