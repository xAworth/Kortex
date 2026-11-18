"""Bulguları dosyaya yazar. Claude Code / Codex bu dosyayı okur."""
from pathlib import Path
from .codescan import to_compact_json

DEFAULT_REPORT = Path("kortex-report.json")


def write_report(findings: list[dict], path: Path = DEFAULT_REPORT) -> Path:
    path.write_text(to_compact_json(findings) + "\n", encoding="utf-8")
    return path
