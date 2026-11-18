"""Hedef güvenliği: tarama yalnızca izinli hedeflerde yapılır."""
from pathlib import Path

ALLOWLIST_PATH = Path.home() / ".kortex" / "allowlist.txt"


def load_allowlist(path: Path = ALLOWLIST_PATH) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def add_to_allowlist(target: str, path: Path = ALLOWLIST_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(target.strip().lower() + "\n")


def is_allowed(target: str, path: Path = ALLOWLIST_PATH) -> bool:
    return target.strip().lower() in load_allowlist(path)
