"""Linux görünümlü komut satırı."""
import os
import sys
from pathlib import Path

from . import __version__
from .codescan import scan_code, to_compact_json
from .guard import add_to_allowlist, is_allowed
from .headers import check_headers
from .ports import port_findings, scan_ports
from .report import write_report

CONFIG_DIR = Path.home() / ".kortex"
NAME_FILE = CONFIG_DIR / "name"

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"

HELP = """Komutlar:
  help                    Bu yardımı gösterir
  scan-code <klasör>      Yerel kodu tarar, kortex-report.json yazar
  scan-ports <host>       Yaygın portları tarar (yalnızca izinli hedef)
  check-headers <url>     Güvenlik başlıklarını denetler (yalnızca izinli hedef)
  allow <host|url>        Hedefi izin listesine ekler (onay ister)
  report                  Son raporu gösterir
  whoami                  Kayıtlı adını gösterir
  clear                   Ekranı temizler
  exit                    Çıkar"""


def _ask_name() -> str:
    print(f"{GREEN}Kortex'e hoş geldin. Adın nedir?{RESET}")
    name = ""
    while not name:
        name = input("> ").strip()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    NAME_FILE.write_text(name, encoding="utf-8")
    return name


def _load_name() -> str:
    if NAME_FILE.exists():
        return NAME_FILE.read_text(encoding="utf-8").strip() or _ask_name()
    return _ask_name()


def _target_host(arg: str) -> str:
    return arg.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def _require_allowed(target: str) -> bool:
    if is_allowed(target):
        return True
    print(f"{YELLOW}'{target}' izin listesinde değil.{RESET}")
    print("Bu hedefin sana ait olduğunu ya da yazılı izninin bulunduğunu onaylıyor musun?")
    if input("(evet/hayir) > ").strip().lower() in {"evet", "e", "yes", "y"}:
        add_to_allowlist(target)
        print(f"{GREEN}'{target}' izin listesine eklendi.{RESET}")
        return True
    print(f"{RED}İşlem iptal edildi.{RESET}")
    return False


def _print_findings(findings: list[dict]) -> None:
    if not findings:
        print(f"{GREEN}Bulgu yok.{RESET}")
        return
    for f in findings:
        color = RED if f["severity"] == "high" else YELLOW
        where = f.get("target") or f"{f.get('file')}:{f.get('line')}"
        print(f"{color}[{f['severity'].upper()}]{RESET} {where}  {f['issue']}")
        print(f"        Öneri: {f['fix']}")


def dispatch(line: str, name: str) -> bool:
    """Komutu işler. False dönerse kabuk kapanır."""
    parts = line.strip().split(maxsplit=1)
    if not parts:
        return True
    cmd, arg = parts[0].lower(), (parts[1] if len(parts) > 1 else "")

    if cmd in {"exit", "quit"}:
        return False
    if cmd == "help":
        print(HELP)
    elif cmd == "clear":
        os.system("cls" if os.name == "nt" else "clear")
    elif cmd == "whoami":
        print(name)
    elif cmd == "scan-code":
        if not arg:
            print("Kullanım: scan-code <klasör>")
        elif not Path(arg).is_dir():
            print(f"{RED}Klasör bulunamadı: {arg}{RESET}")
        else:
            findings = scan_code(arg)
            _print_findings(findings[:50])
            path = write_report(findings)
            print(f"Toplam {len(findings)} bulgu. Rapor: {path}")
    elif cmd == "scan-ports":
        host = _target_host(arg)
        if host and _require_allowed(host):
            open_ports = scan_ports(host)
            print(f"Açık portlar: {open_ports or 'yok'}")
            _print_findings(port_findings(host, open_ports))
    elif cmd == "check-headers":
        url = arg if arg.startswith("http") else f"https://{arg}"
        if arg and _require_allowed(_target_host(url)):
            try:
                _print_findings(check_headers(url))
            except OSError as exc:
                print(f"{RED}Bağlantı hatası: {exc}{RESET}")
    elif cmd == "allow":
        if arg:
            _require_allowed(_target_host(arg))
    elif cmd == "report":
        path = Path("kortex-report.json")
        print(path.read_text(encoding="utf-8") if path.exists() else "Henüz rapor yok.")
    else:
        print(f"Bilinmeyen komut: {cmd}. 'help' yaz.")
    return True


def run() -> None:
    name = _load_name()
    print(f"Kortex {__version__}. 'help' ile komutları gör.")
    while True:
        try:
            line = input(f"{GREEN}{name}@kortex{RESET}:~$ ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not dispatch(line, name):
            break
    sys.exit(0)
