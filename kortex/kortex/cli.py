"""Tek seferlik CLI kullanımı: python -m kortex.cli scan-code ./proje --json"""
import argparse
import sys

from .codescan import scan_code, to_compact_json
from .report import write_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kortex")
    sub = parser.add_subparsers(dest="command", required=True)
    sc = sub.add_parser("scan-code", help="Yerel kodu tara")
    sc.add_argument("path")
    sc.add_argument("--json", action="store_true", help="Sadece JSON yazdır")
    args = parser.parse_args(argv)

    findings = scan_code(args.path)
    if args.json:
        print(to_compact_json(findings))
    else:
        write_report(findings)
        print(f"{len(findings)} bulgu, kortex-report.json yazıldı.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
