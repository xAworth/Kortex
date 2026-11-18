"""Basit TCP port tarayıcı (yalnızca izinli hedeflerde kullanılmalı)."""
import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                1433, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 27017]


def _check(host: str, port: int, timeout: float) -> int | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def scan_ports(host: str, ports: list[int] | None = None,
               timeout: float = 0.5, workers: int = 50) -> list[int]:
    ports = ports or COMMON_PORTS
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: _check(host, p, timeout), ports)
    return sorted(p for p in results if p is not None)


def port_findings(host: str, open_ports: list[int]) -> list[dict]:
    risky = {21: "FTP şifresiz veri taşır", 23: "Telnet şifresiz",
             3306: "MySQL dışarıya açık", 5432: "PostgreSQL dışarıya açık",
             6379: "Redis dışarıya açık (genelde kimlik doğrulamasız)",
             27017: "MongoDB dışarıya açık", 3389: "RDP dışarıya açık"}
    findings = []
    for port in open_ports:
        if port in risky:
            findings.append({"type": "port", "target": f"{host}:{port}",
                             "severity": "high", "issue": risky[port],
                             "fix": "Güvenlik duvarında yalnızca gerekli IP'lere izin ver."})
    return findings
