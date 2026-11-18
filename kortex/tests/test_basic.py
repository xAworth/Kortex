import json
import tempfile
from pathlib import Path

from kortex.codescan import scan_code, to_compact_json
from kortex.guard import add_to_allowlist, is_allowed


def test_code_scan_finds_issues():
    with tempfile.TemporaryDirectory() as d:
        Path(d, "app.py").write_text('import subprocess\nsubprocess.run(cmd, shell=True)\neval(x)\n')
        findings = scan_code(d)
        rules = {f["rule"] for f in findings}
        assert {"shell-true", "eval-use"} <= rules


def test_compact_json_is_valid_and_sorted():
    findings = [{"severity": "medium", "rule": "a"}, {"severity": "high", "rule": "b"}]
    data = json.loads(to_compact_json(findings))
    assert data["count"] == 2
    assert data["findings"][0]["severity"] == "high"


def test_allowlist_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d, "allowlist.txt")
        assert not is_allowed("example.com", path)
        add_to_allowlist("Example.com", path)
        assert is_allowed("example.com", path)
