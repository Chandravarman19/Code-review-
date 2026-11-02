"""Regression tests for AST detection, severity, consolidation, and exports.

Loads selected definitions from app.py without executing Streamlit's UI.
Run: python -m unittest -v
"""
import ast
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

APP_PATH = Path(__file__).with_name("app.py")
SOURCE_TREE = ast.parse(APP_PATH.read_text(encoding="utf-8"))
NEEDED = {
    "safe_text", "normalize_severity", "normalize_path", "source_line",
    "make_finding", "get_fix_recommendation", "identify_issue",
    "CodeReviewVisitor", "analyze_ast", "finding_fingerprint",
    "_silent_exception_handlers", "consolidate_findings", "build_report",
    "export_json", "export_csv",
}
ENV = {
    "ast": ast, "csv": csv, "hashlib": hashlib, "io": io, "json": json,
    "os": os, "re": re, "subprocess": subprocess, "sys": sys,
    "tempfile": tempfile, "datetime": datetime, "Path": Path,
    "SEVERITIES": ["Critical", "High", "Medium", "Low", "Info"],
    "SEVERITY_ORDER": {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4},
    "TOOL_AST": "AST", "TOOL_BANDIT": "Bandit", "TOOL_RUFF": "Ruff",
}
for node in SOURCE_TREE.body:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in NEEDED:
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(APP_PATH), "exec"), ENV)


class DetectionEngineTests(unittest.TestCase):
    def test_detects_common_bug_and_security_rules(self):
        source = '''
import os, pickle, hashlib, requests
API_KEY = "demo-secret-value"
def calculate(value=[]):
    return value
def process(user_input):
    result = eval(user_input)
    number = 10 / 0
    first = [][0]
    missing = {"name": "demo"}["password"]
    os.system("echo " + user_input)
    return result
def load_data(data):
    return pickle.loads(data)
def make_hash(password):
    return hashlib.md5(password.encode()).hexdigest()
def fetch(url):
    return requests.get(url, verify=False)
def ignore_error():
    try:
        int("bad")
    except Exception:
        pass
'''
        findings = ENV["analyze_ast"](source, "demo.py")
        rules = {item["rule"] for item in findings}
        expected = {
            "AST-HARDCODED-SECRET", "AST-MUTABLE-DEFAULT", "AST-EVAL",
            "AST-DIVISION-BY-ZERO", "AST-EMPTY-CONTAINER-INDEX",
            "AST-DICT-KEY-NOT-FOUND", "AST-SHELL-EXECUTION",
            "AST-UNSAFE-DESERIALIZATION", "AST-WEAK-CRYPTOGRAPHY",
            "AST-INSECURE-TLS", "AST-SILENT-EXCEPTION",
        }
        self.assertTrue(expected.issubset(rules), f"Missing rules: {expected - rules}")

    def test_syntax_error_returns_finding_instead_of_crashing(self):
        findings = ENV["analyze_ast"]("def broken(:\n pass", "broken.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "AST-SYNTAX-ERROR")
        self.assertEqual(findings[0]["severity"], "High")

    def test_clean_source_has_no_ast_findings(self):
        self.assertEqual(ENV["analyze_ast"]("def add(a, b):\n    return a + b\n", "clean.py"), [])

    def test_severity_normalization(self):
        normalize = ENV["normalize_severity"]
        self.assertEqual(normalize("critical"), "Critical")
        self.assertEqual(normalize("moderate"), "Medium")
        self.assertEqual(normalize("warning"), "Medium")
        self.assertEqual(normalize("error"), "High")
        self.assertEqual(normalize("unexpected"), "Medium")
        self.assertEqual(normalize(None), "Medium")

    def test_path_normalization(self):
        self.assertEqual(ENV["normalize_path"](r"folder\demo.py"), "folder/demo.py")
        self.assertEqual(ENV["normalize_path"]("  "), "uploaded_file.py")

    def test_same_finding_from_multiple_tools_is_consolidated(self):
        base = {"filename":"demo.py", "line":3, "rule":"AST-EVAL", "title":"Unsafe eval", "severity":"High", "description":"unsafe", "fix":"fix", "tool":"AST", "code":"eval(x)"}
        other = dict(base, rule="B307", tool="Bandit", title="Use of eval")
        result = ENV["consolidate_findings"]([base, other], source="\n\n eval(x)\n")
        self.assertEqual(len(result), 1)
        self.assertIn("AST", result[0]["tool"])
        self.assertIn("Bandit", result[0]["tool"])
        self.assertIn("AST-EVAL", result[0]["rule"])
        self.assertIn("B307", result[0]["rule"])

    def test_different_families_on_same_line_are_not_merged(self):
        tls = {"filename":"demo.py", "line":1, "rule":"B501", "title":"TLS disabled", "severity":"High", "description":"tls", "fix":"tls fix", "tool":"Bandit", "code":"requests.get(url, verify=False)"}
        timeout = dict(tls, rule="B113", title="Missing timeout", description="timeout", fix="timeout fix")
        result = ENV["consolidate_findings"]([tls, timeout], source="requests.get(url, verify=False)")
        self.assertEqual(len(result), 2)

    def test_random_and_temp_path_overlap_is_consolidated_with_evidence(self):
        code = 'return os.path.join("/tmp", str(random.random()))'
        random_finding = {
            "filename": "demo.py", "line": 1, "rule": "AST-SECURITY-RANDOM, B311",
            "title": "Non-cryptographic random number generator", "severity": "Medium",
            "description": "random module is not cryptographically secure", "fix": "Use tempfile",
            "tool": "AST, Bandit", "code": code,
        }
        temp_finding = {
            "filename": "demo.py", "line": 1, "rule": "B108",
            "title": "Probable insecure usage of temp file/directory", "severity": "Medium",
            "description": "Hard-coded temporary path", "fix": "Use tempfile.TemporaryDirectory",
            "tool": "Bandit", "code": code,
        }
        result = ENV["consolidate_findings"]([random_finding, temp_finding], source=code)
        self.assertEqual(len(result), 1)
        self.assertIn("B108", result[0]["rule"])
        self.assertIn("B311", result[0]["rule"])

    def test_random_warning_without_temp_path_remains_separate(self):
        code = "return random.random()"
        random_finding = {
            "filename": "demo.py", "line": 1, "rule": "B311",
            "title": "Non-cryptographic random number generator", "severity": "Medium",
            "description": "random module is not cryptographically secure", "fix": "Use secrets",
            "tool": "Bandit", "code": code,
        }
        other_finding = {
            "filename": "demo.py", "line": 1, "rule": "B108",
            "title": "Probable insecure usage of temp file/directory", "severity": "Medium",
            "description": "Hard-coded temporary path", "fix": "Use tempfile",
            "tool": "Bandit", "code": code,
        }
        result = ENV["consolidate_findings"]([random_finding, other_finding], source=code)
        self.assertEqual(len(result), 2)

    def test_consolidation_keeps_different_lines_separate(self):
        one = {"filename":"demo.py", "line":1, "rule":"AST-EVAL", "title":"Unsafe eval", "severity":"High", "description":"unsafe", "fix":"fix", "tool":"AST", "code":"eval(a)"}
        two = dict(one, line=2, code="eval(b)")
        self.assertEqual(len(ENV["consolidate_findings"]([one, two])), 2)

    def test_report_summary_counts_severity_and_hashes_source(self):
        findings = [
            {"severity":"High", "filename":"demo.py", "line":1, "rule":"R1", "title":"A", "description":"", "fix":"", "tool":"AST", "code":"x", "confidence":"High"},
            {"severity":"low", "filename":"demo.py", "line":2, "rule":"R2", "title":"B", "description":"", "fix":"", "tool":"Ruff", "code":"y", "confidence":"High"},
        ]
        report = ENV["build_report"](findings, "demo.py", "source text", ["sample diagnostic"])
        self.assertEqual(report["summary"]["total_findings"], 2)
        self.assertEqual(report["summary"]["severity_counts"]["High"], 1)
        self.assertEqual(report["summary"]["severity_counts"]["Low"], 1)
        self.assertEqual(report["source_sha256"], hashlib.sha256(b"source text").hexdigest())
        self.assertEqual(report["diagnostics"], ["sample diagnostic"])

    def test_json_export_round_trips(self):
        report = {"summary":{"total_findings":1}, "findings":[{"title":"Test", "severity":"High"}]}
        encoded = ENV["export_json"](report)
        self.assertEqual(json.loads(encoded), report)

    def test_csv_export_has_header_and_finding_rows(self):
        findings = [{"filename":r"folder\demo.py", "line":7, "severity":"warning", "rule":"R1", "title":"Issue", "description":"Details", "fix":"Fix", "tool":"AST", "code":"x = 1", "confidence":"High", "extra":"ignored"}]
        text = ENV["export_csv"](findings)
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "Medium")
        self.assertEqual(rows[0]["line"], "7")
        self.assertEqual(rows[0]["title"], "Issue")
        self.assertNotIn("extra", rows[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
