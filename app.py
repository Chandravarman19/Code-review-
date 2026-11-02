
# INTELLIGENT CODE REVIEW & BUG DETECTION SYSTEM
# Complete replacement for app.py
#
# Features:
# 1. AST-based bug and security analysis
# 2. Bandit security scanning (optional)
# 3. Ruff code-quality analysis (optional)
# 4. Duplicate finding consolidation
# 5. Context-aware fix recommendations
# 6. Severity filters and finding details
# 7. JSON and CSV report exports
# 8. Demo source code and source-file upload

import ast
import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import hashlib
from datetime import datetime
from pathlib import Path

import streamlit as st


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Intelligent Code Review & Bug Detection",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# APPLICATION STYLING
# ============================================================

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    .main-title {
        font-size: 2.1rem;
        font-weight: 800;
        margin-bottom: 0.15rem;
    }

    .subtitle {
        color: #8b949e;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }

    .finding-card {
        border: 1px solid rgba(128, 128, 128, 0.25);
        border-radius: 10px;
        padding: 14px;
        margin-bottom: 10px;
    }

    .small-muted {
        color: #8b949e;
        font-size: 0.85rem;
    }

    div[data-testid="stMetric"] {
        border: 1px solid rgba(128, 128, 128, 0.2);
        padding: 12px;
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# CONSTANTS
# ============================================================

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}

SEVERITY_COLORS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Info": "⚪",
}

TOOL_AST = "AST"
TOOL_BANDIT = "Bandit"
TOOL_RUFF = "Ruff"


# ============================================================
# DEMO SOURCE CODE
# ============================================================

DEMO_SOURCE = '''import os
import pickle
import random
import hashlib
import requests

API_KEY = "sk_demo_123456789abcdef"

def calculate(value=[]):
    return value

def process(user_input):
    result = eval(user_input)
    number = 10 / 0
    first = [][0]
    missing = {"name": "demo"}["password"]

    try:
        os.system("echo " + user_input)
    except Exception:
        pass

    return result

def load_data(data):
    return pickle.loads(data)

def create_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def download_file(url):
    return requests.get(url, verify=False)

def temporary_path():
    return os.path.join("/tmp", str(random.random()))

def unused_example():
    value = 10
    return "unused variable example"
'''


# ============================================================
# GENERAL HELPERS
# ============================================================

def safe_text(value):
    """Convert a value to printable text safely."""
    if value is None:
        return ""
    return str(value)


def normalize_severity(value):
    """Normalize severity labels to the application's severity levels."""
    if not value:
        return "Medium"

    text = safe_text(value).strip().lower()

    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "warning": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
        "error": "High",
    }

    return mapping.get(text, "Medium")


def normalize_path(filename):
    """Normalize a path for stable finding comparisons."""
    filename = safe_text(filename).strip()

    if not filename:
        return "uploaded_file.py"

    return filename.replace("\\", "/")


def source_line(source_lines, line_number):
    """Return a source line without raising on invalid line numbers."""
    try:
        line_number = int(line_number)
        if 1 <= line_number <= len(source_lines):
            return source_lines[line_number - 1].strip()
    except (TypeError, ValueError):
        pass

    return ""


def make_finding(
    filename,
    line,
    rule,
    title,
    severity,
    description,
    fix,
    tool,
    code="",
    confidence="Medium",
):
    """Create a finding with a consistent report schema."""
    return {
        "filename": normalize_path(filename),
        "line": int(line) if str(line).isdigit() else 1,
        "rule": safe_text(rule),
        "title": safe_text(title),
        "severity": normalize_severity(severity),
        "description": safe_text(description),
        "fix": safe_text(fix),
        "tool": safe_text(tool),
        "code": safe_text(code),
        "confidence": safe_text(confidence),
    }


# ============================================================
# CONTEXT-AWARE FIX RECOMMENDATIONS
# ============================================================

def get_fix_recommendation(family, code="", filename=""):
    """Return actionable guidance for a recognized issue family."""

    fixes = {
        "unsafe-eval": (
            "Avoid eval() on input or other untrusted data. "
            "Use a safe parser or explicitly validate and handle the "
            "specific operations your application needs."
        ),

        "shell-execution": (
            "Avoid passing user-controlled strings to shell commands. "
            "Use subprocess.run() with a list of arguments and "
            "shell=False. Validate arguments before execution."
        ),

        "division-by-zero": (
            "Check the denominator before division. For example:\n"
            "if denominator != 0:\n"
            "    result = numerator / denominator\n"
            "else:\n"
            "    # Handle the zero-denominator case\n"
            "    result = None"
        ),

        "empty-container-index": (
            "Check that the list or sequence is non-empty before "
            "accessing an element. For example:\n"
            "if items:\n"
            "    first = items[0]\n"
            "else:\n"
            "    # Handle the empty collection"
        ),

        "unsafe-indexing": (
            "Validate the collection and index before accessing an "
            "element. Check collection length and handle missing "
            "keys or out-of-range indexes."
        ),

        "dict-key-not-found": (
            "Use dictionary.get(key, default) when the key may be "
            "missing, or explicitly check key membership before "
            "accessing the dictionary."
        ),

        "mutable-default": (
            "Avoid mutable function defaults such as [] or {}. "
            "Use None and create a fresh object inside the function:\n"
            "def example(items=None):\n"
            "    if items is None:\n"
            "        items = []"
        ),

        "hardcoded-secret": (
            "Remove the credential from source code. Load secrets "
            "from environment variables or a secret manager, and "
            "rotate any real credential that may have been exposed."
        ),

        "unsafe-deserialization": (
            "Do not unpickle untrusted or tampered data. Prefer JSON "
            "for simple data interchange, or use a format with a "
            "validated schema. Only deserialize trusted data."
        ),

        "pickle-import": (
            "Remove the pickle import if it is unnecessary. Pickle "
            "deserialization can execute code when data is malicious. "
            "Do not use pickle.loads() on untrusted input; prefer JSON "
            "for ordinary data interchange."
        ),

        "weak-cryptography": (
            "Replace MD5 or SHA-1 when used for security-sensitive "
            "hashing. Use SHA-256 or SHA-3 where appropriate. For "
            "password storage, use a dedicated password-hashing "
            "algorithm such as Argon2id, scrypt, or bcrypt."
        ),

        "insecure-tls": (
            "Do not disable TLS certificate verification. Remove "
            "verify=False and use certificate verification. If a "
            "private certificate authority is required, configure "
            "its trusted CA bundle."
        ),

        "missing-request-timeout": (
            "Set an explicit timeout on network requests to avoid "
            "indefinite waits. For example:\n"
            "response = requests.get(url, timeout=10)\n"
            "Keep TLS certificate verification enabled; a timeout "
            "does not fix certificate-validation problems."
        ),

        "insecure-temp-path": (
            "Avoid hard-coded temporary paths such as /tmp and predictable "
            "filenames. Use tempfile.gettempdir() when you only need the "
            "temporary directory, or tempfile.NamedTemporaryFile() / "
            "TemporaryDirectory() when creating temporary resources. Let "
            "the secure API create the resource and generate its path."
        ),

        "insecure-temp-file": (
            "Avoid tempfile.mktemp(), which can introduce a "
            "race condition. Use tempfile.NamedTemporaryFile(), "
            "TemporaryDirectory(), or another secure temporary-file "
            "API appropriate to the use case."
        ),

        "security-random": (
            "Use the secrets module instead of random for security-"
            "sensitive tokens, passwords, or unpredictable values. "
            "The random module is suitable for non-security uses."
        ),

        "silent-exception": (
            "Do not silently suppress exceptions. Catch the specific "
            "exception you expect, handle the failure, or log useful "
            "diagnostic information."
        ),

        "broad-exception": (
            "Catch a specific exception type where possible. If a "
            "broad catch is necessary at an application boundary, "
            "log the error and handle it deliberately."
        ),

        "import-order": (
            "Sort and group imports according to your Ruff "
            "configuration. You can review suggested changes with:\n"
            "ruff check --select I your_file.py\n"
            "ruff check --select I --fix your_file.py\n"
            "Review the changes before accepting them."
        ),

        "unused-variable": (
            "Remove the unused assignment if it is unnecessary, or "
            "use the variable if it is part of the intended logic. "
            "Check whether the assignment was meant to preserve a "
            "result or validate an operation."
        ),

        "unused-import": (
            "Remove the unused import if it is not needed. Confirm "
            "that it is not being used for intentional registration "
            "or another side effect before removing it."
        ),

        "request-security": (
            "Configure an explicit request timeout and keep TLS "
            "certificate verification enabled. Review the network "
            "error-handling behavior."
        ),

        "unsafe-file": (
            "Use a context manager when opening files so that file "
            "handles are closed reliably. Validate file paths and "
            "handle expected I/O errors."
        ),

        "unknown": (
            "Review the source context and the tool's diagnostic. "
            "Confirm the finding is reachable and relevant, then "
            "apply a fix that preserves the intended behavior."
        ),
    }

    return fixes.get(family, fixes["unknown"])


# ============================================================
# FINDING CLASSIFICATION
# ============================================================

def identify_issue(finding):
    """
    Map AST, Bandit, and Ruff findings to common issue families.

    The family is used for deduplication. Findings are merged only
    when the file, line, normalized family, and source code match.
    """

    rule = safe_text(finding.get("rule", "")).upper()
    title = safe_text(finding.get("title", "")).lower()
    description = safe_text(finding.get("description", "")).lower()
    combined = f"{title} {description} {rule.lower()}"

    # Unsafe dynamic execution.
    if (
        "AST-EVAL" in rule
        or rule in {"B307"}
        or "eval(" in combined
        or "unsafe use of eval" in combined
    ):
        return "unsafe-eval"

    # Shell execution.
    if (
        "SHELL-EXECUTION" in rule
        or rule in {"B602", "B603", "B604", "B605", "B606", "B607"}
        or "shell=True" in combined
        or "starting a process with a shell" in combined
        or "os.system" in combined
    ):
        return "shell-execution"

    # Empty collection indexing and out-of-range indexes.
    if (
        "EMPTY-CONTAINER-INDEX" in rule
        or "INDEX-OUT-OF-RANGE" in rule
        or rule == "PLE0643"
        or "indexing an empty list" in combined
        or "empty sequence" in combined
    ):
        return "empty-container-index"

    # Known missing dictionary key.
    if (
        "DICT-KEY-NOT-FOUND" in rule
        or "keyerror" in combined
        or "dictionary key" in combined
        or "key not found" in combined
    ):
        return "dict-key-not-found"

    # Division by zero.
    if (
        "DIVISION-BY-ZERO" in rule
        or "division by zero" in combined
        or "modulo by zero" in combined
        or "zero denominator" in combined
    ):
        return "division-by-zero"

    # Mutable function defaults, including Ruff B006/B008.
    if (
        "MUTABLE-DEFAULT" in rule
        or rule in {"B006", "B008"}
        or "mutable default" in combined
        or "mutable data structures for argument defaults" in combined
        or "function call in default argument" in combined
    ):
        return "mutable-default"

    # Hard-coded credentials.
    if (
        "HARDCODED-SECRET" in rule
        or rule in {"B105", "B106", "B107"}
        or "hardcoded password" in combined
        or "hard-coded password" in combined
        or "hardcoded secret" in combined
        or "hard-coded secret" in combined
        or "hardcoded credential" in combined
    ):
        return "hardcoded-secret"

    # Unsafe deserialization.
    if (
        "UNSAFE-DESERIALIZATION" in rule
        or rule in {"B301", "B302", "B506"}
        or "pickle.loads" in combined
        or "unsafe deserialization" in combined
        or "deserialization of untrusted data" in combined
    ):
        return "unsafe-deserialization"

    # Pickle import warning is separate from a pickle.loads call.
    if (
        rule == "B403"
        or "pickle module" in combined
        or "pickle import" in combined
    ):
        return "pickle-import"

    # Weak cryptography. B324 specifically detects weak hashes.
    if (
        "WEAK-CRYPTOGRAPHY" in rule
        or rule in {"B303", "B304", "B305", "B324"}
        or "md5" in combined
        or "sha1" in combined
        or "weak hash" in combined
        or "weak cryptographic" in combined
    ):
        return "weak-cryptography"

    # Insecure TLS.
    if (
        "INSECURE-TLS" in rule
        or rule == "B501"
        or "verify=False" in combined
        or "certificate verification is disabled" in combined
        or "requests with verify=false" in combined
    ):
        return "insecure-tls"

    # Requests without timeouts. Keep this separate from TLS findings.
    if (
        "REQUEST_WITHOUT_TIMEOUT" in rule
        or rule == "B113"
        or "request_without_timeout" in combined
        or "without timeout" in combined
        or "no timeout" in combined
    ):
        return "missing-request-timeout"

    # B108: hard-coded temporary directory/path.
    if (
        rule == "B108"
        or "probable insecure usage of temp file" in combined
        or "insecure usage of temp file" in combined
        or "hardcoded tmp directory" in combined
        or "hard-coded tmp directory" in combined
    ):
        return "insecure-temp-path"

    # Insecure temporary-file creation, including tempfile.mktemp().
    if (
        "INSECURE-TEMP-FILE" in rule
        or rule == "B306"
        or "tempfile.mktemp" in combined
        or "insecure temporary file" in combined
    ):
        return "insecure-temp-file"

    # Non-cryptographic random numbers.
    if (
        "SECURITY-RANDOM" in rule
        or rule == "B311"
        or "random.random" in combined
        or "random module" in combined and "cryptograph" in combined
        or "cryptographically secure random" in combined
    ):
        return "security-random"

    # Exception handling. Bandit B110 and S110 identify try/except/pass.
    if (
        "SILENT-EXCEPTION" in rule
        or rule in {"B110", "S110"}
        or "try, except, pass detected" in combined
        or "exception: pass" in combined
        or "except exception" in combined and "pass" in combined
        or "silent exception" in combined
    ):
        return "silent-exception"

    if (
        rule == "BLE001"
        or "blind except" in combined
        or "blind exception" in combined
        or "blindly catching" in combined
        or "broad exception" in combined
    ):
        return "broad-exception"

    # Import ordering.
    if (
        rule == "I001"
        or "unsorted-imports" in rule
        or "unsorted import" in combined
        or "import block is un-sorted" in combined
        or "import block is unsorted" in combined
    ):
        return "import-order"

    # Ruff unused variable and import diagnostics.
    if (
        rule.startswith("F841")
        or "unused variable" in combined
        or "local variable" in combined and "assigned to but never used" in combined
    ):
        return "unused-variable"

    if (
        rule.startswith("F401")
        or "unused import" in combined
    ):
        return "unused-import"

    # File operations.
    if (
        "FILE-OPEN" in rule
        or "OPEN-WITHOUT-CONTEXT" in rule
        or "open file without a context manager" in combined
        or "open without a context manager" in combined
    ):
        return "unsafe-file"

    # General unsafe indexing.
    if (
        "UNSAFE-INDEXING" in rule
        or "index out of range" in combined
    ):
        return "unsafe-indexing"

    # Unknown findings remain separate from unrelated families.
    return "unknown"


# ============================================================
# AST VISITOR
# ============================================================

class CodeReviewVisitor(ast.NodeVisitor):
    """AST analyzer for common Python bugs and security issues."""

    def __init__(self, source, filename):
        self.source = source
        self.lines = source.splitlines()
        self.filename = normalize_path(filename)
        self.findings = []
        self.parents = []

    def add(
        self,
        node,
        rule,
        title,
        severity,
        description,
        fix=None,
        confidence="High",
    ):
        line = getattr(node, "lineno", 1)
        code = source_line(self.lines, line)

        family = identify_issue({
            "rule": rule,
            "title": title,
            "description": description,
        })

        if fix is None:
            fix = get_fix_recommendation(
                family,
                code=code,
                filename=self.filename,
            )

        self.findings.append(
            make_finding(
                filename=self.filename,
                line=line,
                rule=rule,
                title=title,
                severity=severity,
                description=description,
                fix=fix,
                tool=TOOL_AST,
                code=code,
                confidence=confidence,
            )
        )

    def visit_Call(self, node):
        func_name = ""

        if isinstance(node.func, ast.Name):
            func_name = node.func.id

        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func

            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value

            if isinstance(current, ast.Name):
                parts.append(current.id)

            func_name = ".".join(reversed(parts))

        # eval() is unsafe for untrusted input.
        if func_name == "eval":
            self.add(
                node,
                "AST-EVAL",
                "Unsafe use of eval()",
                "High",
                "eval() executes dynamically supplied Python expressions. "
                "If the expression is influenced by untrusted input, "
                "arbitrary code may execute.",
            )

        # exec() can execute arbitrary code.
        if func_name == "exec":
            self.add(
                node,
                "AST-EXEC",
                "Dynamic code execution with exec()",
                "High",
                "exec() dynamically executes Python code. Avoid executing "
                "untrusted or insufficiently validated strings.",
            )

        # Shell command execution.
        if func_name == "os.system":
            self.add(
                node,
                "AST-SHELL-EXECUTION",
                "Shell command execution",
                "High",
                "os.system() runs a command through a shell. "
                "String concatenation or untrusted input can create "
                "command-injection risks.",
            )

        if func_name.startswith("subprocess."):
            shell_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )

            if shell_true:
                self.add(
                    node,
                    "AST-SHELL-EXECUTION",
                    "Subprocess called with shell=True",
                    "High",
                    "Using shell=True may expose command execution to "
                    "shell injection if command data is not trusted.",
                )

        # Unsafe pickle deserialization.
        if func_name in {"pickle.loads", "pickle.load"}:
            self.add(
                node,
                "AST-UNSAFE-DESERIALIZATION",
                "Unsafe pickle deserialization",
                "High",
                "Pickle deserialization can execute arbitrary code when "
                "the serialized data is malicious.",
            )

        # Weak hashing algorithms.
        if func_name in {"hashlib.md5", "hashlib.sha1"}:
            algorithm = func_name.split(".")[-1].upper()

            self.add(
                node,
                "AST-WEAK-CRYPTOGRAPHY",
                f"Weak cryptographic hash: {algorithm}",
                "Medium",
                f"{algorithm} is not appropriate for security-sensitive "
                "collision-resistant hashing. Password storage requires "
                "a dedicated password-hashing algorithm.",
            )

        # TLS verification disabled.
        if func_name.startswith("requests.") or func_name.startswith("httpx."):
            for keyword in node.keywords:
                if (
                    keyword.arg == "verify"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    self.add(
                        node,
                        "AST-INSECURE-TLS",
                        "TLS certificate verification disabled",
                        "High",
                        "verify=False disables certificate validation and "
                        "can allow interception of network traffic.",
                    )
                    break

        # Temporary-file race condition.
        if func_name == "tempfile.mktemp":
            self.add(
                node,
                "AST-INSECURE-TEMP-FILE",
                "Insecure temporary file creation",
                "Medium",
                "tempfile.mktemp() returns a name without securely "
                "creating the file, allowing race conditions.",
            )

        # Security-sensitive random generation.
        if func_name in {
            "random.random",
            "random.randint",
            "random.randrange",
            "random.choice",
            "random.getrandbits",
        }:
            self.add(
                node,
                "AST-SECURITY-RANDOM",
                "Non-cryptographic random number generator",
                "Medium",
                "The random module is not designed for security-sensitive "
                "tokens or unpredictable values. Use secrets when "
                "cryptographic randomness is required.",
                confidence="Medium",
            )

        # Detect constant division by zero.
        if func_name == "divmod":
            if len(node.args) >= 2:
                denominator = node.args[1]

                if (
                    isinstance(denominator, ast.Constant)
                    and denominator.value == 0
                ):
                    self.add(
                        node,
                        "AST-DIVISION-BY-ZERO",
                        "Division by zero",
                        "High",
                        "divmod() is called with a constant zero denominator.",
                    )

        self.generic_visit(node)

    def visit_BinOp(self, node):
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            denominator = node.right

            if (
                isinstance(denominator, ast.Constant)
                and isinstance(denominator.value, (int, float))
                and not isinstance(denominator.value, bool)
                and denominator.value == 0
            ):
                operator_name = (
                    "modulo"
                    if isinstance(node.op, ast.Mod)
                    else "division"
                )

                self.add(
                    node,
                    "AST-DIVISION-BY-ZERO",
                    f"Constant zero in {operator_name}",
                    "High",
                    f"The {operator_name} operation uses a constant zero "
                    "denominator and will raise an exception.",
                )

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # Mutable defaults.
        defaults = list(node.args.defaults)

        for default in defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.add(
                    node,
                    "AST-MUTABLE-DEFAULT",
                    "Mutable default argument",
                    "Medium",
                    "A mutable default object is shared between calls "
                    "to the function and may cause unexpected state "
                    "to persist between invocations.",
                )
                break

        self.generic_visit(node)

    def visit_Assign(self, node):
        # Hard-coded credentials at module or function level.
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            name = target.id.lower()

            secret_name = any(
                token in name
                for token in (
                    "password",
                    "passwd",
                    "secret",
                    "api_key",
                    "apikey",
                    "access_token",
                    "auth_token",
                )
            )

            if (
                secret_name
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and len(node.value.value.strip()) >= 4
            ):
                self.add(
                    node,
                    "AST-HARDCODED-SECRET",
                    "Possible hard-coded secret",
                    "High",
                    f"The variable '{target.id}' is assigned a string "
                    "literal that may contain a credential or secret.",
                    confidence="Medium",
                )

        self.generic_visit(node)

    def visit_Subscript(self, node):
        # Known empty literal collection indexing.
        if (
            isinstance(node.value, (ast.List, ast.Tuple, ast.Constant))
            and isinstance(node.slice, ast.Constant)
        ):
            is_empty = (
                isinstance(node.value, (ast.List, ast.Tuple))
                and len(node.value.elts) == 0
            )

            if isinstance(node.value, ast.Constant):
                is_empty = (
                    isinstance(node.value.value, (str, bytes))
                    and len(node.value.value) == 0
                )

            if is_empty:
                self.add(
                    node,
                    "AST-EMPTY-CONTAINER-INDEX",
                    "Indexing an empty collection",
                    "High",
                    "The code indexes a known empty list, tuple, or "
                    "string, which raises an indexing exception.",
                )

        # Known dictionary literal with a missing constant key.
        if isinstance(node.value, ast.Dict) and isinstance(
            node.slice, ast.Constant
        ):
            keys = []

            for key in node.value.keys:
                if isinstance(key, ast.Constant):
                    keys.append(key.value)

            if node.slice.value not in keys:
                self.add(
                    node,
                    "AST-DICT-KEY-NOT-FOUND",
                    "Dictionary key missing",
                    "Medium",
                    "The dictionary literal does not contain the "
                    "constant key accessed by this expression.",
                )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        # Bare except.
        if node.type is None:
            self.add(
                node,
                "AST-BARE-EXCEPT",
                "Bare except clause",
                "Medium",
                "A bare except catches nearly every exception, including "
                "exceptions that are usually better allowed to propagate.",
            )

        # except Exception: pass
        if isinstance(node.type, ast.Name) and node.type.id == "Exception":
            body_is_pass = (
                len(node.body) == 1
                and isinstance(node.body[0], ast.Pass)
            )

            if body_is_pass:
                self.add(
                    node,
                    "AST-SILENT-EXCEPTION",
                    "Exception silently ignored",
                    "Medium",
                    "The handler catches Exception and immediately passes, "
                    "hiding errors and making failures difficult to debug.",
                )

        self.generic_visit(node)

    def visit_With(self, node):
        self.generic_visit(node)

    def visit_CallForOpen(self, node):
        # Kept as a separate helper for potential future file-open checks.
        pass


# ============================================================
# AST ANALYSIS
# ============================================================

def analyze_ast(source, filename):
    """Parse Python source and run AST checks."""
    findings = []

    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [
            make_finding(
                filename=filename,
                line=exc.lineno or 1,
                rule="AST-SYNTAX-ERROR",
                title="Python syntax error",
                severity="High",
                description=(
                    f"Python could not parse the source: "
                    f"{exc.msg or 'unknown syntax error'}."
                ),
                fix=(
                    "Correct the syntax error at or near the reported line, "
                    "then rerun the analysis."
                ),
                tool=TOOL_AST,
                code=source_line(source.splitlines(), exc.lineno or 1),
                confidence="High",
            )
        ]

    visitor = CodeReviewVisitor(source, filename)
    visitor.visit(tree)
    findings.extend(visitor.findings)

    # Detect calls to open() that are not managed by a with statement.
    parent_map = {}

    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Name) or node.func.id != "open":
            continue

        parent = parent_map.get(node)
        inside_with = isinstance(parent, ast.withitem)

        current = parent

        while current is not None and not inside_with:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                break

            if isinstance(current, (ast.With, ast.AsyncWith)):
                inside_with = True
                break

            current = parent_map.get(current)

        if not inside_with:
            line = getattr(node, "lineno", 1)
            code = source_line(source.splitlines(), line)

            findings.append(
                make_finding(
                    filename=filename,
                    line=line,
                    rule="AST-OPEN-WITHOUT-CONTEXT",
                    title="File opened without a context manager",
                    severity="Low",
                    description=(
                        "open() is not directly managed by a with "
                        "statement. Unmanaged file handles can remain "
                        "open longer than intended."
                    ),
                    fix=(
                        "Use a context manager, for example:\n"
                        "with open(path, 'r', encoding='utf-8') as file:\n"
                        "    data = file.read()"
                    ),
                    tool=TOOL_AST,
                    code=code,
                    confidence="Medium",
                )
            )

    return findings


def bandit_source_location(source, test_id, reported_line):
    """Map Bandit diagnostics to the actual source node they describe."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return int(reported_line or 1)

    test_id = safe_text(test_id).upper()
    reported = int(reported_line or 1)
    candidates = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
            if test_id == "B602" and name.startswith("subprocess.") and any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                and kw.value.value is True for kw in node.keywords
            ):
                candidates.append(node.lineno)
            elif test_id == "B306" and name.endswith(".mktemp"):
                candidates.append(node.lineno)
            elif test_id == "B311" and name.startswith("random."):
                candidates.append(node.lineno)
            elif test_id == "B113" and name.startswith(("requests.", "httpx.")):
                candidates.append(node.lineno)

        if test_id == "B105" and isinstance(node, ast.Assign):
            names = [t.id.lower() for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
            if any(any(token in name for token in ("password", "passwd", "secret", "token", "api_key")) for name in names) and isinstance(value, ast.Constant) and isinstance(value.value, str):
                candidates.append(node.lineno)
        elif test_id == "B404" and isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(alias.name == "subprocess" or alias.name.startswith("subprocess.") for alias in node.names):
                candidates.append(node.lineno)

    return min(candidates, key=lambda line: abs(line - reported)) if candidates else reported


def ruff_source_location(source, rule_code, message, reported_line):
    """Recover a source line for Ruff diagnostics, including out-of-range rows."""
    lines = source.splitlines()
    reported = int(reported_line or 1)
    if 1 <= reported <= len(lines):
        return reported

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return max(1, min(reported, len(lines) or 1))

    rule_code = safe_text(rule_code).upper()
    message = safe_text(message)
    candidates = []

    if rule_code == "I001":
        candidates = [node.lineno for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    elif rule_code == "F401":
        match = re.search(r"`([^`]+)` imported but unused", message)
        imported = match.group(1) if match else ""
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if any((alias.asname or alias.name.split(".")[0]) == imported for alias in node.names):
                    candidates.append(node.lineno)
    elif rule_code == "F841":
        match = re.search(r"Local variable `([^`]+)`", message)
        variable = match.group(1) if match else ""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == variable for t in node.targets):
                candidates.append(node.lineno)

    if candidates:
        return min(candidates, key=lambda line: abs(line - reported))
    return max(1, min(reported, len(lines) or 1))


# ============================================================
# BANDIT INTEGRATION
# ============================================================

def run_bandit(source, filename):
    """
    Run Bandit against a temporary source file.

    Bandit is optional. If unavailable, return a diagnostic instead
    of failing the application.
    """
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            safe_name = Path(filename).name or "uploaded_file.py"
            temp_path = os.path.join(temp_dir, safe_name)

            with open(temp_path, "w", encoding="utf-8") as file:
                file.write(source)

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "bandit",
                    "-f",
                    "json",
                    "-q",
                    temp_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            output = result.stdout.strip()

            if not output:
                if "No module named bandit" in result.stderr:
                    return [], "Bandit is not installed."

                return [], (
                    "Bandit returned no JSON findings. "
                    "Check its installation and command output."
                )

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                return [], (
                    "Bandit output could not be parsed. "
                    "Check the Bandit installation."
                )

            findings = []

            for item in data.get("results", []):
                test_id = item.get("test_id", "BANDIT-UNKNOWN")
                line = bandit_source_location(source, test_id, item.get("line_number", 1))
                code = source_line(source.splitlines(), line)
                title = item.get("issue_text", "Security finding")
                severity = normalize_severity(
                    item.get("issue_severity", "Medium")
                )
                confidence = item.get("issue_confidence", "Medium")

                family = identify_issue({
                    "rule": test_id,
                    "title": title,
                    "description": title,
                })

                fix = get_fix_recommendation(
                    family,
                    code=code,
                    filename=filename,
                )

                findings.append(
                    make_finding(
                        filename=filename,
                        line=line,
                        rule=test_id,
                        title=title,
                        severity=severity,
                        description=title,
                        fix=fix,
                        tool=TOOL_BANDIT,
                        code=code,
                        confidence=confidence,
                    )
                )

            return findings, None

    except subprocess.TimeoutExpired:
        return [], "Bandit scan timed out after 30 seconds."

    except OSError as exc:
        return [], f"Could not execute Bandit: {exc}"


# ============================================================
# RUFF INTEGRATION
# ============================================================

def run_ruff(source, filename):
    """
    Run Ruff against a temporary Python file.

    Ruff is optional. Diagnostics are returned separately from
    code findings.
    """
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            safe_name = Path(filename).name or "uploaded_file.py"
            temp_path = os.path.join(temp_dir, safe_name)

            with open(temp_path, "w", encoding="utf-8") as file:
                file.write(source)

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ruff",
                    "check",
                    "--output-format",
                    "json",
                    temp_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            output = result.stdout.strip()

            if not output:
                if "No module named ruff" in result.stderr:
                    return [], "Ruff is not installed."

                # Ruff may return no JSON findings when clean.
                if result.returncode == 0:
                    return [], None

                return [], (
                    "Ruff returned no JSON findings. "
                    "Check its installation and command output."
                )

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                return [], (
                    "Ruff output could not be parsed. "
                    "Check the Ruff installation."
                )

            findings = []

            for item in data:
                location = item.get("location", {})
                reported_line = location.get("row", 1)
                rule_data = item.get("code") or {}
                rule_code = (
                    rule_data.get("code", "RUFF-UNKNOWN")
                    if isinstance(rule_data, dict)
                    else safe_text(rule_data)
                )
                message = item.get("message", "Code quality finding")
                line = ruff_source_location(source, rule_code, message, reported_line)
                code = source_line(source.splitlines(), line)

                family = identify_issue({
                    "rule": rule_code,
                    "title": message,
                    "description": message,
                })

                fix_data = item.get("fix")
                if fix_data:
                    fix = (
                        get_fix_recommendation(
                            family,
                            code=code,
                            filename=filename,
                        )
                    )
                    fix_title = fix_data.get("message")
                    if fix_title:
                        fix = f"{fix_title}\n\n{fix}"
                else:
                    fix = get_fix_recommendation(
                        family,
                        code=code,
                        filename=filename,
                    )

                findings.append(
                    make_finding(
                        filename=filename,
                        line=line,
                        rule=rule_code,
                        title=message,
                        severity="Low",
                        description=message,
                        fix=fix,
                        tool=TOOL_RUFF,
                        code=code,
                        confidence="High",
                    )
                )

            return findings, None

    except subprocess.TimeoutExpired:
        return [], "Ruff scan timed out after 30 seconds."

    except OSError as exc:
        return [], f"Could not execute Ruff: {exc}"


# ============================================================
# CONSOLIDATION AND DUPLICATE DETECTION
# ============================================================

def finding_fingerprint(finding):
    """
    Return a key for finding consolidation.

    Source line and normalized issue family are included so that
    different findings on the same line are not merged incorrectly.
    """
    family = identify_issue(finding)

    return (
        normalize_path(finding.get("filename", "")),
        int(finding.get("line", 1) or 1),
        family,
        safe_text(finding.get("code", "")).strip(),
    )


def _silent_exception_handlers(source):
    """Return (handler_line, last_body_line) ranges for `except Exception: pass` handlers."""
    if not source:
        return []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    handlers = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if not isinstance(node.type, ast.Name) or node.type.id != "Exception":
            continue
        if len(node.body) != 1 or not isinstance(node.body[0], ast.Pass):
            continue
        handlers.append((node.lineno, getattr(node.body[0], "end_lineno", node.body[0].lineno)))
    return handlers


def consolidate_findings(findings, source=None):
    """
    Merge findings only when file, source location, source text, and issue family
    match. AST, Bandit, and Ruff diagnostics for the same `except Exception: pass`
    handler are normalized to the handler line. BLE001/broad-exception is folded
    into silent-exception only for that exact pass-only handler. Different issues
    on the same line, including B113 and B501, remain separate.
    """
    consolidated = {}
    exception_ranges = _silent_exception_handlers(source)

    def canonicalize_exception_location(finding, family):
        line = int(finding.get("line", 1) or 1)
        if family not in {"silent-exception", "broad-exception"}:
            return line, safe_text(finding.get("code", "")).strip(), family
        for handler_line, last_body_line in exception_ranges:
            if handler_line <= line <= last_body_line:
                if family == "broad-exception":
                    family = "silent-exception"
                code = source_line(source.splitlines(), handler_line) if source else safe_text(finding.get("code", "")).strip()
                return handler_line, code.strip(), family
        return line, safe_text(finding.get("code", "")).strip(), family

    silent_locations = set()
    for item in findings:
        family = identify_issue(item)
        if family in {"silent-exception", "broad-exception"}:
            line, code, family = canonicalize_exception_location(item, family)
            if family == "silent-exception":
                silent_locations.add((normalize_path(item.get("filename", "")), line, code))

    for original in findings:
        finding = dict(original)
        finding["filename"] = normalize_path(finding.get("filename", ""))
        finding["severity"] = normalize_severity(finding.get("severity", "Medium"))

        family = identify_issue(finding)
        canonical_line, canonical_code, family = canonicalize_exception_location(finding, family)
        location = (finding["filename"], canonical_line, canonical_code)
        if family == "broad-exception" and location in silent_locations:
            family = "silent-exception"

        # Store canonical coordinates only for findings associated with a
        # verified pass-only exception handler; leave all other locations intact.
        is_exception_finding = identify_issue(finding) in {"silent-exception", "broad-exception"}
        key_line = canonical_line if is_exception_finding else int(finding.get("line", 1) or 1)
        key_code = canonical_code if is_exception_finding else safe_text(finding.get("code", "")).strip()
        key = (finding["filename"], key_line, family, key_code)
        if is_exception_finding:
            finding["line"] = key_line
            finding["code"] = key_code

        if key not in consolidated:
            finding["tools"] = [
                part.strip() for part in safe_text(finding.get("tool", "Unknown")).split(",")
                if part.strip()
            ]
            finding["rules"] = [
                part.strip() for part in safe_text(finding.get("rule", "UNKNOWN")).split(",")
                if part.strip()
            ]
            finding["related_findings"] = []
            consolidated[key] = finding
            continue

        existing = consolidated[key]
        if SEVERITY_ORDER.get(finding["severity"], 2) < SEVERITY_ORDER.get(existing["severity"], 2):
            existing["severity"] = finding["severity"]

        for tool in finding.get("tools", [finding.get("tool", "Unknown")]):
            if tool not in existing["tools"]:
                existing["tools"].append(tool)
        for rule in finding.get("rules", [finding.get("rule", "UNKNOWN")]):
            if rule not in existing["rules"]:
                existing["rules"].append(rule)

        if len(finding.get("description", "")) > len(existing.get("description", "")):
            existing["description"] = finding["description"]
        if len(finding.get("fix", "")) > len(existing.get("fix", "")):
            existing["fix"] = finding["fix"]
        if existing.get("confidence") != "High" and finding.get("confidence") == "High":
            existing["confidence"] = "High"

    results = list(consolidated.values())
    for finding in results:
        finding["tool"] = ", ".join(sorted(set(finding.pop("tools", []))))
        finding["rule"] = ", ".join(sorted(set(finding.pop("rules", []))))
        finding["related_findings"] = finding.get("related_findings", [])

    results.sort(key=lambda item: (
        SEVERITY_ORDER.get(item.get("severity", "Medium"), 2),
        item.get("filename", ""), int(item.get("line", 1) or 1), item.get("title", "")
    ))
    return results


# REPORT GENERATION
# ============================================================

def build_report(findings, filename, source, diagnostics=None):
    """Create a structured JSON-compatible report."""
    counts = {severity: 0 for severity in SEVERITIES}

    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        counts[severity] += 1

    return {
        "report_name": "Intelligent Code Review & Bug Detection System",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "filename": normalize_path(filename),
        "source_sha256": hashlib.sha256(
            source.encode("utf-8", errors="replace")
        ).hexdigest(),
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
            "tools": ["AST", "Bandit", "Ruff"],
        },
        "diagnostics": diagnostics or [],
        "findings": findings,
    }


def export_json(report):
    """Serialize the report to JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False)


def export_csv(findings):
    """Serialize findings to CSV."""
    output = io.StringIO()

    columns = [
        "filename",
        "line",
        "severity",
        "rule",
        "title",
        "description",
        "fix",
        "tool",
        "code",
        "confidence",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=columns,
        extrasaction="ignore",
    )

    writer.writeheader()

    for finding in findings:
        row = dict(finding)
        row["filename"] = normalize_path(row.get("filename", ""))
        row["severity"] = normalize_severity(row.get("severity"))
        writer.writerow(row)

    return output.getvalue()


# ============================================================
# UI COMPONENTS
# ============================================================

def render_metric_row(findings):
    """Display finding totals by severity."""
    counts = {severity: 0 for severity in SEVERITIES}

    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        counts[severity] += 1

    total = len(findings)

    columns = st.columns(6)

    columns[0].metric("Total Findings", total)
    columns[1].metric("Critical", counts["Critical"])
    columns[2].metric("High", counts["High"])
    columns[3].metric("Medium", counts["Medium"])
    columns[4].metric("Low", counts["Low"])
    columns[5].metric("Info", counts["Info"])


def render_finding(finding, index):
    """Render a single finding and its remediation details."""
    severity = normalize_severity(finding.get("severity", "Medium"))
    icon = SEVERITY_COLORS.get(severity, "⚪")
    filename = finding.get("filename", "unknown.py")
    line = finding.get("line", 1)
    title = finding.get("title", "Finding")
    tools = finding.get("tool", "Unknown")
    rule = finding.get("rule", "UNKNOWN")

    heading = (
        f"{icon} {severity} — {title} "
        f"(line {line})"
    )

    with st.expander(heading, expanded=False):
        left, right = st.columns([3, 1])

        with left:
            st.markdown(f"**File:** `{filename}`")
            st.markdown(f"**Rule:** `{rule}`")
            st.markdown(f"**Detected by:** {tools}")

        with right:
            st.markdown(
                f"**Confidence:** {finding.get('confidence', 'Medium')}"
            )

        st.markdown("**Description**")
        st.write(finding.get("description", "No description available."))

        code = finding.get("code", "")
        if code:
            st.markdown("**Source code**")
            st.code(code, language="python")

        st.markdown("**Recommended fix**")
        st.code(finding.get("fix", "Review the source context."), language="text")


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🔍 Code Review")
st.sidebar.caption("Intelligent Code Review & Bug Detection")

st.sidebar.markdown("---")

analysis_mode = st.sidebar.radio(
    "Source selection",
    ["Demo Code", "Upload Python File", "Paste Python Code"],
)

st.sidebar.markdown("---")

st.sidebar.markdown("### Analysis tools")
run_ast = st.sidebar.checkbox("AST Analysis", value=True)
run_bandit_enabled = st.sidebar.checkbox("Bandit Security Scan", value=True)
run_ruff_enabled = st.sidebar.checkbox("Ruff Code Quality", value=True)

st.sidebar.markdown("---")
st.sidebar.caption(
    "Bandit and Ruff are optional. Install them to enable the "
    "corresponding scans."
)


# ============================================================
# SOURCE SELECTION
# ============================================================

DEMO_SOURCES = {
    "Safe Demo": ("safe_demo.py", '''def calculate_total(prices):
    """Return the sum of prices."""
    return sum(prices)


def find_user(users, user_id):
    for user in users:
        if user.get("id") == user_id:
            return user
    return None


def main():
    prices = [12.50, 7.25, 3.00]
    print(f"Total: {calculate_total(prices):.2f}")


if __name__ == "__main__":
    main()
'''),
    "Unsafe Demo": ("demo_vulnerable.py", DEMO_SOURCE),
    "Sample Code": ("sample_demo.py", '''import math

def circle_area(radius):
    if radius < 0:
        raise ValueError("radius must be non-negative")
    return math.pi * radius ** 2

def main():
    for radius in (1, 2, 3):
        print(f"Area for radius {radius}: {circle_area(radius):.2f}")

if __name__ == "__main__":
    main()
'''),
}

filename = "demo_vulnerable.py"
source = DEMO_SOURCE

if analysis_mode == "Demo Code":
    demo_choice = st.selectbox("Choose demo example", list(DEMO_SOURCES.keys()))
    filename, source = DEMO_SOURCES[demo_choice]

elif analysis_mode == "Upload Python File":
    uploaded_file = st.file_uploader(
        "Upload a Python source file",
        type=["py"],
        help="Upload a .py file for static analysis.",
    )

    if uploaded_file is None:
        st.info("Upload a Python file to begin analysis.")
        st.stop()

    filename = uploaded_file.name
    source = uploaded_file.getvalue().decode("utf-8", errors="replace")

elif analysis_mode == "Paste Python Code":
    filename = st.text_input(
        "Filename for this source",
        value="pasted_code.py",
    )

    source = st.text_area(
        "Paste Python source code",
        value=DEMO_SOURCE,
        height=350,
    )

    if not source.strip():
        st.warning("Paste some Python source code before running analysis.")
        st.stop()


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🔍 Intelligent Code Review & Bug Detection</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">'
    'Static analysis for Python bugs, security risks, and code quality.'
    '</div>',
    unsafe_allow_html=True,
)

source_hash = hashlib.sha256(
    source.encode("utf-8", errors="replace")
).hexdigest()

header_left, header_right = st.columns([3, 1])

with header_left:
    st.markdown(f"**Current file:** `{filename}`")

with header_right:
    st.caption(f"SHA-256: `{source_hash[:16]}…`")


# ============================================================
# SOURCE PREVIEW
# ============================================================

with st.expander("View source code", expanded=False):
    st.code(source, language="python")


# ============================================================
# RUN ANALYSIS
# ============================================================

st.markdown("---")

if st.button("🚀 Run Code Review", type="primary", use_container_width=True):
    raw_findings = []
    diagnostics = []

    progress = st.progress(0, text="Preparing analysis...")
    total_phases = (
        int(run_ast)
        + int(run_bandit_enabled)
        + int(run_ruff_enabled)
    )

    if total_phases == 0:
        st.warning("Enable at least one analysis tool in the sidebar.")
        st.stop()

    completed = 0

    if run_ast:
        progress.progress(
            completed / total_phases,
            text="Phase 1: Running AST analysis...",
        )

        ast_findings = analyze_ast(source, filename)
        raw_findings.extend(ast_findings)

        completed += 1

    if run_bandit_enabled:
        progress.progress(
            completed / total_phases,
            text="Phase 2: Running Bandit security scan...",
        )

        bandit_findings, bandit_diagnostic = run_bandit(source, filename)
        raw_findings.extend(bandit_findings)

        if bandit_diagnostic:
            diagnostics.append(
                {"tool": "Bandit", "message": bandit_diagnostic}
            )

        completed += 1

    if run_ruff_enabled:
        progress.progress(
            completed / total_phases,
            text="Phase 3: Running Ruff code-quality scan...",
        )

        ruff_findings, ruff_diagnostic = run_ruff(source, filename)
        raw_findings.extend(ruff_findings)

        if ruff_diagnostic:
            diagnostics.append(
                {"tool": "Ruff", "message": ruff_diagnostic}
            )

        completed += 1

    progress.progress(1.0, text="Analysis complete.")

    final_findings = consolidate_findings(raw_findings, source=source)

    report = build_report(
        findings=final_findings,
        filename=filename,
        source=source,
        diagnostics=diagnostics,
    )

    st.session_state["review_findings"] = final_findings
    st.session_state["review_report"] = report
    st.session_state["review_source"] = source
    st.session_state["review_filename"] = filename
    st.session_state["review_diagnostics"] = diagnostics

    st.success("Code review completed successfully.")


# ============================================================
# RESULTS
# ============================================================

if "review_findings" in st.session_state:
    findings = st.session_state["review_findings"]
    report = st.session_state["review_report"]
    diagnostics = st.session_state.get("review_diagnostics", [])

    st.markdown("---")
    st.header("📊 Analysis Results")

    st.caption(
        f"Report generated at {report.get('generated_at', 'unknown time')} "
        f"for `{report.get('filename', 'unknown.py')}`"
    )

    render_metric_row(findings)

    st.markdown("---")

    # Tool diagnostics.
    if diagnostics:
        with st.expander("Analysis tool diagnostics", expanded=True):
            for diagnostic in diagnostics:
                tool = diagnostic.get("tool", "Tool")
                message = diagnostic.get("message", "")

                if "not installed" in message.lower():
                    st.warning(f"**{tool}:** {message}")
                else:
                    st.info(f"**{tool}:** {message}")

    # Findings filter controls.
    st.subheader("Findings")

    filter_left, filter_middle, filter_right = st.columns([2, 2, 3])

    with filter_left:
        severity_filter = st.multiselect(
            "Severity",
            options=SEVERITIES,
            default=SEVERITIES,
        )

    with filter_middle:
        tool_options = sorted({
            tool.strip()
            for finding in findings
            for tool in finding.get("tool", "").split(",")
            if tool.strip()
        })

        selected_tools = st.multiselect(
            "Analysis tool",
            options=tool_options,
            default=tool_options,
        )

    with filter_right:
        search_text = st.text_input(
            "Search findings",
            placeholder="Search title, rule, filename, or description...",
        )

    filtered_findings = []

    for finding in findings:
        if severity_filter and finding.get("severity") not in severity_filter:
            continue

        finding_tools = {
            item.strip()
            for item in finding.get("tool", "").split(",")
        }

        if selected_tools and not finding_tools.intersection(selected_tools):
            continue

        searchable = " ".join([
            safe_text(finding.get("title")),
            safe_text(finding.get("rule")),
            safe_text(finding.get("filename")),
            safe_text(finding.get("description")),
            safe_text(finding.get("code")),
        ]).lower()

        if search_text and search_text.lower() not in searchable:
            continue

        filtered_findings.append(finding)

    st.caption(
        f"Showing {len(filtered_findings)} of {len(findings)} "
        "consolidated findings."
    )

    if not filtered_findings:
        st.info("No findings match the current filters.")

    else:
        for index, finding in enumerate(filtered_findings, start=1):
            render_finding(finding, index)

    # Severity chart.
    st.markdown("---")
    st.subheader("Severity Distribution")

    severity_counts = report["summary"]["severity_counts"]

    chart_data = {
        "Severity": SEVERITIES,
        "Count": [severity_counts[severity] for severity in SEVERITIES],
    }

    st.bar_chart(
        chart_data,
        x="Severity",
        y="Count",
        use_container_width=True,
    )

    # Exports.
    st.markdown("---")
    st.subheader("📥 Export Report")

    export_left, export_middle, export_right = st.columns(3)

    with export_left:
        json_data = export_json(report)

        st.download_button(
            "Download JSON Report",
            data=json_data,
            file_name="code_review_report.json",
            mime="application/json",
            use_container_width=True,
        )

    with export_middle:
        csv_data = export_csv(findings)

        st.download_button(
            "Download CSV Report",
            data=csv_data,
            file_name="code_review_report.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with export_right:
        st.download_button(
            "Download Source Code",
            data=st.session_state.get("review_source", ""),
            file_name=st.session_state.get(
                "review_filename", "reviewed_code.py"
            ),
            mime="text/x-python",
            use_container_width=True,
        )

    # Summary.
    st.markdown("---")
    st.subheader("Review Summary")

    high_risk = (
        severity_counts["Critical"]
        + severity_counts["High"]
    )

    if high_risk:
        st.warning(
            f"{high_risk} Critical/High severity finding(s) require "
            "priority review."
        )
    elif findings:
        st.info(
            "No Critical or High severity findings were reported. "
            "Review Medium and Low findings before considering the "
            "source ready."
        )
    else:
        st.success(
            "No findings were reported by the enabled analysis tools. "
            "This does not guarantee that the code is free from defects."
        )

    st.caption(
        "Static analysis can produce false positives and may miss "
        "runtime, configuration, dependency, and business-logic defects. "
        "Review findings in context and test changes before deployment."
    )

else:
    st.info(
        "Choose a source file or use the demo, enable the analysis tools "
        "you want, and click **Run Code Review** to view results."
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")
st.caption(
    "Intelligent Code Review & Bug Detection System | "
    "AST + Bandit + Ruff | Static analysis only"
)
