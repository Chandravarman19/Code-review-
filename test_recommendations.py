"""Regression tests for fix recommendations in the Streamlit code-review app.

Run from the project folder with:
    python -m unittest -v test_recommendations.py

The tests load the actual safe_text() and get_fix_recommendation() definitions
from app.py without executing Streamlit's UI.
"""
import ast
import re
import unittest
from pathlib import Path

APP_PATH = Path(__file__).with_name("app.py")
APP_TREE = ast.parse(APP_PATH.read_text(encoding="utf-8"))
_FUNCTIONS = [
    node for node in APP_TREE.body
    if isinstance(node, ast.FunctionDef)
    and node.name in {"safe_text", "get_fix_recommendation"}
]
_NAMESPACE = {"re": re}
exec(compile(ast.Module(body=_FUNCTIONS, type_ignores=[]), str(APP_PATH), "exec"), _NAMESPACE)
get_fix_recommendation = _NAMESPACE["get_fix_recommendation"]


class FixRecommendationRegressionTests(unittest.TestCase):
    def assert_fix_contains(self, family, code, *phrases):
        fix = get_fix_recommendation(family, code=code)
        normalized = fix.lower()
        for phrase in phrases:
            with self.subTest(family=family, phrase=phrase):
                self.assertIn(phrase.lower(), normalized)

    def test_eval_recommends_literal_parser_and_allowlist(self):
        self.assert_fix_contains(
            "unsafe-eval", "result = eval(user_input)",
            "ast.literal_eval()", "ValueError", "allowlist"
        )

    def test_shell_execution_recommends_argument_list_and_timeout(self):
        self.assert_fix_contains(
            "shell-execution", 'os.system("echo " + user_input)',
            "subprocess.run([", "shell=false", "timeout=10"
        )

    def test_pickle_recommends_json_and_schema_validation(self):
        self.assert_fix_contains(
            "unsafe-deserialization", "return pickle.loads(data)",
            "untrusted", "json", "expected schema"
        )

    def test_weak_hash_distinguishes_password_hashing(self):
        self.assert_fix_contains(
            "weak-cryptography", "hashlib.md5(password.encode())",
            "argon2id", "scrypt", "bcrypt"
        )

    def test_tls_fix_keeps_certificate_verification_enabled(self):
        self.assert_fix_contains(
            "insecure-tls", "requests.get(url, verify=False)",
            "server certificate", "trusted ca bundle"
        )

    def test_timeout_fix_does_not_conflate_tls(self):
        self.assert_fix_contains(
            "missing-request-timeout", "requests.get(url, verify=False)",
            "timeout=(3.05, 10)", "requests.timeout", "tls"
        )

    def test_mutable_default_recommends_none_and_fresh_object(self):
        self.assert_fix_contains(
            "mutable-default", "def calculate(value=[]):",
            "value=none", "if value is none", "fresh object"
        )

    def test_missing_dictionary_key_distinguishes_optional_and_required(self):
        self.assert_fix_contains(
            "dict-key-not-found", 'missing = {"name": "demo"}["password"]',
            "does not contain", ".get(", "required"
        )

    def test_hardcoded_secret_recommends_environment_and_rotation(self):
        self.assert_fix_contains(
            "hardcoded-secret", 'API_KEY = "example_secret"',
            "rotate", "os.environ", ".gitignore", "secret manager"
        )

    def test_silent_exception_recommends_specific_handling_and_logging(self):
        self.assert_fix_contains(
            "silent-exception", "except Exception: pass",
            "narrowest expected exception", "logger.exception", "re-raise"
        )

    def test_temp_path_randomness_uses_secure_tempfile_api(self):
        self.assert_fix_contains(
            "security-random", 'return os.path.join("/tmp", str(random.random()))',
            "temporary path", "namedtemporaryfile", "temporarydirectory"
        )

    def test_unused_variable_with_division_overlap_mentions_root_cause(self):
        self.assert_fix_contains(
            "unused-variable", "number = 10 / 0",
            "division", "zero denominator", "preserves the intended behavior"
        )

    def test_unused_variable_with_empty_index_overlap_mentions_root_cause(self):
        self.assert_fix_contains(
            "unused-variable", "first = [][0]",
            "empty sequence", "index", "resulting value should be used"
        )

    def test_unused_variable_with_missing_key_overlap_mentions_root_cause(self):
        self.assert_fix_contains(
            "unused-variable", 'missing = {"name": "demo"}["password"]',
            "dictionary literal", "key", "resulting value should be used"
        )

    def test_ordinary_unused_variable_keeps_generic_guidance(self):
        self.assert_fix_contains(
            "unused-variable", "value = 10",
            "remove the unused assignment", "intended logic"
        )

    def test_unknown_rule_has_safe_fallback(self):
        self.assert_fix_contains(
            "not-a-known-family", "some_call()",
            "review the source context", "preserves the intended behavior"
        )


if __name__ == "__main__":
    unittest.main()
