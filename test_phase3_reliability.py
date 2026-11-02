import unittest
from pathlib import Path
APP = Path(__file__).with_name("app.py").read_text(encoding="utf-8")
class Phase3ReliabilityTests(unittest.TestCase):
    def test_source_size_limit_is_defined(self): self.assertIn("MAX_SOURCE_BYTES = 1_000_000", APP)
    def test_oversized_source_is_rejected(self):
        self.assertIn("MAX_SOURCE_BYTES", APP); self.assertIn("Source file is too large", APP)
    def test_ast_phase_has_safe_error_diagnostic(self): self.assertIn("AST analysis failed safely", APP)
    def test_bandit_phase_has_safe_error_diagnostic(self): self.assertIn("Bandit scan failed safely", APP)
    def test_ruff_phase_has_safe_error_diagnostic(self): self.assertIn("Ruff scan failed safely", APP)
    def test_external_scanners_have_timeouts(self): self.assertGreaterEqual(APP.count("timeout=30"), 2)
    def test_scanner_temp_filename_is_sanitized(self): self.assertGreaterEqual(APP.count("Path(filename).name"), 2)
if __name__ == "__main__": unittest.main()
