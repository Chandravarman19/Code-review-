# Phase 3 — Reliability and Duplicate-Finding Improvements

## What's included
- `app.py`: Streamlit code review application.
- `test_recommendations.py`: recommendation regression tests.
- `test_detection_engine.py`: AST detection, consolidation, severity, and export tests.
- `test_phase3_reliability.py`: input-size, scanner timeout, and diagnostic tests.

## Run on Windows (PowerShell)
If `.venv` is in the parent folder, from this project folder run:

```powershell
..\.venv\Scripts\python.exe -m unittest discover -s . -p "test*.py" -v
..\.venv\Scripts\python.exe -m streamlit run app.py
```

If the virtual environment is inside this folder, use `python -m unittest discover -s . -p "test*.py" -v` and `python -m streamlit run app.py` after activating it, or use `.\.venv\Scripts\python.exe` directly.

## Duplicate-detection change
A random-number warning is consolidated with a hard-coded temporary-path warning only when the same source line contains `random.random()` and evidence of a temporary path (`/tmp`, `\\tmp`, or `temp`). Standalone random-number warnings and different issue families remain separate.

## Validation
All 36 tests in this package passed in the build environment. This validates the included unit tests, not every possible Streamlit UI interaction.
