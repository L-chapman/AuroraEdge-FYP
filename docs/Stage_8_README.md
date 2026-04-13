# Stage 8 - Scoring System (0-100) + Letter Grades

## Overview
Stage 8 deliverable: Implemented a comprehensive scoring system that evaluates domain email security configurations and assigns both numeric scores (0-100) and letter grades (A+ to F).

## Features

### Scoring Weights
Located in `src/app/rules.py`:
```python
WEIGHTS = {
    "CRITICAL": 40,  # Major security risks (e.g., no SPF)
    "HIGH": 25,      # Significant issues (e.g., SPF >10 lookups)
    "WARN": 10,      # Warnings (e.g., DMARC p=none)
    "INFO": 2,       # Minor recommendations
    "OK": 0          # No penalty
}

GRADE_TABLE = [
    (90, "A+"),  # Excellent - fully hardened
    (80, "A"),   # Very good - minor tweaks
    (75, "B"),   # Good - some issues to address
    (60, "C"),   # Acceptable - notable gaps
    (40, "D"),   # Poor - significant vulnerabilities
    (0,  "F")    # Failing - critical security issues
]
```

### Score Calculation
1. Start with 100 points
2. Deduct points for each violation based on severity
3. Cap minimum at 0

## Usage

```python
from app.rules import evaluate

scan_result = {
    "spf_present": True,
    "dmarc_present": True,
    "dkim_present": True,
    # ... more fields
}

evaluation = evaluate(scan_result)
print(f"Score: {evaluation['score']}")  # e.g., 85
print(f"Grade: {evaluation['grade']}")  # e.g., "A"
```

## Tests
- `test_benchmark.py::TestScoringSystem::test_score_weights_are_defined`
- `test_benchmark.py::TestScoringSystem::test_score_weights_hierarchy`
- `test_benchmark.py::TestScoringSystem::test_perfect_score_for_perfect_config`
- `test_benchmark.py::TestScoringSystem::test_score_range_is_valid`
- `test_benchmark.py::TestScoringSystem::test_grade_thresholds`
