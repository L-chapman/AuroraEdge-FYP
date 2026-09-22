# Stage 11 - Analysis Module + Matplotlib Figures

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../README.md) and [`testing guide`](TESTING.md).

## Overview
Stage 11 deliverable: Implemented statistical analysis and visualisation capabilities for scan results, producing academic-quality charts and figures.

## Features

Located in `src/app/analysis.py`:

### Statistical Analysis

```python
from app.analysis import calculate_statistics

stats = calculate_statistics(scan_results)
# Returns:
# {
#     "total_domains": 50,
#     "avg_score": 67.4,
#     "min_score": 15,
#     "max_score": 100,
#     "grade_distribution": {"A+": 5, "A": 12, "B": 18, ...},
#     "severity_distribution": {"OK": 10, "WARN": 25, "HIGH": 15},
#     "spf_adoption": 92.0,
#     "dmarc_adoption": 78.0,
#     "dkim_adoption": 65.0,
#     "mta_sts_adoption": 12.0,
#     "tls_rpt_adoption": 8.0
# }
```

### Chart Generation

The module generates matplotlib figures suitable for academic reports:

#### Grade Distribution Chart
```python
from app.analysis import generate_grade_chart

fig = generate_grade_chart(scan_results)
fig.savefig("docs/figures/grade_distribution.png", dpi=300)
```

#### Protocol Adoption Chart
```python
from app.analysis import generate_adoption_chart

fig = generate_adoption_chart(scan_results)
fig.savefig("docs/figures/protocol_adoption.png", dpi=300)
```

#### Score Distribution Histogram
```python
from app.analysis import generate_score_histogram

fig = generate_score_histogram(scan_results)
fig.savefig("docs/figures/score_histogram.png", dpi=300)
```

### Figure Styling
Charts use a consistent academic style:
- Professional colour palette
- Clear axis labels with units
- Appropriate legends
- Publication-quality DPI (300)

## Tests
- `test_analysis.py::test_calculate_statistics`
- `test_analysis.py::test_empty_statistics`

## Output Directory
Figures saved to: `docs/figures/`
