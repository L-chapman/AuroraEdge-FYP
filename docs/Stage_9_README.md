# Stage 9 - SQLite Database + Persistent Scan History

## Overview
Week 13 deliverable: Implemented SQLite database persistence for storing scan results, enabling historical tracking and trend analysis.

## Database Schema

Located in `src/app/database.py`:

### Tables

#### `scans`
Tracks batch scan sessions:
```sql
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    domain_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running'
)
```

#### `results`
Stores individual domain scan results:
```sql
CREATE TABLE results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    
    -- Core fields
    spf_present INTEGER,
    spf_lookups INTEGER,
    spf_includes TEXT,
    spf_all TEXT,
    
    mx_present INTEGER,
    mx_count INTEGER,
    mx_hosts TEXT,
    
    dmarc_present INTEGER,
    dmarc_policy TEXT,
    -- ... more fields
    
    -- Evaluation results
    severity TEXT,
    score INTEGER,
    grade TEXT,
    violations TEXT,
    
    -- Full JSON for extensibility
    raw_json TEXT,
    
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
)
```

#### `domains`
Tracks unique domains and their latest scores:
```sql
CREATE TABLE domains (
    domain TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_scanned TEXT,
    scan_count INTEGER DEFAULT 1,
    best_score INTEGER,
    latest_score INTEGER,
    latest_grade TEXT
)
```

## API

```python
from app.database import AuroraDatabase

db = AuroraDatabase("state/auroraedge.db")

# Start a new scan session
scan_id = db.start_scan()

# Save a domain result
db.save_result(scan_id, domain, scan_result, evaluation)

# Complete the scan
db.complete_scan(scan_id)

# Query history
stats = db.get_statistics()
recent = db.get_recent_scans(limit=10)
```

## Database Location
Default: `state/auroraedge.db`

## Tests
- `test_database.py::test_database_init_and_save`
- `test_database.py::test_database_multiple_scans`
