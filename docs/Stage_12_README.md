# Stage 12 - Dashboard v2 UI Redesign

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../README.md) and [`testing guide`](TESTING.md).

## Overview
Stage 12 deliverable: Complete visual redesign of the FastAPI dashboard with professional styling, responsive layout, and improved user experience.

## Features

Located in `src/app/dashboard.py`:

### Visual Design
- **Dark theme** with CSS custom properties for theming
- **Gradient header** with AuroraEdge branding
- **Card-based layout** for statistics and results
- **Grade badges** with colour coding (A+=emerald, B=amber, F=red)
- **Responsive grid** for mobile compatibility

### CSS Custom Properties
```css
:root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --success: #10b981;
    --warning: #f59e0b;
    --error: #ef4444;
    --border: #334155;
}
```

### Layout Components

#### Stats Grid
Four-card grid showing:
- Total Domains scanned
- Average Score
- Best/Worst Grade
- Last Scan timestamp

#### Two-Column Layout
- **Left**: Severity distribution breakdown
- **Right**: Grade distribution summary

#### Results Table
Sortable table with columns:
- Domain name
- Score (0-100)
- Grade badge
- Severity indicator
- Scan time

### Footer
Academic branding with:
- Belfast Metropolitan College
- BSc Cybersecurity & Networking Infrastructure
- Project year (2025/2026)
- Navigation links

## Endpoints
- `GET /` - Main dashboard (requires token)
- `GET /health` - Health check (public)
- `GET /api/summary` - JSON statistics
- `GET /api/runs` - List of scan runs
- `GET /download/latest` - Download latest report

## Access
```powershell
.\scripts\serve.ps1
# Open: http://127.0.0.1:8080/?token=aurora-dev
```
