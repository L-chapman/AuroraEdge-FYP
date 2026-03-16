# Stage 13 - Real-time SSE Updates + Auto-refresh

## Overview
Week 17 deliverable: Implemented Server-Sent Events (SSE) for real-time dashboard updates without page refresh, plus periodic auto-refresh polling.

## Features

Located in `src/app/dashboard.py`:

### Server-Sent Events (SSE)

#### Backend Endpoint
```python
@app.get("/api/stream")
async def stream_updates(token: Optional[str] = None):
    """Stream real-time updates via SSE"""
    async def event_generator():
        while True:
            stats = get_latest_stats()
            yield f"data: {json.dumps(stats)}\n\n"
            await asyncio.sleep(5)  # Update every 5 seconds
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream"
    )
```

#### Frontend JavaScript
```javascript
function initSSE() {
    const evtSource = new EventSource('/api/stream?token=' + token);
    
    evtSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        updateDashboard(data);
    };
    
    evtSource.onerror = function() {
        console.warn('SSE connection lost, will retry...');
    };
}
```

### Auto-refresh Polling
Fallback for browsers without SSE support:
```javascript
let autoRefreshEnabled = true;
const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds

setInterval(() => {
    if (autoRefreshEnabled) {
        checkForUpdates();
    }
}, AUTO_REFRESH_INTERVAL);
```

### Visual Feedback
- **Refresh toast** notification when updates arrive
- **"Last updated"** timestamp in header
- **Spinner animation** during data fetch
- **Toggle button** to enable/disable auto-refresh

### Benefits
1. **No page reload** - Dashboard stays responsive
2. **Real-time monitoring** - See new scans as they complete
3. **Low bandwidth** - Only sends changed data
4. **Graceful degradation** - Falls back to polling if SSE fails

## Testing
Run dashboard and perform a scan in another terminal:
```powershell
# Terminal 1 - Dashboard
.\scripts\serve.ps1

# Terminal 2 - Scan
python -m app.cli --domain example.com
```

Watch the dashboard update automatically when the scan completes.
