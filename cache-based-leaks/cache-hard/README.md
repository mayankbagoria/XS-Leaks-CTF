# cache-hard (500 pts)

## Vulnerability: Double-Keyed Partitioned Cache Bypass (Top-Level Window Navigation Timing)

### Description
In modern browsers, the HTTP network cache is partitioned using double keys:
`(top_frame_origin, resource_url)`

Because the bot browses the classified report under `http://victim.ctf:3000`, direct cross-site HTTP `fetch()` requests from the attacker page on `http://attacker.ctf:8080` will always result in a cache miss due to different top-frame origins.

However, an attacker page can open a subwindow navigating to `http://victim.ctf:3000/report/:badge`. Because the top-level origin of that subwindow matches `victim.ctf`, it accesses the partitioned cache. By measuring the navigation completion timing via the victim page's load notification (`postMessage`) (cached reports resolve in <40ms vs uncached reports in >150ms), the attacker identifies which of the 8 candidate badges (`badge-0` through `badge-7`) was viewed by the victim.

## Files
- `server.js`: Hosts victim app (port 3000) and bot portal (port 8000).
- `bot.js`: Headless Chrome bot runner with standard double-keyed caching enabled.
- `public/`: Web UI for HTML payload submissions.
- `Dockerfile` & `docker-compose.yml`: Container setup.
- `challenge.yml`: CTFd configuration.
- `solve.py`: Automated solver / test verification script.

## Testing Locally
```bash
npm install
npm start
python solve.py
```
