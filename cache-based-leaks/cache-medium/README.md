# cache-medium (300 pts)

## Vulnerability: Multi-Resource Cache Timing (Visited Set Inference)

### Description
The victim simulator visits 3 distinct products out of 8 catalog items (`1` through `8`) selected via a cryptographic Fisher-Yates shuffle before visiting your exploit page.
Each product loads an image at `http://victim.ctf:3000/images/product-{id}.jpg`.

In Chromium:
- Unvisited items incur the simulated 120ms server round-trip latency (>120ms).
- Visited items resolve from the local HTTP cache (<60ms).

> **Note on Browser Cache Partitioning:** Modern browsers double-key the HTTP cache by `(top_frame_site, resource_url)`. To model realistic cache timing without requiring top-level window popups, the challenge hosts the player sandbox on `http://victim.ctf:8080`, sharing the same-site top-level partition with `http://victim.ctf:3000` while preserving Same-Origin Policy boundary across ports. Cross-site partitioned cache leak is explored in **cache-hard**.

An attacker page measures timing across all 8 candidate URLs. Filtering for items with duration < 60ms identifies the visited set. The attacker then submits the comma-separated sorted IDs to `/exfil?jobId={jobId}&visited={id1,id2,id3}` to claim the flag.

## Files
- `server.js`: Hosts victim app (port 3000) and bot portal (port 8000).
- `bot.js`: Headless Chrome bot runner.
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
