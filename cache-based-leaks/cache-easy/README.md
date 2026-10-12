# cache-easy (150 pts)

## Vulnerability: Cross-Site Cache-Timing Oracle (Single Resource Visited Leak)

### Description
The victim web application is an e-commerce shop at `http://victim.ctf:3000`.
When viewing a product page `/product/:id`, the browser fetches and caches `/images/:id.jpg`:
```http
Cache-Control: public, max-age=3600
Timing-Allow-Origin: *
```
The victim bot visits one of 16 candidate products (`item-0` through `item-15`), storing the corresponding image in the local browser cache.
Uncached image requests incur a simulated server latency (>120ms), while cached requests resolve locally (<20ms).

An attacker submits an exploit page that issues `fetch()` requests against all 16 candidate image URLs using `performance.now()`. The resource that resolves significantly faster reveals which product was visited by the victim.

> **Note on Browser Cache Partitioning:** Modern browsers double-key the HTTP cache by `(top_frame_site, resource_url)`. To demonstrate cache timing in modern Chromium without disabling browser isolation, the challenge hosts the player sandbox on `http://victim.ctf:8080`, sharing the same-site top-level partition with `http://victim.ctf:3000` while preserving Same-Origin Policy boundary across ports. Cross-site partitioned cache leak is explored in **cache-hard**.

## Files
- `server.js`: Hosts victim app (port 3000) and bot portal (port 8000).
- `bot.js`: Headless Chrome bot simulator.
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
