# xssi-hard (500 pts)

## Vulnerability: JSON-vs-Syntax-Error Timing Differential (Error-Based XS-Leak)

### Description
The victim web service generates JSON responses at `http://victim.ctf:3000/api/search?prefix=...`.
Because the payload begins with an opening curly brace `{`, importing it directly as a script triggers a JavaScript `SyntaxError`.

However, the endpoint performs a search check for the authenticated session's secret 4-digit PIN (1000 through 9999):
- If the prefix matches the start of the PIN, the server performs an internal scan causing a ~120ms delay before responding with the JSON payload.
- If the prefix does not match, the server returns an immediate negative JSON response (<20ms).

An attacker can measure the time from inserting `<script src="http://victim.ctf:3000/api/search?prefix=...">` until the syntax error event triggers. By comparing timing across candidate digits, each digit of the PIN is leaked sequentially and exfiltrated to `/exfil?jobId={jobId}&pin=...`.

## Files
- `server.js`: Hosts victim app (port 3000) and bot portal (port 8000).
- `bot.js`: Headless Chrome bot runner.
- `public/`: Web UI for HTML payload submissions.
- `Dockerfile` & `docker-compose.yml`: Container configuration.
- `challenge.yml`: CTFd configuration.
- `solve.py`: Automated solver / test verification script.

## Testing Locally
```bash
npm install
npm start
python solve.py
```
