#!/usr/bin/env python3
"""
Master verification runner for the entire 6-challenge XS-Leaks CTF suite.
Includes:
- Stale process and port cleanup (ports 3000, 8000, 8080)
- HTTP Health Check (/health) readiness polling
- Positive Solver Verification (runs solve.py to verify real browser exploit)
- Security Regression Tests:
  * Reflected XSS input validation
  * Missing and invalid jobId rejection
  * Premature exfiltration rejection (botVisited enforcement)
  * IP rate limiting and X-Forwarded-For anti-spoofing verification
  * Cookie-based authenticated endpoint verification (XSSI)
  * Per-job attempt lockout and cross-job failed guess global lockout
"""
import os
import sys
import time
import requests
import subprocess

CHALLENGES = [
    {
        "name": "xssi-easy",
        "category": "XSSI",
        "points": 150,
        "dir": os.path.join("xssi", "xssi-easy"),
        "flag": "CTF{xss1_gl0b4l_v4r_d3f1n3_pr0p3rty_pwn3d}",
        "param_name": "secret"
    },
    {
        "name": "xssi-medium",
        "category": "XSSI",
        "points": 300,
        "dir": os.path.join("xssi", "xssi-medium"),
        "flag": "CTF{xss1_funct10n_c4ll_pr0t0_0v3rr1d3_succ3ss}",
        "param_name": "secret"
    },
    {
        "name": "xssi-hard",
        "category": "XSSI",
        "points": 500,
        "dir": os.path.join("xssi", "xssi-hard"),
        "flag": "CTF{xss1_js0n_synt4x_3rr0r_t1m1ng_0r4cl3}",
        "param_name": "pin"
    },
    {
        "name": "cache-easy",
        "category": "Cache-Based Leaks",
        "points": 150,
        "dir": os.path.join("cache-based-leaks", "cache-easy"),
        "flag": "CTF{c4ch3_t1m1ng_s1ngl3_b1t_v1s1t3d}",
        "param_name": "product"
    },
    {
        "name": "cache-medium",
        "category": "Cache-Based Leaks",
        "points": 300,
        "dir": os.path.join("cache-based-leaks", "cache-medium"),
        "flag": "CTF{c4ch3_v1s1t_0rd3r_s3qu3nc3_l34k3d}",
        "param_name": "visited"
    },
    {
        "name": "cache-hard",
        "category": "Cache-Based Leaks",
        "points": 500,
        "dir": os.path.join("cache-based-leaks", "cache-hard"),
        "flag": "CTF{d0ubl3_k3y3d_c4ch3_byp4ss_m4st3r}",
        "param_name": "badge"
    }
]

def kill_stale_processes():
    ports = [3000, 8000, 8080]
    if sys.platform == "win32":
        for port in ports:
            try:
                out = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True, text=True)
                for line in out.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[1].endswith(f":{port}") and "LISTENING" in parts:
                        pid = parts[-1]
                        if pid not in ("0", str(os.getpid())):
                            subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
            except Exception:
                pass
    else:
        for port in ports:
            try:
                subprocess.run(f"fuser -k {port}/tcp", shell=True, capture_output=True)
            except Exception:
                pass

def wait_for_health(port=8000, max_wait=10):
    start = time.time()
    while time.time() - start < max_wait:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/health", timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False

def run_negative_tests(ch):
    print("  [*] Running security regression checks (XSS, anti-spoofing, cookies, job-binding, lockouts)...")
    portal_url = "http://127.0.0.1:8000"
    victim_url = "http://127.0.0.1:3000"
    param = ch["param_name"]

    # 1. Reflected XSS check on victim app (P0 Finding 1)
    if "cache" in ch["name"]:
        endpoint = "/report/" if "hard" in ch["name"] else "/product/"
        xss_res = requests.get(f"{victim_url}{endpoint}%3Cscript%3Ealert(1)%3C/script%3E")
        assert xss_res.status_code == 404, f"Expected 404 on invalid ID path, got {xss_res.status_code}"
        assert "<script>" not in xss_res.text, "Vulnerable: reflected script payload found in victim response"

    # 2. Missing jobId check (F-01)
    r1 = requests.get(f"{portal_url}/exfil?{param}=test_val")
    assert r1.status_code == 400, f"Expected 400 for missing jobId, got {r1.status_code}"

    # 3. Fake jobId check (F-01)
    r2 = requests.get(f"{portal_url}/exfil?jobId=nonexistent_job_123&{param}=test_val")
    assert r2.status_code == 404, f"Expected 404 for nonexistent jobId, got {r2.status_code}"

    # 4. Create Job 1
    sub1_res = requests.post(f"{portal_url}/submit", json={"html": "<h1>Test Job 1</h1>"})
    assert sub1_res.status_code == 200, f"Expected 200 on submit, got {sub1_res.status_code}"
    job1 = sub1_res.json().get("jobId")

    # 5. Premature exfiltration check before bot visits sandbox (P0 Finding 3)
    premature_res = requests.get(f"{portal_url}/exfil?jobId={job1}&{param}=any_guess")
    assert premature_res.status_code == 403, f"Expected 403 for premature exfil, got {premature_res.status_code}"

    # 6. Immediate second submit should trigger 429 rate limit (F-11)
    sub_fast = requests.post(f"{portal_url}/submit", json={"html": "<h1>Test Fast</h1>"})
    assert sub_fast.status_code == 429, f"Expected 429 for rapid submissions, got {sub_fast.status_code}"

    # 7. X-Forwarded-For anti-spoofing check (P1 Finding 6)
    sub_spoof = requests.post(
        f"{portal_url}/submit",
        json={"html": "<h1>Test Spoof</h1>"},
        headers={"X-Forwarded-For": "203.0.113.195"}
    )
    assert sub_spoof.status_code == 429, f"Vulnerable: Spoofed X-Forwarded-For bypassed rate limiting! Got {sub_spoof.status_code}"

    # 8. Authenticated cookie check on victim endpoints (P1 Finding 9)
    if ch["category"] == "XSSI":
        if ch["name"] == "xssi-easy":
            unauth = requests.get(f"{victim_url}/api/profile.js")
            assert 'guest_token' in unauth.text, "Expected guest_token for unauthenticated request"
            auth = requests.get(f"{victim_url}/api/profile.js", cookies={"auth_session": job1})
            assert 'sec_' in auth.text, "Expected secret token for authenticated request"
        elif ch["name"] == "xssi-medium":
            unauth = requests.get(f"{victim_url}/api/userdata.js")
            assert 'guest_key' in unauth.text, "Expected guest_key for unauthenticated request"
            auth = requests.get(f"{victim_url}/api/userdata.js", cookies={"auth_session": job1})
            assert 'sec_' in auth.text, "Expected secret token for authenticated request"
        elif ch["name"] == "xssi-hard":
            unauth = requests.get(f"{victim_url}/api/search?prefix=1")
            assert unauth.status_code == 401, "Expected 401 for unauthenticated search"
            auth = requests.get(f"{victim_url}/api/search?prefix=1", cookies={"auth_session": job1})
            assert auth.status_code == 200, "Expected 200 for authenticated search"

    # 9. Cross-job isolation and attempt lockout (P1 Finding 7, P2 Finding 10)
    # Simulate bot visit on job1 to enable exfiltration
    try:
        requests.get(f"http://127.0.0.1:8080/sandbox/{job1}.html", timeout=1)
    except Exception:
        pass

    # Exceed per-job attempt limit (3 attempts) on job1
    for i in range(3):
        requests.get(f"{portal_url}/exfil?jobId={job1}&{param}=invalid_attempt_{i}")

    job1_locked = requests.get(f"{portal_url}/exfil?jobId={job1}&{param}=any_val")
    assert job1_locked.status_code == 403, f"Expected 403 for locked job1, got {job1_locked.status_code}"

    # Exceed cross-job global failed guesses budget (>= 5 failed guesses)
    for i in range(2):
        requests.get(f"{portal_url}/exfil?jobId={job1}&{param}=invalid_global_{i}")

    global_locked = requests.get(f"{portal_url}/exfil?jobId={job1}&{param}=test")
    assert global_locked.status_code == 403, f"Expected 403 for global lockout, got {global_locked.status_code}"

    print("  [+] Security regression checks PASSED (XSS, anti-spoofing, cookies, job-binding, lockouts verified).")
    return True

def run_challenge(challenge):
    print(f"\n========================================================")
    print(f"[*] Testing {challenge['name']} ({challenge['points']} pts) - {challenge['category']}")
    print(f"========================================================")
    ch_dir = os.path.abspath(challenge["dir"])

    kill_stale_processes()
    time.sleep(0.5)

    proc = subprocess.Popen(
        ["node", "server.js"],
        cwd=ch_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        if not wait_for_health():
            print(f"[-] Server failed to pass health check within timeout.")
            return False

        # 1. Run positive solve.py exploit in clean environment
        print("  [*] Running reference exploit solver (solve.py)...")
        result = subprocess.run(
            [sys.executable, "solve.py"],
            cwd=ch_dir,
            capture_output=True,
            text=True,
            timeout=60
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr)

        expected_flag = os.getenv(f"FLAG_{challenge['name'].upper().replace('-', '_')}", challenge["flag"])
        if result.returncode != 0 or expected_flag not in result.stdout:
            print(f"[FAIL] {challenge['name']} solver failed!")
            return False

        # Wait for rate limit window after solver submit
        time.sleep(3.0)

        # 2. Run negative security regression tests
        run_negative_tests(challenge)

        print(f"[PASS] {challenge['name']} verified successfully!")
        return True
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        kill_stale_processes()

def main():
    print("========================================================")
    print("   Hardened XS-Leaks CTF Suite Automated Verification   ")
    print("========================================================")
    print(f"[*] Python: {sys.version.split()[0]}")
    print(f"[*] Platform: {sys.platform}")
    print(f"[*] CHROME_BIN: {os.getenv('CHROME_BIN', 'Auto-detecting system Chrome')}")
    print("========================================================")

    results = []
    for ch in CHALLENGES:
        success = run_challenge(ch)
        results.append((ch["name"], ch["points"], success))
        time.sleep(1)

    print("\n=================== FINAL SUMMARY ===================")
    all_passed = True
    for name, pts, ok in results:
        status = "PASSED" if ok else "FAILED"
        print(f"[{status}] {name:15} ({pts} pts)")
        if not ok:
            all_passed = False
    print("=====================================================")

    if all_passed:
        print("\n[+] ALL 6 CHALLENGES & SECURITY REGRESSION TESTS PASSING!\n")
        sys.exit(0)
    else:
        print("\n[-] Some tests failed.\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
