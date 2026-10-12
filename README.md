# XS-Leaks CTF Challenge Suite

A comprehensive, competition-ready suite of 6 browser security challenges focused on **Cross-Site Script Inclusion (XSSI)** and **Cache-Based Timing Leaks** for CTFd.

---

## Challenge Taxonomy

| Category | Challenge | Points | Vulnerability / Mechanism | Flag Format |
| :--- | :--- | :--- | :--- | :--- |
| **XSSI** | `xssi-easy` | 150 | Global variable leak via `Object.defineProperty` setter | `CTF{...}` |
| **XSSI** | `xssi-medium` | 300 | Function callback argument interception | `CTF{...}` |
| **XSSI** | `xssi-hard` | 500 | Raw JSON response leak via `SyntaxError` event timing differential | `CTF{...}` |
| **Cache Leaks** | `cache-easy` | 150 | Single resource visited/not-visited cache timing oracle | `CTF{...}` |
| **Cache Leaks** | `cache-medium` | 300 | Multi-ID catalog probe reconstructing visited set | `CTF{...}` |
| **Cache Leaks** | `cache-hard` | 500 | Partition bypass against double-keyed caching via top-level window navigation timing | `CTF{...}` |

---

## Architecture & Submission Workflow

Because CTF participants cannot host their own public web servers, each challenge includes:
1. **Victim Application (Port 3000)**: Simulates the vulnerable internal enterprise or e-commerce service with authenticated states, secrets, and caches (`http://victim.ctf:3000`).
2. **Bot & Submission Portal (Port 8000)**:
   - A modern Web UI and REST API (`POST /submit` with `{ "html": "..." }`) at `http://portal.ctf:8000`.
   - Hosts the player's HTML/JS payload in an isolated sandbox at a dedicated attacker origin (`http://attacker.ctf:8080/sandbox/:id.html`).
   - Headless Chromium bot visits the sandbox with the victim's session/cache active.
   - A strict job-scoped exfiltration collector endpoint (`/exfil`) that validates leaked secrets against the submitter's `jobId` and returns the flag.
3. **Automated Verifier (`solve.py`)**: End-to-end programmatic exploit demonstrating that the challenge is 100% solvable.

---

## Directory Layout

```
CTF/
├── docker-compose.yml              # Multi-container orchestration (ports 8001-8006)
├── test_all.py                     # Master verification script
├── xssi/
│   ├── xssi-easy/                  # (150 pts) - Global var defineProperty leak
│   │   ├── Dockerfile
│   │   ├── challenge.yml
│   │   ├── solve.py
│   │   └── ...
│   ├── xssi-medium/                # (300 pts) - Function call prototype override
│   │   ├── Dockerfile
│   │   ├── challenge.yml
│   │   ├── solve.py
│   │   └── ...
│   └── xssi-hard/                  # (500 pts) - JSON SyntaxError timing oracle
│       ├── Dockerfile
│       ├── challenge.yml
│       ├── solve.py
│       └── ...
└── cache-based-leaks/
    ├── cache-easy/                 # (150 pts) - Visited/not-visited timing
    │   ├── Dockerfile
    │   ├── challenge.yml
    │   ├── solve.py
    │   └── ...
    ├── cache-medium/               # (300 pts) - Multi-ID visit order reconstruction
    │   ├── Dockerfile
    │   ├── challenge.yml
    │   ├── solve.py
    │   └── ...
    └── cache-hard/                 # (500 pts) - Double-keyed partition bypass
        ├── Dockerfile
        ├── challenge.yml
        ├── solve.py
        └── ...
```

---

## Deployment Instructions

### 1. Unified Deployment via Docker Compose
To launch all 6 challenges simultaneously:
```bash
docker compose up --build -d
```
Ports exposed to players:
- `http://<host>:8001` -> `xssi-easy`
- `http://<host>:8002` -> `xssi-medium`
- `http://<host>:8003` -> `xssi-hard`
- `http://<host>:8004` -> `cache-easy`
- `http://<host>:8005` -> `cache-medium`
- `http://<host>:8006` -> `cache-hard`

### 2. Standalone Deployment per Challenge
Each directory contains an independent `Dockerfile`, `docker-compose.yml`, and `challenge.yml` for CTFd import:
```bash
cd xssi/xssi-easy
docker build -t xssi-easy .
docker run -p 8000:8000 -p 3000:3000 xssi-easy
```

### 3. CTFd Integration
Import each challenge's `challenge.yml` using `ctfcli`:
```bash
ctfcli challenge install xssi/xssi-easy
ctfcli challenge sync xssi/xssi-easy
```

---

## Automated Verification

To run the master test suite across all 6 challenges:
```bash
python test_all.py
```
Or verify an individual challenge:
```bash
cd xssi/xssi-easy
node server.js &
python solve.py
```
