const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { visitSubmission } = require('./bot');

const VICTIM_PORT = parseInt(process.env.VICTIM_PORT || '3000', 10);
const PORTAL_PORT = parseInt(process.env.PORTAL_PORT || '8000', 10);
const SANDBOX_PORT = parseInt(process.env.SANDBOX_PORT || '8080', 10);
const FLAG = process.env.FLAG || 'CTF{xss1_js0n_synt4x_3rr0r_t1m1ng_0r4cl3}';

const sandboxDir = path.join(__dirname, 'sandboxes');
if (!fs.existsSync(sandboxDir)) {
  fs.mkdirSync(sandboxDir, { recursive: true });
}

const activeJobs = new Map();
const ipRateLimit = new Map();
const clientBudgets = new Map();

function getClientBudget(ip) {
  const now = Date.now();
  let b = clientBudgets.get(ip);
  if (!b || now - b.windowStart > 60000) {
    b = { count: 0, failedGuesses: 0, windowStart: now };
    clientBudgets.set(ip, b);
  }
  return b;
}

// Concurrency queue
const jobQueue = [];
let runningWorkers = 0;
const MAX_CONCURRENT_BOTS = 2;
const MAX_QUEUE_LENGTH = 10;

function enqueueBotRun(jobId, secretPin, targetUrl) {
  jobQueue.push({ jobId, secretPin, targetUrl });
  processQueue();
}

async function processQueue() {
  if (runningWorkers >= MAX_CONCURRENT_BOTS || jobQueue.length === 0) return;
  runningWorkers++;
  const task = jobQueue.shift();
  const job = activeJobs.get(task.jobId);
  try {
    if (job) job.status = 'running';
    await visitSubmission(task.jobId, task.secretPin, task.targetUrl);
  } catch (err) {
    console.error(`[Portal] Bot run failed for ${task.jobId}:`, err.message);
  } finally {
    runningWorkers--;
    if (job && (job.status === 'running' || job.status === 'pending')) {
      job.status = 'completed';
      job.completedAt = Date.now();
    }
    processQueue();
  }
}

// TTL Job Cleanup (60s retention after completion, 180s hard max)
const RESULT_RETENTION_MS = 60 * 1000;
const MAX_JOB_LIFETIME_MS = 180 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [id, job] of activeJobs.entries()) {
    const isFinished = job.status === 'completed' || job.status === 'failed' || job.status === 'solved' || job.status === 'locked';
    const finishedExpired = isFinished && (now - (job.completedAt || job.createdAt) > RESULT_RETENTION_MS);
    const hardExpired = now - job.createdAt > MAX_JOB_LIFETIME_MS;

    if (finishedExpired || hardExpired) {
      activeJobs.delete(id);
      const filePath = path.join(sandboxDir, `${id}.html`);
      if (fs.existsSync(filePath)) {
        try { fs.unlinkSync(filePath); } catch (e) {}
      }
    }
  }

  for (const [ip, timestamp] of ipRateLimit.entries()) {
    if (now - timestamp > 60000) ipRateLimit.delete(ip);
  }
  for (const [ip, b] of clientBudgets.entries()) {
    if (now - b.windowStart > 60000) clientBudgets.delete(ip);
  }
}, 10000);

// --- 1. Victim App (Port 3000 - victim.ctf) ---
const victimApp = express();
victimApp.use(cookieParser());

victimApp.get('/', (req, res) => {
  res.send('<h1>Corporate Portal - Secure Record Search</h1>');
});

// JSON Search Endpoint - Served as application/javascript with opening '{' to trigger JavaScript SyntaxError (P1 Finding 5)
victimApp.get('/api/search', (req, res) => {
  const sessionId = req.cookies.auth_session;
  const job = activeJobs.get(sessionId);
  const prefix = req.query.prefix || '';

  res.set('Content-Type', 'application/javascript');
  res.set('Cache-Control', 'no-store');

  if (!job) {
    return res.status(401).send('{"error": "Unauthorized"}');
  }

  const isMatch = prefix && job.secretPin.startsWith(prefix);

  if (isMatch) {
    // Artificial backend delay simulating deep index search on match
    setTimeout(() => {
      res.send(`{\n  "status": "matched",\n  "hint": "Record index found",\n  "padding": "${'X'.repeat(20000)}"\n}`);
    }, 120);
  } else {
    // Fast return on mismatch
    res.send(`{\n  "status": "not_found"\n}`);
  }
});

victimApp.listen(VICTIM_PORT, '0.0.0.0', () => {
  console.log(`[Victim App] Listening on http://0.0.0.0:${VICTIM_PORT}`);
});

// --- 2. Attacker Sandbox Server (Port 8080 - attacker.ctf) ---
const sandboxApp = express();
sandboxApp.get('/sandbox/:jobId.html', (req, res) => {
  const file = path.join(sandboxDir, `${req.params.jobId}.html`);
  if (fs.existsSync(file)) {
    const job = activeJobs.get(req.params.jobId);
    if (job) {
      job.botVisited = true;
    }
    res.sendFile(file);
  } else {
    res.status(404).send('Exploit sandbox file not found or expired');
  }
});

sandboxApp.listen(SANDBOX_PORT, '0.0.0.0', () => {
  console.log(`[Sandbox Server] Listening on http://0.0.0.0:${SANDBOX_PORT}`);
});

// --- 3. Bot & Submission Portal (Port 8000 - portal.ctf) ---
const portalApp = express();
portalApp.set('trust proxy', process.env.TRUST_PROXY === 'true');
portalApp.use(express.json({ limit: '1mb' }));
portalApp.use(express.urlencoded({ extended: true, limit: '1mb' }));
portalApp.use(express.static(path.join(__dirname, 'public')));

portalApp.get('/health', (req, res) => {
  res.json({ status: 'ok', activeJobs: activeJobs.size, queueLength: jobQueue.length });
});

portalApp.post('/submit', async (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  const budget = getClientBudget(clientIp);

  if (budget.count >= 10) {
    return res.status(429).json({ error: 'Submission quota exceeded for this interval' });
  }

  const lastSubmit = ipRateLimit.get(clientIp) || 0;
  if (Date.now() - lastSubmit < 2500) {
    return res.status(429).json({ error: 'Rate limit exceeded: wait 3 seconds between submissions' });
  }
  ipRateLimit.set(clientIp, Date.now());
  budget.count++;

  if (jobQueue.length >= MAX_QUEUE_LENGTH) {
    return res.status(503).json({ error: 'Job queue is full. Please retry shortly.' });
  }

  const { html } = req.body;
  if (!html || typeof html !== 'string') {
    return res.status(400).json({ error: 'Missing html payload' });
  }

  const jobId = crypto.randomBytes(8).toString('hex');
  // Cryptographically random 4-digit PIN (1000 - 9999)
  const secretPin = String(crypto.randomInt(1000, 10000));

  const job = {
    jobId,
    secretPin,
    status: 'pending',
    botVisited: false,
    flag: null,
    attempts: 0,
    createdAt: Date.now()
  };
  activeJobs.set(jobId, job);
  console.log(`[Portal] Job registered: ${jobId}`);

  const filePath = path.join(sandboxDir, `${jobId}.html`);
  fs.writeFileSync(filePath, html, 'utf8');

  res.json({ success: true, jobId });

  const targetUrl = `http://attacker.ctf:${SANDBOX_PORT}/sandbox/${jobId}.html?jobId=${jobId}`;
  enqueueBotRun(jobId, secretPin, targetUrl);
});

// Strict job-scoped exfiltration with attempt lockout & bot visit validation
portalApp.get('/exfil', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  const { jobId, pin } = req.query;
  if (!jobId || !pin) {
    return res.status(400).json({ error: 'Missing required parameters: jobId and pin' });
  }

  const clientIp = req.ip || req.connection.remoteAddress;
  const budget = getClientBudget(clientIp);
  if (budget.failedGuesses >= 5) {
    return res.status(403).json({ error: 'Too many failed guesses across jobs. Lockout active.' });
  }

  const job = activeJobs.get(jobId);
  if (!job) {
    return res.status(404).json({ error: 'Job not found or expired' });
  }

  if (job.status === 'locked') {
    return res.status(403).json({ error: 'Job locked due to excessive attempts' });
  }

  // Reject premature exfiltration before bot visits (P0 Finding 3)
  if (!job.botVisited) {
    return res.status(403).json({ error: 'Exploit has not been visited by the bot yet' });
  }

  job.attempts++;
  if (job.attempts > 3) {
    job.status = 'locked';
    budget.failedGuesses++;
    return res.status(403).json({ error: 'Too many attempts. Job locked.' });
  }

  if (job.secretPin === pin.trim()) {
    job.status = 'solved';
    job.flag = FLAG;
    console.log(`[Portal] Flag awarded for job ${jobId}`);
    return res.json({ success: true, message: 'PIN verified', flag: FLAG });
  }

  budget.failedGuesses++;
  return res.status(403).json({ error: 'Incorrect PIN' });
});

portalApp.get('/status/:jobId', (req, res) => {
  const job = activeJobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }
  res.json({
    status: job.status,
    flag: job.flag
  });
});

portalApp.listen(PORTAL_PORT, '0.0.0.0', () => {
  console.log(`[Submission Portal] Listening on http://0.0.0.0:${PORTAL_PORT}`);
});
