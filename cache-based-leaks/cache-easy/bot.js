const puppeteer = require('puppeteer-core');
const fs = require('fs');

function getChromePath() {
  if (process.env.CHROME_BIN && fs.existsSync(process.env.CHROME_BIN)) {
    return process.env.CHROME_BIN;
  }
  const candidatePaths = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium'
  ];
  for (const p of candidatePaths) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

async function setupEgressFilter(page) {
  if (!page || page.__egressFilterAttached) return;
  page.__egressFilterAttached = true;
  try {
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      try {
        if (req.isInterceptResolutionHandled()) return;
        const u = req.url();
        const parsed = new URL(u);
        const allowedHosts = new Set(['victim.ctf', 'portal.ctf', 'attacker.ctf', 'localhost', '127.0.0.1']);
        if (parsed.protocol === 'data:' || parsed.protocol === 'about:' || parsed.protocol === 'javascript:' || allowedHosts.has(parsed.hostname)) {
          req.continue().catch(() => {});
        } else {
          console.warn(`[Bot Network Filter] Blocked egress request: ${u}`);
          req.abort('blockedbyclient').catch(() => {});
        }
      } catch (e) {
        try {
          if (!req.isInterceptResolutionHandled()) req.abort('blockedbyclient').catch(() => {});
        } catch (_) {}
      }
    });
  } catch (err) {}
}

async function visitSubmission(jobId, secretProduct, targetUrl) {
  const chromePath = getChromePath();
  if (!chromePath) {
    throw new Error('Chrome/Chromium binary not found. Set CHROME_BIN environment variable.');
  }

  const launchArgs = [
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--host-resolver-rules=MAP victim.ctf 127.0.0.1, MAP portal.ctf 127.0.0.1, MAP attacker.ctf 127.0.0.1'
  ];
  if (process.env.CHROME_NO_SANDBOX === 'true' || process.platform === 'win32') {
    launchArgs.push('--no-sandbox', '--disable-setuid-sandbox');
  }

  const browser = await puppeteer.launch({
    executablePath: chromePath,
    headless: true,
    args: launchArgs
  });

  try {
    const page = await browser.newPage();
    page.setDefaultNavigationTimeout(8000);
    await setupEgressFilter(page);

    // 1. Victim visits the secret product page, populating the HTTP cache
    console.log(`[Bot] Victim browsing product page`);
    await page.goto(`http://victim.ctf:3000/product/${secretProduct}`, { waitUntil: 'networkidle0', timeout: 5000 });

    // 2. Victim visits the player-submitted exploit page
    console.log(`[Bot] Visiting player exploit: ${targetUrl}`);
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 6000 });

    await new Promise((resolve) => setTimeout(resolve, 3500));
  } catch (err) {
    console.warn(`[Bot] Navigation error: ${err.message}`);
  } finally {
    await browser.close();
    console.log(`[Bot] Completed job: ${jobId}`);
  }
}

module.exports = { visitSubmission };
