// Investigação passiva do tráfego do blackweb.cc na SUA sessão.
// Uso:  npm i playwright && npx playwright install chromium && node blackweb-investigate.js
// 1) faça login manualmente  2) abra um canal, um filme e uma série  3) volte ao terminal e tecle ENTER.
// Não grava senhas, cookies, headers de autorização nem corpos de resposta (exceto JS público, só para busca de URLs).
// Credenciais e tokens em URLs/paths são substituídos por <redacted>.
const { chromium } = require('playwright');
const fs = require('fs');
const readline = require('readline');

const SENSITIVE_QS = /^(username|user|password|pass|pwd|token|key|auth|session|sid|jwt|access_token|api_key|hash|sig|signature|expires)$/i;
const XTREAM_PATH = /^\/(live|movie|series|timeshift|hls|streaming)\/[^/]+\/[^/]+\//i; // /live/USER/PASS/ID.ts
const PATTERNS = [
  'player_api.php', 'get.php', 'xmltv.php', 'panel_api.php', 'baseURL', 'baseUrl', 'apiUrl', 'apiURL',
  'serverUrl', 'server_url', 'endpoint', 'proxy', 'gateway', 'm3u8', 'xtream',
];

function redact(u) {
  try {
    const url = new URL(u);
    for (const k of [...url.searchParams.keys()]) {
      if (SENSITIVE_QS.test(k)) url.searchParams.set(k, '<redacted>');
    }
    let p = url.pathname.replace(XTREAM_PATH, (m) => '/' + m.split('/')[1] + '/<user>/<pass>/');
    p = p.split('/').map((s) => (/^[A-Za-z0-9_\-.=]{32,}$/.test(s) ? '<redacted>' : s)).join('/');
    return { origin: url.origin, host: url.host, path: p, query: [...url.searchParams.keys()].join(',') };
  } catch { return { origin: '?', host: '?', path: '?', query: '' }; }
}

const requests = [];
const redirects = [];
const websockets = [];
const jsFindings = new Map(); // key -> {file, snippet}
const serverInfo = []; // apenas url/port/protocolo vindos de player_api.php

(async () => {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();

  page.on('websocket', (ws) => websockets.push(redact(ws.url())));

  page.on('response', async (res) => {
    const req = res.request();
    const r = redact(req.url());
    const status = res.status();
    requests.push({ method: req.method(), type: req.resourceType(), status, ...r });

    if (status >= 300 && status < 400) {
      const loc = res.headers()['location'];
      if (loc) redirects.push({ from: `${r.host}${r.path}`, status, to: redact(new URL(loc, req.url()).href) });
    }

    // JS público: procurar URLs/configurações
    if (req.resourceType() === 'script' && status === 200) {
      try {
        const body = await res.text();
        const file = `${r.host}${r.path}`;
        for (const m of body.matchAll(/https?:\/\/[A-Za-z0-9.\-]+(?::\d+)?[^\s"'`\\)<>]{0,80}/g)) {
          const red = redact(m[0]);
          jsFindings.set(`url|${red.origin}${red.path}`, { kind: 'url', file, value: `${red.origin}${red.path}` });
        }
        for (const pat of PATTERNS) {
          let i = body.indexOf(pat);
          if (i >= 0) {
            const snip = body.slice(Math.max(0, i - 60), i + 100).replace(/\s+/g, ' ')
              .replace(/(pass(word)?|token|secret|key)["']?\s*[:=]\s*["'][^"']+["']/gi, '$1:<redacted>');
            jsFindings.set(`pat|${pat}|${file}`, { kind: 'pattern:' + pat, file, value: snip });
          }
        }
      } catch {}
    }

    // Xtream: guardar somente server_info (host/porta/protocolo), nunca user_info
    if (/player_api\.php/.test(req.url()) && status === 200) {
      try {
        const j = await res.json();
        if (j && j.server_info) {
          const { url, port, https_port, server_protocol, rtmp_port } = j.server_info;
          serverInfo.push({ via: r.host, url, port, https_port, server_protocol, rtmp_port });
        }
      } catch {}
    }
  });

  await page.goto('https://blackweb.cc');
  console.log('\nFaça login, abra um canal, um filme e uma série. Depois tecle ENTER aqui...');
  await new Promise((ok) => readline.createInterface({ input: process.stdin }).once('line', ok));
  await browser.close();

  // ---- relatório ----
  const byHost = {};
  for (const r of requests) {
    const h = (byHost[r.host] ||= { count: 0, types: new Set(), samples: new Set() });
    h.count++; h.types.add(r.type);
    if (['xhr', 'fetch', 'media', 'websocket'].includes(r.type) || /\.(m3u8|ts|mp4|mkv|php)$/i.test(r.path)) {
      if (h.samples.size < 8) h.samples.add(`${r.method} ${r.path}${r.query ? '?' + r.query + '=<redacted>' : ''}`);
    }
  }
  const hosts = Object.entries(byHost).map(([host, v]) => ({
    host, count: v.count, types: [...v.types], samples: [...v.samples],
  })).sort((a, b) => b.count - a.count);

  const out = {
    hosts, redirects, websockets, serverInfo,
    streamHosts: [...new Set(requests.filter((r) => /\.(m3u8|ts|mp4|mkv)$/i.test(r.path) || r.type === 'media').map((r) => r.host))],
    epgHints: requests.filter((r) => /xmltv|epg/i.test(r.path)).map((r) => `${r.host}${r.path}`),
    jsFindings: [...jsFindings.values()],
  };
  fs.writeFileSync('blackweb-report.json', JSON.stringify(out, null, 2));
  console.log('\n=== Hosts contatados ===');
  for (const h of hosts) console.log(`${h.count.toString().padStart(4)}  ${h.host}  [${h.types.join(',')}]`);
  console.log('\nHosts de stream:', out.streamHosts.join(', ') || '(nenhum)');
  console.log('server_info (Xtream):', JSON.stringify(serverInfo));
  console.log('Redirecionamentos:', redirects.length, '| WebSockets:', websockets.length);
  console.log('\nRelatório redigido salvo em blackweb-report.json (pode colar aqui para eu analisar).');
})();
