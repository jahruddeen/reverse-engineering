#!/usr/bin/env node
/**
 * trace-anything -- cross-layer feature tracer (static analysis only).
 *
 * Point it at a folder that mixes anything you are authorised to analyse:
 * app source / extracted Electron app, native binaries, HAR captures.
 * Give it a feature keyword. It extracts facts from every layer, links them
 * (shared IPC channel, same URL, same file proximity, relative-path match),
 * and reports the end-to-end flows that touch your feature:
 *
 *   bridge API -> renderer IPC call -> main handler -> code network call
 *     -> observed HAR request -> native binary string
 *
 * Usage:  node trace-anything.mjs <folder> [keyword] [--out report]
 * Output: <out>.json  and  <out>.html (self-contained interactive graph)
 */
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const outIdx = args.indexOf('--out');
const outBase = outIdx >= 0 ? args.splice(outIdx, 2)[1] : 'trace-report';
const [root, keyword = ''] = args;
if (!root || !fs.existsSync(root)) { console.error('usage: trace-anything.mjs <folder> [keyword] [--out name]'); process.exit(1); }
const kw = keyword.toLowerCase();

/* ---------------------------------------------------------- layers ---- */
const LAYERS = ['bridge', 'renderer', 'main', 'code-network', 'observed-network', 'native'];
const KIND_LAYER = {
  'exposed-api': 'bridge', 'ipc-renderer': 'renderer', 'ipc-main': 'main', 'child-process': 'main',
  'http-call': 'code-network', websocket: 'code-network', url: 'code-network',
  'har-request': 'observed-network', 'binary-string': 'native',
};

/* ----------------------------------------------------------- facts ---- */
const nodes = new Map();
function addNode(kind, value, file, line, extra = {}) {
  const id = `${kind}|${value}|${file}:${line}`;
  if (!nodes.has(id)) nodes.set(id, { id, kind, layer: KIND_LAYER[kind], value, file, line, key: value, ...extra });
}
const normUrl = (u) => { try { const x = new URL(u); return (x.host + x.pathname).replace(/\/$/, '').toLowerCase(); } catch { return u; } };
const isUrl = (s) => /^https?:\/\/|^wss?:\/\//.test(s);

const CODE_RULES = [
  ['exposed-api',   /exposeInMainWorld\(\s*['"]([^'"]+)['"]/g],
  ['ipc-renderer',  /ipcRenderer\.(?:invoke|send|sendSync|on|once)\(\s*['"]([^'"]+)['"]/g],
  ['ipc-main',      /ipcMain\.(?:handle|handleOnce|on|once)\(\s*['"]([^'"]+)['"]/g],
  ['http-call',     /\b(?:fetch|axios(?:\.\w+)?|got|request)\(\s*[`'"]([^`'"]+)[`'"]/g],
  ['websocket',     /new\s+WebSocket\(\s*['"`]([^'"`]+)/g],
  ['child-process', /\b(?:execSync|exec|spawnSync|spawn|execFile)\(\s*['"`]([^'"`]+)/g],
  ['url',           /https?:\/\/[^\s'"`<>)\\]{4,}/g],
];
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.html']);
const SKIP = new Set(['node_modules', '.git']);

function lineIndex(text) {
  const s = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) s.push(i + 1);
  return (p) => { let lo = 0, hi = s.length - 1; while (lo < hi) { const m = (lo + hi + 1) >> 1; s[m] <= p ? (lo = m) : (hi = m - 1); } return lo + 1; };
}

function readCode(file, rel) {
  const text = fs.readFileSync(file, 'utf8');
  const lineOf = lineIndex(text);
  for (const [kind, re] of CODE_RULES) {
    let m, n = 0;
    while ((m = re.exec(text)) && n++ < 300) {
      const v = (m[1] ?? m[0]).slice(0, 300);
      addNode(kind, v, rel, lineOf(m.index), isUrl(v) ? { key: normUrl(v) } : v.startsWith('/') && kind === 'http-call' ? { relPath: v.split('?')[0] } : {});
    }
  }
}

function readHar(file, rel) {
  const entries = JSON.parse(fs.readFileSync(file, 'utf8')).log.entries;
  entries.forEach((e, i) => {
    const u = new URL(e.request.url);
    addNode('har-request', `${e.request.method} ${e.request.url} [${e.response.status}]`, rel, i, { key: normUrl(e.request.url), harPath: u.pathname });
  });
}

function readBinary(file, rel) {
  const b = fs.readFileSync(file);
  let start = -1, n = 0;
  for (let i = 0; i <= b.length && n < 400; i++) {
    const ok = i < b.length && b[i] >= 0x20 && b[i] < 0x7f;
    if (ok) { if (start < 0) start = i; continue; }
    if (start >= 0 && i - start >= 6) {
      const s = b.toString('latin1', start, i);
      if (isUrl(s) || (kw && s.toLowerCase().includes(kw)) || /^[\w-]+:[\w:-]+$/.test(s)) {
        addNode('binary-string', s.slice(0, 200), rel, start, isUrl(s) ? { key: normUrl(s) } : {});
        n++;
      }
    }
    start = -1;
  }
}

function sniffBinary(file) {
  const fd = fs.openSync(file, 'r'); const h = Buffer.alloc(4); fs.readSync(fd, h, 0, 4, 0); fs.closeSync(fd);
  const m = h.readUInt32BE(0);
  return m === 0x7f454c46 || (m >>> 16) === 0x4d5a || [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m);
}

const skipped = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = path.join(dir, e.name), rel = path.relative(root, p);
    if (e.isDirectory()) { walk(p); continue; }
    const ext = path.extname(e.name).toLowerCase();
    try {
      const size = fs.statSync(p).size;
      if (size > 64 * 1024 * 1024) { skipped.push(`${rel} (too large)`); continue; }
      if (ext === '.har') readHar(p, rel);
      else if (CODE_EXT.has(ext) && size < 8 * 1024 * 1024) readCode(p, rel);
      else if (size > 0 && sniffBinary(p)) readBinary(p, rel);
    } catch (err) { skipped.push(`${rel} (${err.message})`); }
  }
})(root);

/* ----------------------------------------------------------- edges ---- */
const edges = [];
const seen = new Set();
const link = (a, b, type) => {
  if (a.id === b.id) return;
  const [x, y] = LAYERS.indexOf(a.layer) <= LAYERS.indexOf(b.layer) ? [a, b] : [b, a];
  const k = `${x.id}>${y.id}>${type}`;
  if (!seen.has(k)) { seen.add(k); edges.push({ from: x.id, to: y.id, type }); }
};
const all = [...nodes.values()];

// 1. identical key (same IPC channel, same URL) across different nodes
const groups = new Map();
for (const n of all) { if (n.kind === 'url') continue; (groups.get(n.key) ?? groups.set(n.key, []).get(n.key)).push(n); }
for (const g of groups.values()) {
  if (g.length < 2 || g.length > 40) continue;
  for (let i = 0; i < g.length; i++) for (let j = i + 1; j < g.length; j++) if (g[i].layer !== g[j].layer || g[i].file !== g[j].file) link(g[i], g[j], isUrl(g[i].value) || g[i].kind === 'har-request' ? 'same-url' : 'same-name');
}
// 2. relative API path in code <-> HAR pathname
for (const c of all.filter((n) => n.relPath)) for (const h of all.filter((n) => n.harPath)) if (h.harPath.startsWith(c.relPath)) link(c, h, 'path-match');
// 3. same-file proximity (code that is physically close is usually related)
const byFile = new Map();
for (const n of all) if (n.layer && n.layer !== 'observed-network' && n.layer !== 'native') (byFile.get(n.file) ?? byFile.set(n.file, []).get(n.file)).push(n);
for (const list of byFile.values()) for (const a of list) for (const b of list) {
  if (a === b || Math.abs(a.line - b.line) > 12) continue;
  if (a.kind === 'exposed-api' && b.kind === 'ipc-renderer') link(a, b, 'exposes');
  if (a.kind === 'ipc-main' && ['http-call', 'websocket', 'child-process'].includes(b.kind)) link(a, b, 'handler-calls');
  if (a.kind === 'http-call' && b.kind === 'url' && b.line === a.line) link(a, b, 'same-call');
}

/* --------------------------------------------------------- relevance ---- */
const adj = new Map(all.map((n) => [n.id, []]));
for (const e of edges) { adj.get(e.from).push(e.to); adj.get(e.to).push(e.from); }
const seeds = kw ? all.filter((n) => n.value.toLowerCase().includes(kw) || n.file.toLowerCase().includes(kw)) : all;
const keep = new Set(seeds.map((n) => n.id));
if (kw) { let frontier = [...keep]; for (let d = 0; d < 3; d++) { const nxt = []; for (const id of frontier) for (const nb of adj.get(id)) if (!keep.has(nb)) { keep.add(nb); nxt.push(nb); } frontier = nxt; } }
const subNodes = all.filter((n) => keep.has(n.id));
const subEdges = edges.filter((e) => keep.has(e.from) && keep.has(e.to));
const seedIds = new Set(seeds.map((n) => n.id));

/* ------------------------------------------------------------ flows ---- */
const byId = new Map(subNodes.map((n) => [n.id, n]));
const out = new Map(subNodes.map((n) => [n.id, []]));
for (const e of subEdges) out.get(e.from).push(e);
const hasIn = new Set(subEdges.map((e) => e.to));
const flows = [];
function dfs(id, path_, types) {
  const n = byId.get(id);
  const nexts = out.get(id).filter((e) => LAYERS.indexOf(byId.get(e.to).layer) > LAYERS.indexOf(n.layer) || e.type === 'same-url');
  if (!nexts.length) { if (path_.length > 1) flows.push({ steps: path_.map((i) => { const x = byId.get(i); return { layer: x.layer, value: x.value, evidence: `${x.file}:${x.line}` }; }), via: types }); return; }
  if (path_.length > 8) return;
  for (const e of nexts) if (!path_.includes(e.to)) dfs(e.to, [...path_, e.to], [...types, e.type]);
}
for (const n of subNodes) if (!hasIn.has(n.id) && out.get(n.id).length) dfs(n.id, [n.id], []);
flows.sort((a, b) => b.steps.length - a.steps.length);

const report = {
  target: path.resolve(root), keyword: keyword || null,
  stats: { facts: all.length, links: edges.length, shownNodes: subNodes.length, flows: flows.length },
  flows: flows.slice(0, 50),
  nodes: subNodes.map(({ id, kind, layer, value, file, line }) => ({ id, kind, layer, value, evidence: `${file}:${line}`, matchesKeyword: seedIds.has(id) && !!kw })),
  edges: subEdges,
  skipped,
  limitations: [
    'Static, regex-based extraction: dynamically built strings, obfuscation and encrypted payloads are not resolved.',
    'Links are heuristics (shared strings, URLs, file proximity). Each link carries its type -- verify important ones manually.',
    'Binaries are only string-scanned; use a disassembler (Ghidra/Hopper/IDA) to follow code in them.',
  ],
};
fs.writeFileSync(`${outBase}.json`, JSON.stringify(report, null, 2));

/* ------------------------------------------------------------- HTML ---- */
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const data = JSON.stringify({ nodes: report.nodes, edges: report.edges, layers: LAYERS }).replace(/</g, '\\u003c');
const flowHtml = report.flows.slice(0, 20).map((f) => `<li>${f.steps.map((s) => `<span class="step"><b>${esc(s.layer)}</b> ${esc(s.value.slice(0, 70))}<small>${esc(s.evidence)}</small></span>`).join('<span class="arrow">&rarr;</span>')}</li>`).join('') || '<li>No multi-layer flow found. Try another keyword or add more artifacts (HAR, binaries).</li>';
fs.writeFileSync(`${outBase}.html`, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>trace-anything: ${esc(keyword || 'all')}</title>
<style>
:root{--bg:#fff;--fg:#1c1c1e;--mut:#6b6b70;--card:#f4f4f6;--line:#b9b9c0;--hit:#d9480f;--ac:#3b5bdb}
@media (prefers-color-scheme:dark){:root{--bg:#18181b;--fg:#ececf0;--mut:#9a9aa3;--card:#25252a;--line:#55555d;--hit:#ff922b;--ac:#748ffc}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
h1{font-size:18px;margin:0 0 4px}p.s{color:var(--mut);margin:0 0 12px}
.wrap{overflow-x:auto;background:var(--card);border-radius:10px;padding:8px}
text{fill:var(--fg);font-size:11px}.hd{font-weight:600;fill:var(--mut);text-transform:uppercase;font-size:10px}
rect.n{fill:var(--bg);stroke:var(--line)}rect.hit{stroke:var(--hit);stroke-width:2}
line.e{stroke:var(--line);stroke-width:1.2;opacity:.7}line.e.hot{stroke:var(--ac);stroke-width:2.2;opacity:1}
ol{padding-left:18px}li{margin:8px 0}.step{display:inline-block;background:var(--card);border-radius:6px;padding:3px 8px;margin:2px 0}
.step small{display:block;color:var(--mut);font-size:11px}.arrow{margin:0 6px;color:var(--mut)}
</style></head><body>
<h1>trace-anything &mdash; ${esc(keyword || 'full map')}</h1>
<p class="s">${report.stats.shownNodes} nodes, ${subEdges.length} links, ${report.stats.flows} flows. Orange border = matches keyword. Hover a box for evidence; hover to highlight links.</p>
<div class="wrap"><svg id="g"></svg></div>
<h2 style="font-size:15px">End-to-end flows</h2><ol>${flowHtml}</ol>
<script>
const D=${data};const NS='http://www.w3.org/2000/svg';const svg=document.getElementById('g');
const W=250,H=34,GX=60,GY=12,pos={};const cols={};D.layers.forEach((l,i)=>cols[l]=[]);
D.nodes.forEach(n=>cols[n.layer].push(n));
const used=D.layers.filter(l=>cols[l].length);let maxRows=0;
used.forEach((l,ci)=>{cols[l].forEach((n,r)=>{pos[n.id]={x:ci*(W+GX)+8,y:30+r*(H+GY)};});maxRows=Math.max(maxRows,cols[l].length)});
svg.setAttribute('width',used.length*(W+GX));svg.setAttribute('height',40+maxRows*(H+GY));
const mk=(t,a)=>{const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);return e};
used.forEach((l,ci)=>{const t=mk('text',{x:ci*(W+GX)+8,y:16,class:'hd'});t.textContent=l;svg.appendChild(t)});
const lines=D.edges.map(e=>{const a=pos[e.from],b=pos[e.to];if(!a||!b)return null;const ln=mk('line',{x1:a.x+W,y1:a.y+H/2,x2:b.x,y2:b.y+H/2,class:'e'});const t=mk('title',{});t.textContent=e.type;ln.appendChild(t);svg.appendChild(ln);return{ln,e}}).filter(Boolean);
D.nodes.forEach(n=>{const p=pos[n.id];const g=mk('g',{});const r=mk('rect',{x:p.x,y:p.y,width:W,height:H,rx:6,class:'n'+(n.matchesKeyword?' hit':'')});
const t=mk('text',{x:p.x+8,y:p.y+14});t.textContent=n.value.length>38?n.value.slice(0,37)+'\u2026':n.value;
const t2=mk('text',{x:p.x+8,y:p.y+27,class:'hd'});t2.textContent=n.evidence.length>40?'\u2026'+n.evidence.slice(-39):n.evidence;
const tt=mk('title',{});tt.textContent=n.kind+'\\n'+n.value+'\\n'+n.evidence;g.append(r,t,t2,tt);
g.addEventListener('mouseenter',()=>lines.forEach(({ln,e})=>{if(e.from===n.id||e.to===n.id)ln.classList.add('hot')}));
g.addEventListener('mouseleave',()=>lines.forEach(({ln})=>ln.classList.remove('hot')));svg.appendChild(g)});
</script></body></html>`);

/* ---------------------------------------------------------- console ---- */
console.log(`Facts: ${all.length}  Links: ${edges.length}  Shown: ${subNodes.length}  Flows: ${flows.length}`);
for (const f of flows.slice(0, 5)) console.log('\n' + f.steps.map((s) => `[${s.layer}] ${s.value.slice(0, 60)} (${s.evidence})`).join('\n   -> '));
console.log(`\nWrote ${outBase}.json and ${outBase}.html`);
