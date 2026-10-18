#!/usr/bin/env node
/**
 * mini-rea: a small, dependency-free reverse-engineering helper.
 * Static analysis only -- nothing is executed. Use on software you own
 * or are authorised to analyse.
 *
 * Commands:
 *   js <dir>                 analyse a JS / Electron app directory
 *   asar <file.asar> <out>   extract an Electron ASAR archive
 *   binary <file>            identify ELF / PE / Mach-O, list sections
 *   strings <file> [minLen]  extract & classify printable strings
 *   har <file.har>           summarise a saved network capture
 */
import fs from 'node:fs';
import path from 'node:path';

const out = (o) => console.log(JSON.stringify(o, null, 2));
const die = (m) => { console.error(m); process.exit(1); };

/* ---------------------------------------------------------------- JS ---- */
const SKIP_DIRS = new Set(['node_modules', '.git']);
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.html', '.json']);

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else yield p;
  }
}

// [kind, regex]; capture group 1 (or whole match) is the "value".
const RULES = [
  ['import',        /\bimport\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]/g],
  ['require',       /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g],
  ['ipc-main',      /ipcMain\.(?:handle|handleOnce|on|once)\(\s*['"]([^'"]+)['"]/g],
  ['ipc-renderer',  /ipcRenderer\.(?:invoke|send|sendSync|on|once)\(\s*['"]([^'"]+)['"]/g],
  ['exposed-api',   /exposeInMainWorld\(\s*['"]([^'"]+)['"]/g],
  ['http-call',     /\b(?:fetch|axios(?:\.\w+)?|got|request)\(\s*[`'"]([^`'"]+)[`'"]/g],
  ['websocket',     /new\s+WebSocket\(\s*['"`]([^'"`]+)/g],
  ['child-process', /\b(?:execSync|exec|spawnSync|spawn|execFile)\(\s*['"`]([^'"`]+)/g],
  ['sourcemap',     /\/\/[#@]\s*sourceMappingURL=(\S+)/g],
  ['url',           /https?:\/\/[^\s'"`<>)\\]{4,}/g],
];

const SECURITY = [
  ['nodeIntegration enabled',      /nodeIntegration\s*:\s*true/g],
  ['contextIsolation disabled',    /contextIsolation\s*:\s*false/g],
  ['webSecurity disabled',         /webSecurity\s*:\s*false/g],
  ['sandbox disabled',             /sandbox\s*:\s*false/g],
  ['remote module enabled',        /enableRemoteModule\s*:\s*true/g],
  ['eval / new Function',          /\beval\(|new\s+Function\(/g],
];

function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (pos) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; starts[mid] <= pos ? (lo = mid) : (hi = mid - 1); }
    return lo + 1;
  };
}

function scan(text, rules, cap = 200) {
  const lineOf = lineIndex(text);
  const hits = [];
  for (const [kind, re] of rules) {
    re.lastIndex = 0;
    let m, n = 0;
    while ((m = re.exec(text)) && n++ < cap) {
      hits.push({ kind, value: (m[1] ?? m[0]).slice(0, 300), line: lineOf(m.index) });
    }
  }
  return hits;
}

function analyseJs(root) {
  if (!fs.existsSync(root)) die(`Not found: ${root}`);
  const files = [], deps = {}, ipc = { main: {}, renderer: {} }, exposed = [];
  const urls = new Set(), findings = [], endpoints = [];
  let pkg = null;

  for (const file of walk(root)) {
    const ext = path.extname(file).toLowerCase();
    if (!CODE_EXT.has(ext)) continue;
    const stat = fs.statSync(file);
    if (stat.size > 8 * 1024 * 1024) continue;
    const rel = path.relative(root, file);
    const text = fs.readFileSync(file, 'utf8');
    if (rel === 'package.json') { try { pkg = JSON.parse(text); } catch {} }
    const hits = scan(text, RULES);
    const sec = scan(text, SECURITY);
    files.push({ file: rel, bytes: stat.size, minified: text.length > 5000 && text.split('\n').length < text.length / 2000 });

    for (const h of hits) {
      const ev = `${rel}:${h.line}`;
      if (h.kind === 'import' || h.kind === 'require') (deps[h.value] ??= []).push(ev);
      else if (h.kind === 'ipc-main') (ipc.main[h.value] ??= []).push(ev);
      else if (h.kind === 'ipc-renderer') (ipc.renderer[h.value] ??= []).push(ev);
      else if (h.kind === 'exposed-api') exposed.push({ name: h.value, evidence: ev });
      else if (h.kind === 'url') urls.add(h.value);
      else endpoints.push({ type: h.kind, value: h.value, evidence: ev });
    }
    for (const s of sec) findings.push({ issue: s.kind, evidence: `${rel}:${s.line}` });
  }

  // Which IPC channels have both a handler and a caller?
  const channels = [...new Set([...Object.keys(ipc.main), ...Object.keys(ipc.renderer)])].sort().map((c) => ({
    channel: c,
    handlers: ipc.main[c] ?? [],
    callers: ipc.renderer[c] ?? [],
    matched: !!(ipc.main[c] && ipc.renderer[c]),
  }));

  const externalDeps = Object.keys(deps).filter((d) => !d.startsWith('.') && !d.startsWith('/'));
  return {
    target: root,
    package: pkg && { name: pkg.name, version: pkg.version, main: pkg.main, dependencies: Object.keys(pkg.dependencies ?? {}) },
    isElectron: externalDeps.includes('electron') || Object.keys(pkg?.dependencies ?? {}).includes('electron') || !!pkg?.devDependencies?.electron,
    fileCount: files.length,
    minifiedFiles: files.filter((f) => f.minified).map((f) => f.file),
    importedModules: externalDeps.sort().map((d) => ({ module: d, evidence: deps[d].slice(0, 3) })),
    ipcChannels: channels,
    exposedToRenderer: exposed,
    networkEndpoints: endpoints.slice(0, 200),
    urls: [...urls].sort().slice(0, 200),
    securityFindings: findings,
    limitations: [
      'Regex-based static analysis: dynamically built strings and obfuscated code are missed.',
      'Minified files report accurate lines only if source maps are available.',
    ],
  };
}

/* -------------------------------------------------------------- ASAR ---- */
function extractAsar(file, dest) {
  const buf = fs.readFileSync(file);
  const pickleSize = buf.readUInt32LE(4);
  const jsonLen = buf.readUInt32LE(12);
  const header = JSON.parse(buf.toString('utf8', 16, 16 + jsonLen));
  const base = 8 + pickleSize;
  const root = path.resolve(dest);
  let count = 0;
  (function recurse(node, rel) {
    for (const [name, entry] of Object.entries(node.files ?? {})) {
      const target = path.resolve(root, rel, name);
      if (!target.startsWith(root + path.sep)) continue; // block path traversal
      if (entry.files) { fs.mkdirSync(target, { recursive: true }); recurse(entry, path.join(rel, name)); }
      else if (!entry.unpacked && !entry.link) {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        const start = base + Number(entry.offset);
        fs.writeFileSync(target, buf.subarray(start, start + entry.size));
        count++;
      }
    }
  })(header, '');
  return { extractedFiles: count, to: root };
}

/* ------------------------------------------------------------ BINARY ---- */
const ELF_MACHINE = { 3: 'x86', 8: 'MIPS', 40: 'ARM', 62: 'x86-64', 183: 'AArch64', 243: 'RISC-V' };
const PE_MACHINE = { 0x14c: 'x86', 0x8664: 'x86-64', 0x1c0: 'ARM', 0xaa64: 'ARM64' };

function analyseBinary(file) {
  const b = fs.readFileSync(file);
  const info = { file, bytes: b.length };

  if (b.readUInt32BE(0) === 0x7f454c46) {
    const is64 = b[4] === 2, le = b[5] === 1;
    Object.assign(info, { format: 'ELF', bits: is64 ? 64 : 32, endian: le ? 'little' : 'big' });
    info.arch = ELF_MACHINE[le ? b.readUInt16LE(18) : b.readUInt16BE(18)] ?? 'unknown';
    if (is64 && le) {
      const shoff = Number(b.readBigUInt64LE(0x28)), shentsize = b.readUInt16LE(0x3a);
      const shnum = b.readUInt16LE(0x3c), shstrndx = b.readUInt16LE(0x3e);
      const sh = (i) => shoff + i * shentsize;
      const strOff = Number(b.readBigUInt64LE(sh(shstrndx) + 0x18));
      const name = (o) => { let e = strOff + o; while (b[e]) e++; return b.toString('latin1', strOff + o, e); };
      info.sections = Array.from({ length: shnum }, (_, i) => ({
        name: name(b.readUInt32LE(sh(i))),
        addr: '0x' + b.readBigUInt64LE(sh(i) + 0x10).toString(16),
        size: Number(b.readBigUInt64LE(sh(i) + 0x20)),
        flags: Number(b.readBigUInt64LE(sh(i) + 8)),
      })).filter((s) => s.name);
      info.notes = info.sections.filter((s) => s.flags & 1 && s.flags & 4).map((s) => `${s.name} is writable+executable`);
    }
  } else if (b.readUInt16BE(0) === 0x4d5a) {
    const pe = b.readUInt32LE(0x3c);
    if (b.toString('latin1', pe, pe + 4) === 'PE\0\0') {
      info.format = 'PE';
      info.arch = PE_MACHINE[b.readUInt16LE(pe + 4)] ?? 'unknown';
      const n = b.readUInt16LE(pe + 6), opt = b.readUInt16LE(pe + 20);
      info.timestamp = new Date(b.readUInt32LE(pe + 8) * 1000).toISOString();
      info.sections = Array.from({ length: n }, (_, i) => {
        const o = pe + 24 + opt + i * 40;
        return { name: b.toString('latin1', o, o + 8).replace(/\0+$/, ''), virtualSize: b.readUInt32LE(o + 8), rawSize: b.readUInt32LE(o + 16) };
      });
    } else info.format = 'DOS MZ';
  } else if ([0xfeedfacf, 0xfeedface, 0xcffaedfe, 0xcefaedfe, 0xcafebabe].includes(b.readUInt32BE(0))) {
    info.format = b.readUInt32BE(0) === 0xcafebabe ? 'Mach-O universal (or Java class)' : 'Mach-O';
  } else if (b.toString('latin1', 0, 4) === 'PK\x03\x04') {
    info.format = 'ZIP container (APK / JAR / DOCX ...)';
  } else info.format = 'unknown';
  return info;
}

/* ----------------------------------------------------------- STRINGS ---- */
const CLASSES = [
  ['url',        /^https?:\/\//],
  ['path',       /^(\/[\w.-]+){2,}|^[A-Za-z]:\\/],
  ['email',      /^[\w.+-]+@[\w-]+\.[\w.]+$/],
  ['ip-address', /^\d{1,3}(\.\d{1,3}){3}$/],
  ['possible-secret', /(?:api[_-]?key|secret|token|passw(?:or)?d)/i],
  ['format-string', /%[sdxp]/],
];

function extractStrings(file, minLen = 6) {
  const b = fs.readFileSync(file);
  const found = [];
  let start = -1;
  for (let i = 0; i <= b.length; i++) {
    const printable = i < b.length && b[i] >= 0x20 && b[i] < 0x7f;
    if (printable) { if (start < 0) start = i; }
    else if (start >= 0) {
      if (i - start >= minLen) found.push({ offset: '0x' + start.toString(16), text: b.toString('latin1', start, i) });
      start = -1;
    }
  }
  const classified = {};
  for (const s of found) for (const [k, re] of CLASSES) if (re.test(s.text)) (classified[k] ??= []).push(s);
  for (const k in classified) classified[k] = classified[k].slice(0, 100);
  return { file, total: found.length, classified };
}

/* --------------------------------------------------------------- HAR ---- */
function analyseHar(file) {
  const entries = JSON.parse(fs.readFileSync(file, 'utf8')).log.entries;
  const sensitive = /^(authorization|cookie|set-cookie|x-api-key|x-auth-token)$/i;
  const hosts = {};
  const requests = entries.map((e, i) => {
    const u = new URL(e.request.url);
    hosts[u.host] = (hosts[u.host] ?? 0) + 1;
    return {
      i, method: e.request.method, url: e.request.url, status: e.response.status,
      mime: e.response.content?.mimeType,
      hasBody: !!e.request.postData,
      authHeadersPresent: e.request.headers.filter((h) => sensitive.test(h.name)).map((h) => h.name), // names only, never values
    };
  });
  return { total: requests.length, hosts, requests };
}

/* --------------------------------------------------------------- CLI ---- */
const [cmd, a, b2] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'js':      out(analyseJs(a)); break;
    case 'asar':    if (!a || !b2) die('usage: asar <file> <outdir>'); out(extractAsar(a, b2)); break;
    case 'binary':  out(analyseBinary(a)); break;
    case 'strings': out(extractStrings(a, Number(b2) || 6)); break;
    case 'har':     out(analyseHar(a)); break;
    default: die('usage: mini-rea.mjs <js|asar|binary|strings|har> <target> [arg]');
  }
} catch (e) { die(`error: ${e.message}`); }
