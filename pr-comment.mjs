#!/usr/bin/env node
/**
 * pr-comment.mjs — un comentario FIJO en el pull request con lo que este cambio hace al inventario.
 *
 * Por qué esto y no una línea más en el log. Un informe que vive en la pestaña de un pase de CI lo
 * lee quien ya fue a buscarlo, es decir casi nadie. Un comentario en el pull request aparece donde
 * la decisión se toma de verdad, mientras alguien revisa el cambio, y convierte el inventario en
 * parte de la conversación en vez de un archivo que se archiva.
 *
 * Es FIJO a propósito: busca su propio comentario por una marca invisible y lo REESCRIBE. Veinte
 * comentarios idénticos en un pull request largo es la forma más rápida de que alguien desactive la
 * herramienta, y entonces se pierde la señal entera por un problema de modales.
 *
 * Degrada en silencio y con el motivo dicho: si falta `pull-requests: write` avisa y sale con
 * éxito. Un vigilante al que le faltan permisos no puede romper la obra de otro.
 *
 * Entorno: GH_TOKEN, REPO (owner/name), PR (número), FINDINGS, INCREASED, DECREASED, TRUNCATED, CBOM.
 */
import fs from 'node:fs';

const MARKER = '<!-- pqc-readiness-scan:sticky -->';
const {
  GH_TOKEN, REPO, PR, FINDINGS = '0', INCREASED = '0', DECREASED = '0', TRUNCATED = 'false', CBOM = '',
} = process.env;

const note = (msg) => console.log(`::notice title=PQC scan::${msg}`);
const warn = (msg) => console.log(`::warning title=PQC scan: pull-request comment skipped::${msg}`);

if (!GH_TOKEN || !REPO || !PR) { note('not a pull request with a token, nothing to comment'); process.exit(0); }

async function api(method, url, body) {
  const r = await fetch(`https://api.github.com${url}`, {
    method,
    headers: {
      authorization: `Bearer ${GH_TOKEN}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'content-type': 'application/json',
      'user-agent': 'pqc-readiness-scan',
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000),
  });
  return { status: r.status, json: await r.json().catch(() => null) };
}

/** Las familias presentes, leídas del propio CBOM: una sola fuente para el log y el comentario. */
function familiesFromCbom() {
  if (!CBOM || !fs.existsSync(CBOM)) return { vulnerable: [], resistant: [], limits: '' };
  try {
    const doc = JSON.parse(fs.readFileSync(CBOM, 'utf8'));
    const prop = (c, n) => (c.properties || []).find((p) => p.name === n)?.value;
    const vulnerable = (doc.components || [])
      .filter((c) => prop(c, 'fractalai:quantum_vulnerable') === 'true')
      .map((c) => ({
        name: c.name,
        count: Number(prop(c, 'fractalai:occurrences') || 0),
        // Leida del documento, NO inferida del `primitive`: inferirla daba mal RSA, cuyo primitive
        // es `pke` y cuya urgencia es `harvest`.
        urgency: prop(c, 'fractalai:urgency') || 'deadline',
        whyNow: prop(c, 'fractalai:why_now') || '',
      }))
      .filter((f) => f.count > 0)
      .sort((a, b) => b.count - a.count);
    const resistant = (doc.components || [])
      .filter((c) => prop(c, 'fractalai:quantum_vulnerable') === 'false')
      .map((c) => c.name);
    const limits = (doc.metadata?.properties || []).find((p) => p.name === 'fractalai:coverage_limits')?.value || '';
    return { vulnerable, resistant, limits };
  } catch {
    return { vulnerable: [], resistant: [], limits: '' };
  }
}

const { vulnerable, resistant, limits } = familiesFromCbom();
const up = Number(INCREASED) || 0;
const down = Number(DECREASED) || 0;
const truncated = TRUNCATED === 'true';

const lines = [MARKER, '', '### Post-quantum readiness'];

if (up > 0) {
  lines.push('', `**${up} algorithm family(ies) went up against the baseline.** Nothing here asks you to fix the existing inventory; it asks this change not to add to it.`);
} else if (down > 0) {
  lines.push('', `**${down} algorithm family(ies) went down.** That is the direction the deadline needs.`);
} else if (vulnerable.length) {
  lines.push('', 'No change to the inventory in this pull request.');
} else {
  lines.push('', 'No quantum-vulnerable cryptography matched in what was scanned.');
}

if (vulnerable.length) {
  const harvest = vulnerable.filter((f) => f.urgency === 'harvest');
  lines.push('', '| Algorithm | Occurrences | Why now |', '|---|---:|---|');
  for (const f of vulnerable.slice(0, 12)) {
    const why = f.whyNow || (f.urgency === 'harvest'
      ? 'Harvest now, decrypt later: traffic recorded today is decryptable later.'
      : 'Risk arrives at the 2030/2035 deadline, earlier for long-lived artefacts.');
    lines.push(`| ${f.name} | ${f.count} | ${why.replace(/\|/g, '\\|')} |`);
  }
  if (vulnerable.length > 12) lines.push(`| … and ${vulnerable.length - 12} more | | |`);
  if (harvest.length) {
    lines.push('', `The ${harvest.length} key-agreement family(ies) above are the ones that cannot wait for the deadline: migrating in 2029 does not repair traffic an adversary recorded in 2026.`);
  }
}

if (resistant.length) lines.push('', `Already quantum-resistant here: ${resistant.join(', ')}.`);

if (truncated) {
  lines.push('', `> **This scan did not read everything.** ${limits} A clean result must not be read as clean.`);
}

lines.push(
  '',
  `<sub>${FINDINGS} occurrence(s) in code. Static scan: evidence to start a migration from, **not** a proof of absence and not a compliance certification. NIST IR 8547 deprecates these algorithms after 2030 and disallows them after 2035. · [PQC Readiness Scan](https://github.com/johnInarti/pqc-readiness-action)</sub>`,
);

const body = lines.join('\n');

// Reescribir el propio comentario si ya existe, para no apilar duplicados en cada push.
const list = await api('GET', `/repos/${REPO}/issues/${PR}/comments?per_page=100`);
if (list.status === 403) { warn("the job is missing 'pull-requests: write'; add it to your job's permissions block"); process.exit(0); }
if (list.status >= 400) { warn(`HTTP ${list.status} listing comments`); process.exit(0); }

const mine = (list.json || []).find((c) => typeof c.body === 'string' && c.body.includes(MARKER));
const res = mine
  ? await api('PATCH', `/repos/${REPO}/issues/comments/${mine.id}`, { body })
  : await api('POST', `/repos/${REPO}/issues/${PR}/comments`, { body });

if (res.status === 403) { warn("the job is missing 'pull-requests: write'; add it to your job's permissions block"); process.exit(0); }
if (res.status >= 400) { warn(`HTTP ${res.status} posting the comment`); process.exit(0); }
console.log(mine ? 'Updated the existing pull-request comment.' : 'Posted the pull-request comment.');
