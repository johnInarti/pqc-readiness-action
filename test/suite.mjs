#!/usr/bin/env node
/**
 * Regression suite for the PQC Readiness Scan.
 *
 * Every case here exists because an adversarial pass actually broke this scanner. The findings are
 * not hypothetical: each one was reproduced with a command before it was fixed. Keeping them as
 * tests is the only thing that stops them coming back, and the list doubles as the honest record
 * of what this tool got wrong before anyone adopted it.
 *
 * Written in Node rather than Python on purpose: it must run unchanged on windows-latest, where
 * `python3` does not exist.
 *
 * Usage: node test/suite.mjs
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCAN = path.join(HERE, '..', 'scan.mjs');  // la acción vive en la raíz del repo
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'pqc-suite-'));

let pass = 0;
const failures = [];

function run(args, env = {}) {
  const r = spawnSync(process.execPath, [SCAN, ...args], {
    cwd: WORK, encoding: 'utf8', env: { ...process.env, ...env },
  });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

/** Write a fixture tree under a fresh subdirectory and return its name (relative to WORK). */
function fixture(name, files) {
  const dir = path.join(WORK, name);
  fs.rmSync(dir, { recursive: true, force: true });
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    if (Buffer.isBuffer(content)) fs.writeFileSync(p, content);
    else fs.writeFileSync(p, content);
  }
  return name;
}

function cbom(name) { return JSON.parse(fs.readFileSync(path.join(WORK, name), 'utf8')); }

function check(title, fn) {
  try {
    fn();
    pass++;
    console.log(`  ok   ${title}`);
  } catch (e) {
    failures.push({ title, message: e.message });
    console.log(`  FAIL ${title}\n         ${e.message}`);
  }
}
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

/** Vulnerable families reported as occurring in code. */
function vulnNames(doc) {
  return doc.components
    .filter((c) => (c.properties || []).some((p) => p.name === 'fractalai:quantum_vulnerable' && p.value === 'true'))
    .filter((c) => Number((c.properties.find((p) => p.name === 'fractalai:occurrences') || {}).value) > 0)
    .map((c) => c.name);
}
function resistantNames(doc) {
  return doc.components
    .filter((c) => (c.properties || []).some((p) => p.name === 'fractalai:quantum_vulnerable' && p.value === 'false'))
    .map((c) => c.name);
}
const occurrences = (doc, name) => Number(
  doc.components.find((c) => c.name === name).properties.find((p) => p.name === 'fractalai:occurrences').value);

console.log('\nPQC Readiness Scan — regression suite\n');

// ───────────────────────── Detection: it must find real cryptography ─────────────────────────
check('finds classical cryptography in JavaScript', () => {
  const d = fixture('js', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst k = crypto.createECDH("secp256k1");\n' });
  run([`--path=${d}`, '--output=js.json']);
  const names = vulnNames(cbom('js.json'));
  assert(names.some((n) => n.includes('RSA')), `RSA missing: ${names}`);
  assert(names.some((n) => n.includes('ECDSA')) || names.some((n) => n.includes('ECDH')), `EC missing: ${names}`);
});

// El `\b` trataba `_` como carácter de palabra, así que toda la API de OpenSSL, de Rust y de PHP
// (UPPER_SNAKE) era invisible. Era el 61% de los fallos de detección medidos.
check('finds UPPER_SNAKE API names that a word boundary used to hide', () => {
  const d = fixture('snake', {
    'a.c': 'EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);\nEVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, ...);\nEC_KEY_new_by_curve_name(NID_X9_62_PRIME256V1);\n',
    'b.rs': 'use ed25519_dalek::SigningKey;\nuse x25519_dalek::EphemeralSecret;\n',
    'c.php': '"private_key_type" => OPENSSL_KEYTYPE_RSA,\n',
  });
  run([`--path=${d}`, '--output=snake.json']);
  const names = vulnNames(cbom('snake.json'));
  assert(names.some((n) => n.includes('RSA')), `EVP_PKEY_RSA / OPENSSL_KEYTYPE_RSA missed: ${names}`);
  assert(names.some((n) => n.includes('Ed25519')), `ed25519_dalek missed: ${names}`);
  assert(names.some((n) => n.includes('X25519')), `x25519_dalek missed: ${names}`);
});

check('finds the JWT algorithm identifiers, including ES256K', () => {
  const d = fixture('jwt', { 'a.ts': "const a='RS256';\nconst b='PS256';\nconst c='ES256K';\nconst e='RS512';\n" });
  run([`--path=${d}`, '--output=jwt.json']);
  const names = vulnNames(cbom('jwt.json'));
  assert(names.some((n) => n.includes('RSA')), `RS256/PS256 missed: ${names}`);
  assert(names.some((n) => n.includes('ECDSA')), `ES256K missed: ${names}`);
});

check('finds committed key material and certificates', () => {
  const d = fixture('keys', {
    'id_rsa.pub': 'ssh-rsa AAAAB3NzaC1yc2EAAAA user@host\n',
    'cert.pem': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
  });
  run([`--path=${d}`, '--output=keys.json']);
  const names = vulnNames(cbom('keys.json'));
  assert(names.some((n) => n.includes('key material')), `key material missed: ${names}`);
});

check('finds classical cryptography declared as a dependency', () => {
  const d = fixture('dep', { 'package.json': '{"dependencies":{"ethers":"^6.0.0","elliptic":"^6.5.4","jsonwebtoken":"^9.0.0"}}' });
  run([`--path=${d}`, '--output=dep.json']);
  const names = vulnNames(cbom('dep.json'));
  assert(names.some((n) => n.includes('Dependency')), `dependency layer missed: ${names}`);
});

check('reads minified single-line bundles instead of skipping them', () => {
  const pad = 'x'.repeat(2000);
  const d = fixture('min', { 'bundle.min.js': `/*${pad}*/const s=crypto.createSign("RSA-SHA256");\n` });
  run([`--path=${d}`, '--output=min.json']);
  assert(vulnNames(cbom('min.json')).some((n) => n.includes('RSA')), 'a >1000-char line was skipped');
});

// ───────────────────── No false positives: the thing that kills credibility ─────────────────────
check('never reports ML-DSA, ML-KEM or SLH-DSA as vulnerable', () => {
  const d = fixture('pqc', {
    'a.ts': 'import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";\nconst b = ml_kem768;\n',
    'b.ts': 'const x = "ML_DSA_65", y = "mldsa65", z = "SLH-DSA-SHA2-128f", w = "slh_dsa_shake_256s";\nconst v = "Dilithium3", u = "Kyber768", t = "fips204";\n',
  });
  run([`--path=${d}`, '--output=pqc.json']);
  const names = vulnNames(cbom('pqc.json'));
  assert(names.length === 0, `false positive on post-quantum code: ${names}`);
  const res = resistantNames(cbom('pqc.json'));
  assert(res.some((n) => n.includes('ML-DSA')), `ML-DSA not credited as resistant: ${res}`);
  assert(res.some((n) => n.includes('SLH-DSA')), `underscore SLH-DSA spelling not credited: ${res}`);
});

check('does not match crypto names inside unrelated identifiers', () => {
  const d = fixture('ident', {
    'a.go': 'rsaCount int // Retail Sales Analytics\ndsaRecords int\nmedsaEntries int\nP256Budget int\nes256Quota int\necdsaDisabled := true\n',
    'b.ts': "const p11='PKCS11'; const p12='PKCS12 keystore holds an EC key'; const p15='PKCS15 card';\n",
  });
  run([`--path=${d}`, '--output=ident.json']);
  const names = vulnNames(cbom('ident.json'));
  assert(names.length === 0, `false positive on unrelated identifiers: ${names}`);
});

check('a line that forbids an algorithm is not counted as a finding', () => {
  const d = fixture('neg', { 'policy.conf': 'deny_signature = RSA\ndeny_key_exchange = X25519\n' });
  run([`--path=${d}`, '--output=neg.json']);
  const names = vulnNames(cbom('neg.json'));
  assert(names.length === 0, `a prohibition was counted as a finding: ${names}`);
  const doc = cbom('neg.json');
  const noted = doc.components.some((c) => (c.properties || []).some((p) => p.name === 'fractalai:mentions_not_counted'));
  assert(noted, 'the prohibition was dropped instead of reported separately');
});

check('a prohibition does not erase a real use elsewhere in the repository', () => {
  const d = fixture('mix', { 'policy.conf': 'deny_signature = RSA\n', 'real.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  run([`--path=${d}`, '--output=mix.json']);
  assert(occurrences(cbom('mix.json'), 'RSA') === 1, 'the real use was lost or double counted');
});

// ───────────────────────────── Honest numbers ─────────────────────────────
check('occurrences is the real total, not the number of listed locations', () => {
  const d = fixture('many', { 'a.js': 'const k = "RSA-2048";\n'.repeat(300) });
  run([`--path=${d}`, '--output=many.json']);
  assert(occurrences(cbom('many.json'), 'RSA') === 300, `expected 300, got ${occurrences(cbom('many.json'), 'RSA')}`);
});

check('ten mentions on one line count as ten, not one', () => {
  const d = fixture('oneline', { 'a.js': `const a = "${'RSA '.repeat(10)}";\n` });
  run([`--path=${d}`, '--output=oneline.json']);
  assert(occurrences(cbom('oneline.json'), 'RSA') === 10, `expected 10, got ${occurrences(cbom('oneline.json'), 'RSA')}`);
});

// ───────────────── Coverage honesty: a truncated scan must never read as clean ─────────────────
check('an oversize file is reported as truncated coverage, not as a clean pass', () => {
  const d = fixture('over', { 'vendored.js': 'const k = crypto.createSign("RSA-SHA256");\n'.repeat(60000) });
  const r = run([`--path=${d}`, '--output=over.json']);
  assert(/COVERAGE WAS TRUNCATED/.test(r.out), 'a skipped file produced a green pass');
  const limits = cbom('over.json').metadata.properties.find((p) => p.name === 'fractalai:coverage_limits').value;
  assert(/were skipped/.test(limits), `coverage limits not recorded: ${limits}`);
});

check('a UTF-16 file is reported as unmatched instead of silently claiming full coverage', () => {
  const d = fixture('u16', { 'a.js': Buffer.from('const k = "RSA-2048"; // ECDSA Ed25519\n', 'utf16le') });
  const r = run([`--path=${d}`, '--output=u16.json']);
  assert(/COVERAGE WAS TRUNCATED/.test(r.out), 'a UTF-16 file was counted as fully scanned');
  const limits = cbom('u16.json').metadata.properties.find((p) => p.name === 'fractalai:coverage_limits').value;
  assert(/not UTF-8/.test(limits), `UTF-16 not disclosed: ${limits}`);
});

check('a clean scan says plainly that no cap was hit', () => {
  const d = fixture('clean', { 'a.ts': 'export const x = 1;\n' });
  run([`--path=${d}`, '--output=clean.json']);
  const limits = cbom('clean.json').metadata.properties.find((p) => p.name === 'fractalai:coverage_limits').value;
  assert(/No cap was hit/.test(limits), `expected a clean coverage statement, got: ${limits}`);
});

// ───────────────────────────── Security ─────────────────────────────
check('an output path with a newline is refused before anything is written', () => {
  const d = fixture('sec1', { 'a.js': 'RSA\n' });
  const go = path.join(WORK, 'go.txt');
  fs.writeFileSync(go, '');
  const r = run([`--path=${d}`, '--output=out.json\nPWNED=1'], { GITHUB_OUTPUT: go });
  assert(r.code === 2, `expected exit 2, got ${r.code}`);
  assert(!/PWNED/.test(fs.readFileSync(go, 'utf8')), 'an output variable was injected');
});

check('step outputs use a random delimiter so they cannot be forged', () => {
  const d = fixture('sec2', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  const go = path.join(WORK, 'go2.txt');
  fs.writeFileSync(go, '');
  run([`--path=${d}`, '--output=ok.json'], { GITHUB_OUTPUT: go });
  const written = fs.readFileSync(go, 'utf8');
  assert(/^findings=\d+$/m.test(written), `findings not a bare number: ${written}`);
  assert(/cbom<<PQC_EOF_[0-9a-f]{32}/.test(written), `cbom not delimited: ${written}`);
});

check('an output path outside the workspace is refused', () => {
  const d = fixture('sec3', { 'a.js': 'RSA\n' });
  const r = run([`--path=${d}`, '--output=../../escaped.json']);
  assert(r.code === 2, `traversal accepted (exit ${r.code})`);
  assert(!fs.existsSync(path.join(WORK, '..', '..', 'escaped.json')), 'a file was written outside the workspace');
});

check('the workspace confinement holds when GITHUB_WORKSPACE is set', () => {
  // El confinamiento se mide desde el directorio de trabajo, y cuando ese directorio está dentro
  // del espacio de trabajo de Actions se usa el espacio entero. Imponer GITHUB_WORKSPACE a ciegas
  // rompía toda escritura legítima de cualquier proceso que corriera fuera de él, incluida esta
  // batería; no imponerlo nunca permitiría escapar del checkout. Las dos mitades se comprueban.
  const d = fixture('ws', { 'a.js': 'const k = "RSA-2048";\n' });
  const inside = run([`--path=${d}`, '--output=inside.json'], { GITHUB_WORKSPACE: WORK });
  assert(inside.code === 0, `a legitimate write inside the workspace was refused (exit ${inside.code})`);
  const outside = run([`--path=${d}`, '--output=../../escaped.json'], { GITHUB_WORKSPACE: WORK });
  assert(outside.code === 2, `an escape from the workspace was accepted (exit ${outside.code})`);
});

check('an output path that is a symlink is refused', () => {
  const d = fixture('sec4', { 'a.js': 'RSA\n' });
  const target = path.join(WORK, 'precious.txt');
  fs.writeFileSync(target, 'ORIGINAL');
  const link = path.join(WORK, 'link.json');
  try { fs.symlinkSync(target, link); } catch { return; }   // Windows without privileges: skip
  const r = run([`--path=${d}`, '--output=link.json']);
  assert(r.code === 2, `symlink accepted (exit ${r.code})`);
  assert(fs.readFileSync(target, 'utf8') === 'ORIGINAL', 'the symlink target was overwritten');
});

check('control characters in a scanned filename never reach the log raw', () => {
  // Bytes de escape REALES escritos como \u001b en la fuente, para que el archivo de pruebas sea
  // legible: un repositorio hostil puede cometer un archivo cuyo NOMBRE mueva el cursor del log de
  // quien nos adopta y tape líneas verdaderas del propio informe.
  const ESC = '\u001b';
  const name = `evil${ESC}[31mRED${ESC}[0m\rCARRIAGE.js`;
  let d;
  try { d = fixture('sec5', { [name]: 'const k = "RSA-2048";\n' }); } catch { return; }  // Windows: skip
  const r = run([`--path=${d}`, '--output=sec5.json']);
  assert(r.out.includes('CARRIAGE.js'), 'the file was never scanned, so this test would prove nothing');
  assert(!r.out.includes(`${ESC}[31mRED`), 'an ANSI escape from a filename reached the log');
  assert(!r.out.includes('\rCARRIAGE'), 'a carriage return from a filename reached the log');
});

// ───────────────────────────── Behaviour and contract ─────────────────────────────
check('fail-on-findings exits non-zero, and only when asked', () => {
  const d = fixture('gate', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  assert(run([`--path=${d}`, '--output=g1.json']).code === 0, 'the default must not fail the build');
  assert(run([`--path=${d}`, '--output=g2.json', '--fail-on-findings=true']).code === 1, 'the gate did not fail');
});

check('a missing path fails loudly instead of passing green', () => {
  assert(run(['--path=./does-not-exist', '--output=x.json']).code === 2, 'a bad path passed silently');
});

check('an empty --output falls back to the default instead of crashing', () => {
  const d = fixture('empty', { 'a.js': 'RSA\n' });
  const r = run([`--path=${d}`, '--output=']);
  assert(r.code === 0, `exit ${r.code}`);
  assert(fs.existsSync(path.join(WORK, 'cbom.json')), 'the default output was not written');
});

check('a nested output directory is created', () => {
  const d = fixture('nested', { 'a.js': 'RSA\n' });
  const r = run([`--path=${d}`, '--output=reports/deep/cbom.json']);
  assert(r.code === 0, `exit ${r.code}`);
  assert(fs.existsSync(path.join(WORK, 'reports', 'deep', 'cbom.json')), 'the directory was not created');
});

check('inputs arrive through the environment, the way the action passes them', () => {
  const d = fixture('env', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  const r = run([], { PQC_PATH: d, PQC_OUTPUT: 'env.json' });
  assert(r.code === 0, `exit ${r.code}`);
  assert(vulnNames(cbom('env.json')).some((n) => n.includes('RSA')), 'the env input was ignored');
});

check('seal only runs over https', () => {
  const d = fixture('seal', { 'a.js': 'RSA\n' });
  const r = run([`--path=${d}`, '--output=s.json', '--seal=true'], { FRACTALAI_BASE_URL: 'http://evil.example.com' });
  assert(r.code === 2, `a plaintext seal endpoint was accepted (exit ${r.code})`);
});

// ───────────────────────────── The CBOM itself ─────────────────────────────
check('the CBOM is CycloneDX 1.6 with cryptographic-asset components', () => {
  const d = fixture('spec', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst k = crypto.createECDH("secp256k1");\n' });
  run([`--path=${d}`, '--output=spec.json']);
  const doc = cbom('spec.json');
  assert(doc.bomFormat === 'CycloneDX' && doc.specVersion === '1.6', 'not CycloneDX 1.6');
  assert(/^urn:uuid:[0-9a-f-]{36}$/.test(doc.serialNumber), `bad serialNumber: ${doc.serialNumber}`);
  assert(!Number.isNaN(Date.parse(doc.metadata.timestamp)), 'bad timestamp');
  for (const c of doc.components) {
    assert(c.type === 'cryptographic-asset', `bad component type: ${c.type}`);
    assert(c.cryptoProperties && c.cryptoProperties.assetType === 'algorithm', `bad cryptoProperties on ${c.name}`);
    assert(!('oid' in c.cryptoProperties) || c.cryptoProperties.oid.length > 0, `empty oid on ${c.name}`);
  }
});

// Declarar que ECDH firma convierte el inventario en una lista falsa de sitios de firma, que es
// justo lo que un plan de migración usaría para decidir. Un criptógrafo lo ve en diez segundos.
check('key-agreement algorithms are never declared as signing functions', () => {
  const d = fixture('fns', { 'a.js': 'const k = crypto.createECDH("prime256v1");\nconst x = "X25519";\nconst d = "diffie-hellman";\n' });
  run([`--path=${d}`, '--output=fns.json']);
  for (const c of cbom('fns.json').components) {
    const ap = c.cryptoProperties.algorithmProperties;
    if (ap.primitive === 'key-agree') {
      assert(!ap.cryptoFunctions.includes('sign'), `${c.name} is key-agree but declares sign`);
    }
  }
});

check('no algorithm is left with primitive "unknown" unless it genuinely is', () => {
  const d = fixture('prim', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst e = "ECDSA";\nconst h = "SHA-256";\n' });
  run([`--path=${d}`, '--output=prim.json']);
  const named = { RSA: 'pke', ECDSA: 'signature', 'SHA-2': 'hash' };
  for (const c of cbom('prim.json').components) {
    if (named[c.name]) {
      assert(c.cryptoProperties.algorithmProperties.primitive === named[c.name],
        `${c.name} should be ${named[c.name]}, got ${c.cryptoProperties.algorithmProperties.primitive}`);
    }
  }
});

check('post-quantum algorithms carry their NIST security level explicitly', () => {
  const d = fixture('lvl', { 'a.ts': 'import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";\n' });
  run([`--path=${d}`, '--output=lvl.json']);
  const c = cbom('lvl.json').components.find((x) => x.name.includes('ML-DSA'));
  assert(c, 'ML-DSA component missing');
  // Sin esto, una ida y vuelta por la serialización protobuf devuelve 0, que el estándar define
  // como «no cumple NINGUNA categoría»: el archivo afirmaría lo contrario de su propia tesis.
  assert(c.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel === 3,
    'ML-DSA has no explicit NIST level');
});

check('locations are emitted in the standard evidence block', () => {
  const d = fixture('ev', { 'src/a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  run([`--path=${d}`, '--output=ev.json']);
  const c = cbom('ev.json').components.find((x) => x.name === 'RSA');
  assert(c.evidence && Array.isArray(c.evidence.occurrences) && c.evidence.occurrences.length > 0,
    'no evidence.occurrences block');
  assert(c.evidence.occurrences[0].location === 'src/a.js', `bad location: ${c.evidence.occurrences[0].location}`);
  // POSIX siempre: con separadores nativos de Windows el mismo repositorio daría dos documentos.
  assert(!c.evidence.occurrences[0].location.includes('\\'), 'a Windows separator reached the CBOM');
  assert(typeof c.evidence.occurrences[0].line === 'number', 'no line number');
});

check('no source line content is ever stored in the CBOM', () => {
  const secret = 'TOP_SECRET_PASSPHRASE_9c3f';
  const d = fixture('leak', { 'a.js': `const k = crypto.createSign("RSA-SHA256"); // ${secret}\n` });
  const r = run([`--path=${d}`, '--output=leak.json']);
  const raw = fs.readFileSync(path.join(WORK, 'leak.json'), 'utf8');
  assert(!raw.includes(secret), 'source line content leaked into the CBOM');
  assert(!r.out.includes(secret), 'source line content leaked into the log');
});

// ───────────────────────────── Result ─────────────────────────────
fs.rmSync(WORK, { recursive: true, force: true });
console.log('');
if (failures.length) {
  console.log(`  ${pass} passed, ${failures.length} FAILED\n`);
  for (const f of failures) console.log(`  · ${f.title}: ${f.message}`);
  process.exit(1);
}
console.log(`  ${pass} checks passed.\n`);
