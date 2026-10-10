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

check('finds the Node key-agreement APIs by their function names', () => {
  // La frontera por letra, que es correcta y arreglo el 61% de fallos de deteccion, bloqueaba de
  // rebote los nombres en CamelCase: en `crypto.createECDH(...)` el "ECDH" va precedido por la "e"
  // de "create". Es la API mas usada de Node para acuerdo de claves, es decir el caso de urgencia
  // `harvest`, y pasaba invisible. Lo encontro la propia bateria al probar el trinquete.
  const d = fixture('nodeapi', {
    'a.js': "const k = crypto.createECDH('prime256v1');\nconst d = crypto.createDiffieHellman(2048);\nconst g = crypto.getDiffieHellman('modp14');\n",
  });
  run([`--path=${d}`, '--output=nodeapi.json']);
  const names = vulnNames(cbom('nodeapi.json'));
  assert(names.some((n) => n === 'ECDH'), `createECDH missed: ${names}`);
  assert(names.some((n) => n.includes('Diffie-Hellman')), `createDiffieHellman missed: ${names}`);
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

// ───────────────────── SARIF: la salida que vive en la interfaz de GitHub ─────────────────────
const sarif = (name) => JSON.parse(fs.readFileSync(path.join(WORK, name), 'utf8'));

check('emits valid SARIF 2.1.0 with one rule per family and stable fingerprints', () => {
  const d = fixture('sarif', { 'src/a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst k = crypto.createECDH("secp256k1");\n' });
  const r = run([`--path=${d}`, '--output=s.json', '--sarif=s.sarif']);
  assert(r.code === 0, `exit ${r.code}`);
  const doc = sarif('s.sarif');
  assert(doc.version === '2.1.0', `version ${doc.version}`);
  const run0 = doc.runs[0];
  assert(run0.tool.driver.name === 'PQC Readiness Scan', 'tool name');
  assert(run0.tool.driver.rules.length > 0, 'no rules');
  assert(run0.results.length > 0, 'no results');
  for (const res of run0.results) {
    assert(run0.tool.driver.rules.some((x) => x.id === res.ruleId), `result ${res.ruleId} has no rule`);
    const loc = res.locations[0].physicalLocation;
    assert(loc.artifactLocation.uri && !loc.artifactLocation.uri.includes('\\'), `bad uri ${loc.artifactLocation.uri}`);
    assert(typeof loc.region.startLine === 'number', 'no startLine');
    // Sin huella estable GitHub abre una alerta NUEVA cada vez que alguien mueve una linea, el
    // panel se llena de duplicados y el equipo deja de mirarlo.
    assert(res.partialFingerprints && res.partialFingerprints.pqcFamilyFile, 'no partialFingerprints');
  }
});

// Un `error` en Code Scanning bloquea revisiones en muchas configuraciones. Esto es un INVENTARIO,
// no una vulnerabilidad explotable hoy: marcar 800 lineas como errores el primer dia consigue una
// sola cosa, que desactiven la herramienta.
check('no SARIF finding is emitted at error level', () => {
  const d = fixture('sarif2', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst k = "X25519";\nconst j = "ES256";\n' });
  run([`--path=${d}`, '--output=s2.json', '--sarif=s2.sarif']);
  const doc = sarif('s2.sarif');
  for (const rule of doc.runs[0].tool.driver.rules) {
    assert(rule.defaultConfiguration.level !== 'error', `${rule.id} is error level`);
    assert(rule.properties['security-severity'], `${rule.id} has no security-severity`);
  }
  for (const res of doc.runs[0].results) assert(res.level !== 'error', `${res.ruleId} result is error level`);
});

check('key agreement ranks above signatures in SARIF severity', () => {
  const d = fixture('sev', { 'a.js': 'const k = "X25519";\nconst j = "ES256";\n' });
  run([`--path=${d}`, '--output=sev.json', '--sarif=sev.sarif']);
  const rules = sarif('sev.sarif').runs[0].tool.driver.rules;
  const sevOf = (id) => Number(rules.find((r) => r.id === id)?.properties['security-severity'] || 0);
  // Harvest-now-decrypt-later: el trafico grabado hoy no se puede des-grabar, asi que un sitio de
  // acuerdo de claves no puede ordenarse por debajo de uno de firma.
  assert(sevOf('pqc/x25519') > sevOf('pqc/ecdsa'),
    `key agreement ${sevOf('pqc/x25519')} must outrank signature ${sevOf('pqc/ecdsa')}`);
});

check('truncated coverage travels inside the SARIF, not only in the log', () => {
  const d = fixture('sarifcov', { 'big.js': 'const k = crypto.createSign("RSA-SHA256");\n'.repeat(60000), 'ok.js': 'const x = "ECDSA";\n' });
  run([`--path=${d}`, '--output=sc.json', '--sarif=sc.sarif']);
  const inv = sarif('sc.sarif').runs[0].invocations[0];
  assert(inv.toolExecutionNotifications.length > 0, 'coverage limits missing from the SARIF');
  assert(/Coverage limit/.test(inv.toolExecutionNotifications[0].message.text), 'notification text');
});

// ─────────────────── Trinquete: la puerta que un equipo acepta el primer dia ───────────────────
check('the baseline freezes a count per family, not a single total', () => {
  const d = fixture('base1', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst k = "X25519";\n' });
  const r = run([`--path=${d}`, '--output=b1.json', '--baseline=bl.json', '--write-baseline=true']);
  assert(r.code === 0, `exit ${r.code}`);
  const bl = JSON.parse(fs.readFileSync(path.join(WORK, 'bl.json'), 'utf8'));
  assert(bl.counts && typeof bl.counts === 'object', 'no counts object');
  assert(Object.keys(bl.counts).length >= 2, `expected per-family counts, got ${JSON.stringify(bl.counts)}`);
  assert(bl.created_at, 'no created_at');
});

check('the ratchet does not fire when nothing changed', () => {
  const d = fixture('base2', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  run([`--path=${d}`, '--output=b2.json', '--baseline=bl2.json', '--write-baseline=true']);
  const r = run([`--path=${d}`, '--output=b2.json', '--baseline=bl2.json', '--fail-on-increase=true']);
  assert(r.code === 0, `the gate fired on an unchanged repository (exit ${r.code})`);
});

check('the ratchet fires when a family goes up, and says which', () => {
  const d = fixture('base3', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  run([`--path=${d}`, '--output=b3.json', '--baseline=bl3.json', '--write-baseline=true']);
  fs.writeFileSync(path.join(WORK, d, 'new.js'), 'const k = crypto.createECDH("prime256v1");\n');
  const r = run([`--path=${d}`, '--output=b3.json', '--baseline=bl3.json', '--fail-on-increase=true'], { GITHUB_ACTIONS: '1' });
  assert(r.code === 1, `expected exit 1, got ${r.code}`);
  assert(/went UP/.test(r.out), 'the log does not say what went up');
  assert(/::error title=/.test(r.out), 'no run annotation, so it is invisible outside the log');
});

// Una familia de firma que baja y una de acuerdo de claves que sube puede DEJAR IGUAL el total y
// empeorar la exposicion real. Comparar un solo numero esconde exactamente el cambio que importa.
check('the ratchet compares per family, so a swap that keeps the total still fires', () => {
  const d = fixture('base4', { 'a.js': 'const j = "ES256";\nconst k = "ES384";\n' });
  run([`--path=${d}`, '--output=b4.json', '--baseline=bl4.json', '--write-baseline=true']);
  fs.writeFileSync(path.join(WORK, d, 'a.js'), 'const j = "ES256";\nconst k = crypto.createECDH("prime256v1");\n');
  const r = run([`--path=${d}`, '--output=b4.json', '--baseline=bl4.json', '--fail-on-increase=true']);
  assert(r.code === 1, `a family went up but the gate stayed quiet (exit ${r.code})`);
});

check('the ratchet reports improvement instead of staying silent', () => {
  const d = fixture('base5', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst k = "X25519";\n' });
  run([`--path=${d}`, '--output=b5.json', '--baseline=bl5.json', '--write-baseline=true']);
  fs.writeFileSync(path.join(WORK, d, 'a.js'), 'const x = 1;\n');
  const r = run([`--path=${d}`, '--output=b5.json', '--baseline=bl5.json', '--fail-on-increase=true']);
  assert(r.code === 0, `exit ${r.code}`);
  assert(/▼/.test(r.out), 'the improvement was not reported');
});

// Pedir la puerta sin linea base no puede pasar en silencio: el pase se pondria verde para siempre
// y el equipo creeria tener una proteccion que no existe.
check('asking for the gate with no baseline fails loudly instead of passing green', () => {
  const d = fixture('base6', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  const r = run([`--path=${d}`, '--output=b6.json', '--baseline=missing.json', '--fail-on-increase=true']);
  assert(r.code === 2, `expected exit 2, got ${r.code}`);
  assert(/no baseline/.test(r.out), 'the reason was not stated');
});

check('a corrupt baseline is refused rather than guessed at', () => {
  const d = fixture('base7', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  fs.writeFileSync(path.join(WORK, 'bad.json'), '{"not":"a baseline"}');
  const r = run([`--path=${d}`, '--output=b7.json', '--baseline=bad.json']);
  assert(r.code === 2, `a corrupt baseline was accepted (exit ${r.code})`);
});

// ─────────────── Autoexclusion: la herramienta no puede contarse a si misma ───────────────
check('the scan never reads its own output, so two runs agree', () => {
  const d = fixture('self', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst k = "X25519";\n' });
  // El CBOM contiene por definicion los nombres de los algoritmos que inventaria: leerlo inflaba
  // las cifras con hallazgos que eran nuestro propio informe.
  run([`--path=${d}`, `--output=${d}/cbom.json`, `--sarif=${d}/out.sarif`]);
  const first = Number(/(\d+) occurrence\(s\) in code/.exec(run([`--path=${d}`, '--output=x1.json'])?.out || '')?.[1] || -1);
  const second = Number(/(\d+) occurrence\(s\) in code/.exec(run([`--path=${d}`, '--output=x2.json'])?.out || '')?.[1] || -2);
  assert(first === second && first === 2, `self-pollution: ${first} vs ${second}, expected 2`);
});

check('an existing CBOM or baseline committed under any name is excluded by content', () => {
  const d = fixture('self2', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  // Renombrados a proposito: la exclusion debe ser por CONTENIDO, no por nombre de archivo.
  fs.writeFileSync(path.join(WORK, d, 'inventory-archive.json'), JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'RSA' }, { name: 'ECDSA' }] }));
  fs.writeFileSync(path.join(WORK, d, 'frozen-counts.json'), JSON.stringify({ tool: 'pqc-readiness-scan', counts: { rsa: 9, ecdsa: 9, x25519: 9 } }));
  const r = run([`--path=${d}`, '--output=s2b.json']);
  const n = Number(/(\d+) occurrence\(s\) in code/.exec(r.out)?.[1] || -1);
  assert(n === 1, `a renamed inventory document poisoned the scan: ${n} occurrences, expected 1`);
  assert(/excluded on purpose/.test(r.out), 'the exclusion was silent instead of disclosed');
});

// ─────────────────────── Dependencias transitivas de los lock files ───────────────────────
check('transitive dependencies in lock files are inventoried', () => {
  const d = fixture('locks', {
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/elliptic': { version: '6.5.4' }, 'node_modules/node-forge': { version: '1.3.1' } } }, null, 2),
    'Cargo.lock': '[[package]]\nname = "ring"\nversion = "0.17.5"\n',
    'go.sum': 'github.com/btcsuite/btcd/btcec/v2 v2.3.2 h1:abc=\n',
    'app.ts': 'export const x = 1;\n',
  });
  const r = run([`--path=${d}`, '--output=locks.json']);
  assert(r.code === 0, `exit ${r.code}`);
  const names = vulnNames(cbom('locks.json'));
  // Sin esta capa un monedero completo de blockchain, secp256k1 de punta a punta, sale limpio.
  assert(names.some((n) => n.includes('Dependency')), `lock-file dependencies missed: ${names}`);
});

// ─────────────────────────── El informe para una persona ───────────────────────────
check('the written report leads with harvest-now-decrypt-later, not with the biggest number', () => {
  const d = fixture('rep', {
    // Muchas firmas y UNA sola de acuerdo de claves: ordenar por cantidad pondria las firmas
    // primero, y seria el peor consejo posible.
    'many.js': 'const j = "ES256";\n'.repeat(40),
    'one.js': 'const k = crypto.createECDH("prime256v1");\n',
  });
  const r = run([`--path=${d}`, '--output=rp.json', '--report=rp.md']);
  assert(r.code === 0, `exit ${r.code}`);
  const md = fs.readFileSync(path.join(WORK, 'rp.md'), 'utf8');
  const iHarvest = md.indexOf('already losing ground');
  const iDeadline = md.indexOf('what the deadline governs');
  assert(iHarvest > 0 && iDeadline > 0, 'the report has no urgency sections');
  assert(iHarvest < iDeadline, 'the report ranks signatures above key agreement');
  assert(/not a proof of absence/.test(md), 'the report omits its own limits');
  assert(/not a compliance certification/.test(md), 'the report omits the certification limit');
});

check('the report states the coverage limits of the very scan that produced it', () => {
  const d = fixture('rep2', { 'big.js': 'const k = crypto.createSign("RSA-SHA256");\n'.repeat(60000), 'ok.js': 'const x = "ECDSA";\n' });
  run([`--path=${d}`, '--output=rp2.json', '--report=rp2.md']);
  const md = fs.readFileSync(path.join(WORK, 'rp2.md'), 'utf8');
  assert(/did not read everything/.test(md), 'a truncated scan produced a report that reads as complete');
});

// ─────────────────────── La urgencia viaja en el documento ───────────────────────
check('urgency is recorded in the CBOM so nothing downstream has to infer it', () => {
  const d = fixture('urg', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\nconst j = "ES256";\nconst k = "X25519";\n' });
  run([`--path=${d}`, '--output=urg.json']);
  const doc = cbom('urg.json');
  const urgency = (name) => {
    const c = doc.components.find((x) => x.name === name);
    return (c.properties || []).find((p) => p.name === 'fractalai:urgency')?.value;
  };
  assert(urgency('ECDSA') === 'deadline', `ECDSA urgency ${urgency('ECDSA')}`);
  assert(urgency('X25519 / X448') === 'harvest', `X25519 urgency ${urgency('X25519 / X448')}`);
  // RSA es `harvest` aunque su primitive sea `pke`: un barrido estatico no puede distinguir
  // transporte de claves de firma, y ante la duda se asume la lectura con exposicion retroactiva.
  // Inferirlo del primitive daba mal justamente este caso.
  assert(urgency('RSA') === 'harvest', `RSA urgency ${urgency('RSA')}; inferring it from the primitive gets this one wrong`);
});

// ─────────────────────── Salidas del paso para el workflow ───────────────────────
check('the step publishes the ratchet and the truncation as usable outputs', () => {
  const d = fixture('outs', { 'a.js': 'const s = crypto.createSign("RSA-SHA256");\n' });
  const go = path.join(WORK, 'go-outs.txt');
  fs.writeFileSync(go, '');
  run([`--path=${d}`, '--output=o.json', '--sarif=o.sarif', '--baseline=blo.json', '--write-baseline=true'], { GITHUB_OUTPUT: go });
  fs.writeFileSync(go, '');
  run([`--path=${d}`, '--output=o.json', '--sarif=o.sarif', '--baseline=blo.json'], { GITHUB_OUTPUT: go });
  const written = fs.readFileSync(go, 'utf8');
  for (const key of ['findings=', 'increased=', 'decreased=', 'truncated=']) {
    assert(written.includes(key), `output ${key} missing from: ${written}`);
  }
  assert(/sarif<<PQC_EOF_[0-9a-f]{32}/.test(written), 'the sarif path is not delimited');
});

// ─────────────── El contrato entre el manifiesto y el escaner ───────────────
// Esta prueba existe por un fallo concreto: se anadio la entrada `report` al escaner y se olvido
// declararla en action.yml, asi que la accion la IGNORABA en silencio y solo un aviso perdido en el
// log decia "Unexpected input(s) 'report'". Las pruebas que llamaban al escaner directamente
// pasaban, porque el agujero estaba en el manifiesto, no en el codigo. Un contrato entre dos
// archivos que nadie comprueba se rompe en el tercer cambio.
check('every input the scanner reads is declared in action.yml and wired through env', () => {
  const scan = fs.readFileSync(SCAN, 'utf8');
  const manifest = fs.readFileSync(path.join(HERE, '..', 'action.yml'), 'utf8');

  // input('PQC_FOO', 'foo', default) -> la pareja (variable de entorno, nombre de la entrada)
  const pairs = [...scan.matchAll(/input\(\s*'([A-Z_]+)'\s*,\s*'([a-z-]+)'/g)]
    .map((m) => ({ env: m[1], name: m[2] }));
  assert(pairs.length >= 8, `expected the scanner to read several inputs, found ${pairs.length}`);

  const declared = new Set([...manifest.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)].map((m) => m[1]));
  const wired = new Set([...manifest.matchAll(/^ {8}([A-Z_]+):/gm)].map((m) => m[1]));

  const undeclared = pairs.filter((x) => !declared.has(x.name)).map((x) => x.name);
  assert(undeclared.length === 0, `inputs read by the scanner but not declared in action.yml: ${undeclared}`);

  const unwired = pairs.filter((x) => !wired.has(x.env)).map((x) => `${x.name} (${x.env})`);
  assert(unwired.length === 0, `inputs declared but never passed through env, so the action ignores them: ${unwired}`);
});

check('every output the scanner writes is declared in action.yml', () => {
  const scan = fs.readFileSync(SCAN, 'utf8');
  const manifest = fs.readFileSync(path.join(HERE, '..', 'action.yml'), 'utf8');
  // Las lineas que el escaner escribe en GITHUB_OUTPUT, en sus dos formas.
  const written = new Set([
    ...[...scan.matchAll(/`([a-z]+)=\$\{/g)].map((m) => m[1]),
    ...[...scan.matchAll(/`([a-z]+)<<\$\{/g)].map((m) => m[1]),
  ]);
  assert(written.size >= 4, `expected several step outputs, found ${[...written]}`);
  const outsBlock = manifest.slice(manifest.indexOf('\noutputs:'), manifest.indexOf('\nruns:'));
  for (const name of written) {
    assert(new RegExp(`^ {2}${name}:$`, 'm').test(outsBlock),
      `the scanner writes the step output '${name}' but action.yml does not declare it, so no caller can read it`);
  }
});

// Los pasos de una accion composite NO admiten `continue-on-error`. Si un paso que depende de un
// permiso opcional no se guarda a mano, una falta de permisos tumba el pase de quien nos adopte por
// algo que quiza ni sabe que existe.
check('every optional step guards itself, since composite steps cannot continue-on-error', () => {
  const manifest = fs.readFileSync(path.join(HERE, '..', 'action.yml'), 'utf8');
  // Solo CLAVES reales, no texto: la primera version de esta prueba disparaba por el propio
  // comentario del manifiesto que explica por que no se puede usar continue-on-error.
  const realKey = manifest.split('\n').some((l) => /^\s*continue-on-error\s*:/.test(l) && !/^\s*#/.test(l));
  assert(!realKey, 'action.yml uses continue-on-error as a step key, which composite action steps silently ignore');
  const runsBlock = manifest.slice(manifest.indexOf('\nruns:'));
  // La subida a code scanning y el comentario del pull request dependen de permisos opcionales:
  // ambos deben acabar en `exit 0` o estar encadenados con `||`.
  assert(/exit 0/.test(runsBlock), 'the optional steps do not force a successful exit');
  assert(/\|\|\s*echo/.test(runsBlock), 'the pull-request comment step is not guarded with ||');
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
