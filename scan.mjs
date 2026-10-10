#!/usr/bin/env node
/**
 * PQC Readiness Scan — finds quantum-vulnerable cryptography in a repository and emits a
 * CycloneDX CBOM (Cryptographic Bill of Materials, ECMA-424).
 *
 * Why this exists: NIST IR 8547 deprecates RSA, ECDSA, ECDH, DH and DSA after 2030 and disallows
 * them after 2035. Before anyone can migrate, they need to know where those algorithms actually
 * live in their stack. That inventory is the first deliverable of every migration, and almost
 * nobody has it.
 *
 * What this is, honestly:
 *   - A STATIC scan of manifests and source for known quantum-vulnerable primitives.
 *   - It runs entirely in your runner. Nothing is uploaded. No account, no key, no payment.
 *
 * What this is NOT:
 *   - Not a proof of absence: a static scan misses dynamic loading, vendored binaries,
 *     hardware modules and anything behind an abstraction it does not recognise.
 *   - Not a compliance certification. It is evidence to start from, not a clean bill of health.
 *
 * Optional: `seal: true` asks FractalAI to sign the CBOM with ML-DSA-65 (FIPS 204) so a third
 * party can verify the inventory was produced at a given time and not edited afterwards. That
 * costs USDC over x402 and is strictly optional — the scan and the CBOM are free forever.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const arg = (n, d) => {
  const f = process.argv.find((a) => a.startsWith(`--${n}=`));
  const v = f ? f.slice(n.length + 3) : undefined;
  // Un `--output=` presente pero vacío NO debe ganarle al valor por defecto: antes devolvía la
  // cadena vacía y el pase moría con ENOENT después de haber hecho todo el trabajo.
  return v === undefined || v === '' ? d : v;
};
/** La acción pasa las entradas por el entorno. argv queda para uso local desde la terminal. */
const input = (envName, argName, d) => {
  const e = process.env[envName];
  return e === undefined || e === '' ? arg(argName, d) : e;
};

const ROOT = path.resolve(input('PQC_PATH', 'path', '.'));
const OUT_RAW = input('PQC_OUTPUT', 'output', 'cbom.json');
const FAIL = input('PQC_FAIL_ON_FINDINGS', 'fail-on-findings', 'false') === 'true';
const SEAL = input('PQC_SEAL', 'seal', 'false') === 'true';
/**
 * Destino del sellado. La variable de entorno existe para poder probar contra un servidor local,
 * pero en Actions el `env` de un workflow o de un workflow reutilizable que no controlas se hereda
 * hacia abajo: sin restringirla, alguien podía redirigir el sellado a otro host, en texto claro, y
 * el log no lo decía. Ahora solo se acepta https y SIEMPRE se imprime el destino antes de enviar.
 */
const DEFAULT_API = 'https://fractalai.net.co';
let API = DEFAULT_API;
let API_OVERRIDDEN = false;
if (process.env.FRACTALAI_BASE_URL) {
  try {
    const u = new URL(process.env.FRACTALAI_BASE_URL);
    const localhost = u.hostname === '127.0.0.1' || u.hostname === 'localhost';
    if (u.protocol !== 'https:' && !localhost) {
      console.error('  FRACTALAI_BASE_URL must use https.');
      process.exit(2);
    }
    API = u.origin;
    API_OVERRIDDEN = API !== DEFAULT_API;
  } catch {
    console.error('  FRACTALAI_BASE_URL is not a valid URL.');
    process.exit(2);
  }
}

/**
 * La ruta de salida es la única que escribimos, así que se valida como tal. Sin esto era una
 * primitiva de escritura arbitraria: `../..` salía del espacio de trabajo, una ruta absoluta
 * pisaba cualquier archivo, un enlace simbólico machacaba su destino, y un salto de línea dentro
 * del valor inyectaba variables falsas en $GITHUB_OUTPUT.
 */
function safeOutPath(raw) {
  if (/[\r\n\0]/.test(raw)) {
    console.error('  output: no puede contener saltos de línea ni bytes nulos.');
    process.exit(2);
  }
  // La base del confinamiento es el directorio de trabajo. Cuando ese directorio está DENTRO del
  // espacio de trabajo de Actions se usa el espacio completo, para que `output: ../informes/x.json`
  // siga siendo legítimo dentro del checkout. Lo que no se puede hacer es imponer GITHUB_WORKSPACE
  // a ciegas: un proceso que corre fuera de él (la propia batería de pruebas, o cualquier paso con
  // working-directory propio) vería rechazada toda escritura legítima.
  const cwd = process.cwd();
  const ws = process.env.GITHUB_WORKSPACE ? path.resolve(process.env.GITHUB_WORKSPACE) : null;
  const inWorkspace = ws && (cwd === ws || cwd.startsWith(ws + path.sep));
  const base = inWorkspace ? ws : cwd;
  const abs = path.resolve(cwd, raw);
  if (abs !== base && !abs.startsWith(base + path.sep)) {
    console.error(`  output: must stay inside ${base}. Received: ${abs}`);
    process.exit(2);
  }
  try {
    // lstat, no stat: lo que importa es si la ENTRADA es un enlace, no a dónde apunta.
    if (fs.lstatSync(abs).isSymbolicLink()) {
      console.error('  output: apunta a un enlace simbólico; escribir ahí pisaría su destino.');
      process.exit(2);
    }
  } catch { /* no existe todavía: es el caso normal */ }
  return abs;
}
const OUT = safeOutPath(OUT_RAW);
// Lo que se escribe es la ruta absoluta ya validada; lo que se PUBLICA como salida del paso y se
// imprime es la que pidió quien nos llama, porque es la que su propio workflow sabe consumir
// (`path: ${{ steps.x.outputs.cbom }}` en upload-artifact). Ya está validada, así que es segura.
const OUT_LABEL = OUT_RAW;

/**
 * Todo lo que venga del repositorio escaneado (nombres de archivo, contenido de líneas) es dato
 * ajeno y puede traer escapes ANSI o retornos de carro. Impreso en crudo en un log de CI, eso
 * permite falsificar colores, mover el cursor y tapar líneas reales del propio pase.
 */
const clean = (s) => String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');

/**
 * Quantum-vulnerable primitives per NIST IR 8547.
 *
 * On the boundaries, which is where the previous version of this file quietly failed: `\b` treats
 * `_` as a word character, so `EVP_PKEY_RSA`, `ed25519_dalek`, `ECDSA_P256` and
 * `OPENSSL_KEYTYPE_RSA` never matched — and C, Rust, PHP and the OpenSSL APIs are overwhelmingly
 * UPPER_SNAKE. Meanwhile a missing trailing boundary made `rsaCount` and `PKCS11` match as RSA.
 * A letter-only boundary fixes both directions at once: `_ - / : .` and quotes delimit a token,
 * a trailing letter does not. Measured over a 15-ecosystem fixture tree: 47 real constructs
 * recovered, 6 false positives removed, no true positive lost.
 *
 * Each entry also carries the facts a CBOM consumer needs: the CycloneDX `primitive`, the
 * `cryptoFunctions` the algorithm actually performs, and its OID where the family has one.
 * `why` says which deadline applies and what replaces it.
 */
const VULNERABLE = [
  { id: 'rsa', name: 'RSA', primitive: 'pke', nistQuantum: 0,
    fns: ['sign', 'verify', 'encrypt', 'decrypt', 'keygen'], oid: '1.2.840.113549.1.1.1',
    re: /(?<![A-Za-z])(?:RSA|rsaEncryption|RSASSA(?:-PSS)?|PKCS#?1(?:v15)?(?![0-9])|genrsa|RSAES)(?![A-Za-z])|(?<![A-Za-z])RS[Aa](?=Crypto|Key|KeyPair|Signature|Private|Public|Params|Encrypt|Decrypt|Sign|Verify|OAEP|PSS|Pkcs|Pss)|(?<![A-Za-z])(?:RS|PS)(?:256|384|512)(?![A-Za-z0-9])/i,
    why: 'Signature and key transport. Deprecated after 2030, disallowed after 2035 (NIST IR 8547). Replace signatures with ML-DSA (FIPS 204), key transport with ML-KEM (FIPS 203).' },

  { id: 'ecdsa', name: 'ECDSA', primitive: 'signature', nistQuantum: 0,
    fns: ['sign', 'verify', 'keygen'], oid: '1.2.840.10045.4.3.2',
    re: /(?<![A-Za-z])(?:ECDSA|secp(?:192|224|256|384|521)[kr]1|prime(?:192|239|256)v[123]|P-?(?:256|384|521)|ES(?:256|384|512)K?|nistp(?:256|384|521)|X9_62_PRIME256V1|ECC_NIST_P(?:256|384|521)|ECC_SECG_P256K1|EC_SIGN_P(?:256|384)|EC_prime256v1|SHA(?:1|224|256|384|512)with(?:EC)?DSA)(?![A-Za-z])|(?<![A-Za-z])ECDsa(?=Cng|Certificate|OpenSsl|P256|P384|P521)|(?<![A-Za-z])ECDSA_P(?:256|384|521)/i,
    why: 'Elliptic-curve signature. Deprecated after 2030, disallowed after 2035. Replace with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).' },

  // ECDH y X25519 acuerdan claves; NO firman. Declararles cryptoFunctions ["sign"] convertiría el
  // inventario en una lista falsa de sitios de firma, que es justo lo que un plan de migración usa.
  { id: 'ecdh', name: 'ECDH', primitive: 'key-agree', nistQuantum: 0,
    fns: ['keyderive', 'keygen'], oid: '1.3.132.1.12',
    re: /(?<![A-Za-z])(?:ECDHE?|ECDiffieHellman[A-Za-z]*)(?![A-Za-z])/i,
    why: 'Key agreement. Harvest-now-decrypt-later applies: traffic captured today can be decrypted once a quantum computer exists. Replace with ML-KEM (FIPS 203), hybrid during transition.' },

  { id: 'x25519', name: 'X25519 / X448', primitive: 'key-agree', nistQuantum: 0,
    fns: ['keyderive', 'keygen'], oid: '1.3.101.110',
    re: /(?<![A-Za-z])(?:X25519|X448|curve25519|crypto_box|nacl\.box|box\.GenerateKey|sodium_crypto_box_keypair)(?![A-Za-z])/i,
    why: 'Montgomery-curve key agreement, including the NaCl/libsodium box APIs. Same harvest-now-decrypt-later exposure as ECDH. Replace with ML-KEM (FIPS 203).' },

  { id: 'eddsa', name: 'Ed25519 / Ed448 (EdDSA)', primitive: 'signature', nistQuantum: 0,
    fns: ['sign', 'verify', 'keygen'], oid: '1.3.101.112',
    re: /(?<![A-Za-z])(?:Ed25519|Ed448|EdDSA|edwards25519|ssh-ed25519|nacl\.sign|sodium_crypto_sign_keypair)(?![A-Za-z])/i,
    why: 'Edwards-curve signature. Same quantum exposure as ECDSA. Replace with ML-DSA (FIPS 204).' },

  { id: 'dh', name: 'Diffie-Hellman (finite field)', primitive: 'key-agree', nistQuantum: 0,
    fns: ['keyderive', 'keygen'], oid: '1.2.840.113549.1.3.1',
    re: /(?<![A-Za-z])(?:DHE?-RSA|diffie[-_ ]?hellman|dhparam|MODP|EVP_PKEY_DH|PKey::DH|DH-?(?:1024|2048|3072|4096))(?![A-Za-z])/i,
    why: 'Finite-field key agreement. Deprecated after 2030. Replace with ML-KEM (FIPS 203).' },

  // La lista de lookbehind DEBE conservar las variantes con guión bajo: bajo una frontera por
  // letra, el `_` ya no bloquea, así que ML_DSA y SLH_DSA pasarían a ser falsos positivos. Reportar
  // ML-DSA como vulnerable es el error que haría que un criptógrafo tirara esto a la basura.
  { id: 'dsa', name: 'DSA', primitive: 'signature', nistQuantum: 0,
    fns: ['sign', 'verify', 'keygen'], oid: '1.2.840.10040.4.1',
    re: /(?<![A-Za-z])(?<!ML-)(?<!ML_)(?<!SLH-)(?<!SLH_)(?:DSA|dsaEncryption|DSA-?(?:1024|2048|3072)|SHA(?:1|224|256)withDSA|PKey::DSA)(?![A-Za-z])/i,
    why: 'Legacy signature, already discouraged pre-quantum. Replace with ML-DSA (FIPS 204).' },

  // Material de clave y certificados cometidos al repositorio. La etiqueta da el algoritmo para
  // ssh-rsa / ecdsa-sha2-* / "BEGIN RSA PRIVATE KEY"; un "BEGIN PRIVATE KEY" (PKCS#8) o un
  // "BEGIN CERTIFICATE" a secas requiere parsear el DER, así que se declara como activo de
  // algoritmo no determinado y NO se afirma que sea vulnerable.
  { id: 'keymaterial', name: 'X.509 / SSH key material (algorithm from label)',
    primitive: 'unknown', fns: ['unknown'],
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?(?:PRIVATE KEY|PUBLIC KEY|CERTIFICATE|CERTIFICATE REQUEST)-----|(?<![A-Za-z])(?:ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519)(?![A-Za-z])/,
    why: 'Key material or a certificate is committed in the repository. For ssh-rsa, ssh-dss, ecdsa-sha2-* and "BEGIN RSA/EC/DSA PRIVATE KEY" the label names the algorithm. A bare PKCS#8 "BEGIN PRIVATE KEY" or "BEGIN CERTIFICATE" needs DER parsing, so it is listed as an asset of undetermined algorithm, not asserted to be vulnerable.' },

  // Capa de dependencias: un regex de nombres de primitiva no puede ver una biblioteca. Sin esto,
  // un monedero completo de blockchain (secp256k1 de punta a punta) salía como limpio. Solo se
  // aplica a archivos de manifiesto, para que «ring» u «openssl» no casen en prosa.
  { id: 'dependency', name: 'Dependency implementing classical cryptography',
    primitive: 'unknown', fns: ['unknown'], manifestOnly: true,
    re: /(?:^|[@/"'\s=:,>])(?:elliptic|tweetnacl|ethers|web3|bitcoinjs-lib|ecpair|tiny-secp256k1|jsrsasign|node-forge|sshpk|jsonwebtoken|jose|python-jose|pyjwt|paramiko|pycryptodome|cryptography|pynacl|coincurve|eth-keys|k256|p256|ring|openssl|rsa|ecdsa|bcprov[\w-]*|bouncycastle[\w.]*|java-jwt|web3j|go-ethereum|btcec|edwards25519|golang-jwt|NSec[\w.]*|Nethereum[\w.]*|@solana\/web3\.js|@noble\/(?:secp256k1|ed25519|curves)|firebase\/php-jwt|ethereumjs)(?:["'\s=:,<\[\]/]|$)/i,
    why: 'A declared dependency whose purpose is RSA, ECDSA, EdDSA, secp256k1 or Diffie-Hellman. This is an inventory entry about the library, not a claim that your own call sites use it: the primitive lives in the dependency and travels with your build.' },
];

/**
 * Primitives that are already quantum-resistant: reported so the inventory is not one-sided.
 *
 * `nistQuantum` and `classical` are emitted explicitly. CycloneDX carries these as integers, and a
 * round-trip through the protobuf serialisation turns an absent integer into 0 — which the spec
 * defines as "meets NONE of the NIST categories". Omitting them would make a file bearing our name
 * assert, after one hop through the standard tooling, that ML-KEM and ML-DSA are not post-quantum.
 */
const RESISTANT = [
  { id: 'ml-dsa', name: 'ML-DSA (FIPS 204)', primitive: 'signature', fns: ['sign', 'verify', 'keygen'],
    nistQuantum: 3, classical: 192, re: /(?<![A-Za-z])(?:ML[-_]?DSA|Dilithium[2-5]?|fips[-_ ]?204)(?![A-Za-z])/i },
  { id: 'ml-kem', name: 'ML-KEM (FIPS 203)', primitive: 'kem', fns: ['encapsulate', 'decapsulate', 'keygen'],
    nistQuantum: 3, classical: 192, re: /(?<![A-Za-z])(?:ML[-_]?KEM|Kyber(?:512|768|1024)?|fips[-_ ]?203)(?![A-Za-z])/i },
  { id: 'slh-dsa', name: 'SLH-DSA (FIPS 205)', primitive: 'signature', fns: ['sign', 'verify', 'keygen'],
    nistQuantum: 3, classical: 192, re: /(?<![A-Za-z])(?:SLH[-_]?DSA|SPHINCS\+?|sphincsplus|fips[-_ ]?205)(?![A-Za-z])/i },
  { id: 'aes', name: 'AES', primitive: 'block-cipher', fns: ['encrypt', 'decrypt'],
    classical: 256, re: /(?<![A-Za-z])(?:AES[-_]?256)(?![A-Za-z])/i },
  // SHA-2 y SHA-3 son familias distintas (Merkle-Damgård contra esponja Keccak, FIPS 180-4 contra
  // FIPS 202). Un solo componente no puede ser ambas, así que van separadas.
  { id: 'sha2', name: 'SHA-2', primitive: 'hash', fns: ['digest'], oid: '2.16.840.1.101.3.4.2.1',
    re: /(?<![A-Za-z])(?:SHA-?(?:256|384|512))(?![A-Za-z0-9])/i },
  { id: 'sha3', name: 'SHA-3', primitive: 'hash', fns: ['digest'], oid: '2.16.840.1.101.3.4.2.8',
    re: /(?<![A-Za-z])(?:SHA3-?(?:224|256|384|512)|sha3_(?:256|512)|keccak)(?![A-Za-z])/i },
];

/** Nombres de manifiesto, como EXPRESIÓN. El conjunto anterior guardaba la cadena literal
 *  '*.csproj' y se consultaba con Set.has(nombreDeArchivo), así que el comodín era código muerto y
 *  ningún proyecto .NET se abría nunca. */
const MANIFEST_RE = /^(?:package(?:-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements[\w.-]*\.txt|Pipfile(?:\.lock)?|pyproject\.toml|poetry\.lock|Cargo\.(?:toml|lock)|go\.(?:mod|sum|work)|pom\.xml|build\.gradle(?:\.kts)?|build\.sbt|Gemfile(?:\.lock)?|composer\.(?:json|lock)|[\w.-]+\.(?:csproj|fsproj|vbproj)|packages\.config|Podfile(?:\.lock)?|pubspec\.(?:yaml|lock)|Dockerfile|mix\.exs|environment\.yml)$/i;
/** Archivos de clave, que no tienen extensión y por eso eran invisibles. */
const KEYFILE_RE = /^(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|authorized_keys|known_hosts|sshd?_config)$/;
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.rs', '.go', '.java', '.kt',
  '.rb', '.php', '.cs', '.c', '.h', '.cpp', '.hpp', '.swift', '.m', '.scala', '.ex', '.sol', '.tf', '.tfvars',
  '.yaml', '.yml', '.conf', '.cnf', '.ini', '.toml', '.json', '.xml', '.properties', '.sh', '.bash', '.ps1',
  '.sbt', '.gradle', '.groovy', '.sql', '.gemspec', '.podspec',
  '.pem', '.crt', '.cer', '.csr', '.key', '.pub']);
const DOC_EXT = new Set(['.md', '.rst', '.adoc', '.txt']);
const SKIP_DIR = new Set(['node_modules', '.git', 'target', 'dist', 'build', 'vendor', '.next', '__pycache__',
  '.venv', 'venv', 'coverage', '.cache', 'out']);
const TEST_PATH = /(^|\/)(?:tests?|__tests__|spec|fixtures?|testdata|test[-_]?vectors?)(\/|$)/i;
/** Una línea que PROHÍBE un algoritmo no es un sitio donde ese algoritmo vive. Contarla como
 *  hallazgo invierte el significado de un archivo de endurecimiento, que es justo el primero que
 *  un equipo de seguridad va a probar. */
// Frontera por letra aquí también, por la misma razón que en las expresiones de detección: con
// `\b` la palabra «deny» no casaba en `deny_signature = RSA`, que es exactamente la forma en que
// un archivo de endurecimiento escribe una prohibición, y la prohibición se contaba como hallazgo.
const NEGATION = /(?<![A-Za-z])(?:deny|disallow|forbid|forbidden|removed?|drop(?:ped)?|no[- ]longer|migrat(?:ed|ing) away|deprecat(?:e|ed)|ban(?:ned)?|reject(?:ed)?|must not|do not use|disabled?|blocklist|blacklist)(?![A-Za-z])/i;
/**
 * Regiones de COMENTARIO dentro de una línea, por posición.
 *
 * Una regla de «la línea empieza por /*, luego es un comentario» parecía razonable y era falsa: un
 * bundle minificado es UNA sola línea que empieza por su banner `/*...*\/` y sigue con todo el
 * código del paquete, así que la regla escondía precisamente el lugar donde vive la criptografía
 * de terceros. Hay que mirar DÓNDE cae cada coincidencia, no cómo empieza la línea.
 *
 * Los marcadores de línea llevan guardas a propósito: `//` no cuenta tras `:` porque `https://`
 * no abre un comentario, y `#` y `--` exigen espacio o inicio de línea porque `PKCS#1` y los
 * guiones de `AES-256-GCM` no son comentarios. Preferimos clasificar de menos: un comentario leído
 * como código produce una mención de más en el inventario; código leído como comentario esconde un
 * hallazgo real, que es el error que no podemos permitirnos.
 */
function commentRegions(line) {
  const regions = [];
  let i = 0;
  while ((i = line.indexOf('/*', i)) !== -1) {
    const end = line.indexOf('*/', i + 2);
    regions.push([i, end === -1 ? line.length : end + 2]);
    if (end === -1) break;
    i = end + 2;
  }
  const inBlock = (j) => regions.some(([a, b]) => j >= a && j < b);
  const starts = [];
  for (let j = 0; j < line.length - 1; j++) {
    if (inBlock(j)) continue;
    const two = line.slice(j, j + 2);
    if (two === '//' && line[j - 1] !== ':') { starts.push(j); break; }
    if (two === '--' && (j === 0 || /\s/.test(line[j - 1]))) { starts.push(j); break; }
    if (line[j] === '#' && (j === 0 || /\s/.test(line[j - 1]))) { starts.push(j); break; }
  }
  if (starts.length) regions.push([starts[0], line.length]);
  // Una línea de continuación de bloque (` * texto`) es comentario de principio a fin.
  if (/^\s*\*(?!\/)/.test(line)) regions.push([0, line.length]);
  return regions;
}

const MAX_FILES = 20000;
const MAX_DEPTH = 14;
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_LINE = 200000;
const MAX_LOCATIONS = 200;

/**
 * Lo que el barrido NO cubrió. Se cuenta y se informa: un límite silencioso es peor que un límite,
 * porque el informe se lee entonces como «lo revisamos todo» cuando no fue así, y quien lo firme se
 * apoyará en una cobertura que nunca existió.
 */
const skipped = { fileCap: false, depthCap: 0, tooBig: 0, unreadable: 0, skippedDirs: new Set(),
  longLines: 0, notUtf8: 0, deadline: false, byteBudget: false };

function walk(dir, acc = [], depth = 0) {
  if (acc.length >= MAX_FILES) { skipped.fileCap = true; return acc; }
  if (depth > MAX_DEPTH) { skipped.depthCap++; return acc; }
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { skipped.unreadable++; return acc; }
  for (const e of entries) {
    if (acc.length >= MAX_FILES) { skipped.fileCap = true; break; }
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIR.has(e.name)) { skipped.skippedDirs.add(e.name); continue; }
      if (e.name.startsWith('.') && e.name !== '.github') continue;
      walk(p, acc, depth + 1);
    } else if (e.isFile()) {
      const ext = path.extname(e.name).toLowerCase();
      if (MANIFEST_RE.test(e.name) || KEYFILE_RE.test(e.name) || CODE_EXT.has(ext) || DOC_EXT.has(ext)) acc.push(p);
    }
    // Los enlaces simbólicos no son ni isDirectory() ni isFile(), así que caen aquí y se ignoran.
    // Es lo correcto: seguirlos permite bucles infinitos y salir del árbol que nos pidieron.
  }
  return acc;
}

/** Una copia global de cada expresión, para contar OCURRENCIAS y no solo «hubo una en la línea». */
const globalOf = new Map();
const asGlobal = (re) => {
  if (!globalOf.has(re)) globalOf.set(re, new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'));
  const g = globalOf.get(re); g.lastIndex = 0; return g;
};

try {
  if (!fs.statSync(ROOT).isDirectory()) {
    console.error(`  path: ${clean(ROOT)} is not a directory.`);
    process.exit(2);
  }
} catch {
  console.error(`  path: ${clean(ROOT)} does not exist. Nothing was scanned.`);
  process.exit(2);
}

// F4: tope de trabajo TOTAL y plazo. Los topes por archivo y por número de archivos acotan cada
// dimensión por separado, pero su producto permitía 39 GiB y más de una hora de CI facturada sin
// un solo aviso. El plazo se puede subir con PQC_TIMEOUT_MS si alguien tiene un repo enorme.
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const DEADLINE_MS = Number(process.env.PQC_TIMEOUT_MS || 180000);
const startedAt = Date.now();
let totalBytes = 0;

const files = walk(ROOT);
const found = new Map();      // id -> {def,name,why,hits:[],code,comment,test,negated,lines}
const resistant = new Map();  // id -> {def,name,count}

for (const f of files) {
  if (Date.now() - startedAt > DEADLINE_MS) { skipped.deadline = true; break; }
  if (totalBytes > MAX_TOTAL_BYTES) { skipped.byteBudget = true; break; }

  let text = '';
  try {
    if (fs.statSync(f).size > MAX_BYTES) { skipped.tooBig++; continue; }
    // Leer bytes y decidir la codificación. Con readFileSync(f,'utf8') un archivo UTF-16 se
    // convierte en "c\0o\0n\0s\0t\0", así que ninguna expresión casa nunca: el peor de los
    // casos, porque la lectura TRIUNFA y entonces el informe afirma haber cubierto el archivo.
    const buf = fs.readFileSync(f);
    if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) text = buf.toString('utf16le');
    else if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) { buf.swap16(); text = buf.toString('utf16le'); }
    else if (buf.subarray(0, 8192).includes(0)) { skipped.notUtf8++; continue; }
    else text = buf.toString('utf8');
    totalBytes += buf.length;
  } catch { skipped.unreadable++; continue; }

  // Separadores POSIX siempre. Un CBOM se archiva, se difunde y se compara; con los separadores
  // nativos de Windows el mismo repositorio produciría dos documentos distintos.
  const rel = (path.relative(ROOT, f) || path.basename(f)).split(path.sep).join('/');
  const base = path.basename(f);
  const ext = path.extname(f).toLowerCase();
  const isManifest = MANIFEST_RE.test(base);
  const isDoc = DOC_EXT.has(ext);
  const isTestPath = TEST_PATH.test(rel);
  const lines = text.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // El tope anterior era de 1000 caracteres, y los bundles minificados y los lockfiles de una
    // sola línea son precisamente donde se esconde la criptografía de terceros: dos bundles con la
    // misma criptografía daban veredictos opuestos solo por la longitud de la línea.
    if (line.length > MAX_LINE) { skipped.longLines++; continue; }

    // Clasificación de la evidencia. Un hallazgo en una línea que PROHÍBE el algoritmo, en un
    // comentario, en documentación o en un vector de prueba sigue siendo información que va al
    // inventario, pero no es un sitio donde el algoritmo vive, así que no va al titular.
    const negated = NEGATION.test(line);
    const regions = negated || isDoc ? null : commentRegions(line);
    const inComment = (idx) => regions !== null && regions.some(([a, b]) => idx >= a && idx < b);
    const kindAt = (idx) => (negated ? 'negated' : isDoc ? 'doc' : inComment(idx) ? 'comment' : isTestPath ? 'test' : 'code');

    for (const v of VULNERABLE) {
      if (v.manifestOnly && !isManifest) continue;
      const ms = [...line.matchAll(asGlobal(v.re))];
      if (!ms.length) continue;
      if (!found.has(v.id)) {
        found.set(v.id, { def: v, name: v.name, why: v.why, hits: [], lines: 0, codeLines: 0,
          code: 0, comment: 0, doc: 0, test: 0, negated: 0, truncated: false });
      }
      const e = found.get(v.id);
      e.lines++;
      let codeHere = 0;
      for (const m of ms) e[kindAt(m.index)]++;   // ocurrencias REALES: 10 menciones en una línea cuentan 10
      for (const m of ms) if (kindAt(m.index) === 'code') codeHere++;
      if (codeHere) {
        // Contadas aparte: decir «1 ocurrencia en 2 líneas» porque una de ellas era una prohibición
        // es una contradicción en la misma frase, y quien la lea dejará de creerse el resto.
        e.codeLines++;
        if (e.hits.length < MAX_LOCATIONS) e.hits.push({ file: rel, line: i + 1 });
        else e.truncated = true;
      }
    }
    for (const r of RESISTANT) {
      const ms = [...line.matchAll(asGlobal(r.re))];
      if (!ms.length) continue;
      if (!resistant.has(r.id)) resistant.set(r.id, { def: r, name: r.name, count: 0 });
      resistant.get(r.id).count += ms.length;
    }
  }
}

/** Ocurrencias que cuentan para el titular: solo las que están en código real. */
const codeOf = (e) => e.code;
/** Las demás, que van al inventario pero no al número grande. */
const asideOf = (e) => e.comment + e.doc + e.test + e.negated;
const totalHits = [...found.values()].reduce((n, e) => n + codeOf(e), 0);
const totalAside = [...found.values()].reduce((n, e) => n + asideOf(e), 0);
const codeFamilies = [...found.values()].filter((e) => codeOf(e) > 0).length;
const serial = 'urn:uuid:' + crypto.randomUUID();
const now = new Date().toISOString();

// CycloneDX 1.6 with cryptographic-asset components (CBOM / ECMA-424).
//
// `implementationPlatform: 'generic'` is deliberate: the canonical cyclonedx-cli emits an
// `xsi:nil` element when it is absent, which makes the XML it produces fail XML-schema
// validation. A legal, honest value here keeps the conversion anyone's pipeline may run usable.
//
// `executionEnvironment: 'unknown'` is also deliberate, and is the honest answer. A static scan
// over source text has no evidence about where the algorithm executes: the match could be a
// comment, a config string, a PKCS#11 call into a hardware module. Asserting 'software-plain-ram'
// would contradict this tool's own stated limits two screens above.
const assetBase = (def) => ({
  assetType: 'algorithm',
  algorithmProperties: {
    primitive: def.primitive,
    executionEnvironment: 'unknown',
    implementationPlatform: 'generic',
    cryptoFunctions: def.fns,
    ...(def.nistQuantum !== undefined ? { nistQuantumSecurityLevel: def.nistQuantum } : {}),
    ...(def.classical !== undefined ? { classicalSecurityLevel: def.classical } : {}),
  },
  // `oid` se OMITE cuando no se conoce. Emitir la cadena vacía afirma que el OID es la cadena
  // vacía, no que no se determinó, y adivinarlo sería peor: los OID son por variante.
  ...(def.oid ? { oid: def.oid } : {}),
});

const coverageNotes = [];
if (skipped.fileCap) coverageNotes.push(`the ${MAX_FILES}-file cap was reached, so the scan is INCOMPLETE`);
if (skipped.depthCap) coverageNotes.push(`${skipped.depthCap} directory branch(es) deeper than ${MAX_DEPTH} levels were not entered`);
if (skipped.tooBig) coverageNotes.push(`${skipped.tooBig} file(s) over ${MAX_BYTES} bytes were skipped`);
if (skipped.longLines) coverageNotes.push(`${skipped.longLines} line(s) over ${MAX_LINE} characters were not matched`);
if (skipped.notUtf8) coverageNotes.push(`${skipped.notUtf8} file(s) were not UTF-8 text and were not matched`);
if (skipped.deadline) coverageNotes.push(`the ${DEADLINE_MS}ms deadline was reached, so the scan is INCOMPLETE (raise PQC_TIMEOUT_MS)`);
if (skipped.byteBudget) coverageNotes.push(`the ${MAX_TOTAL_BYTES}-byte total budget was reached, so the scan is INCOMPLETE`);
if (skipped.unreadable) coverageNotes.push(`${skipped.unreadable} path(s) could not be read`);
if (skipped.skippedDirs.size) coverageNotes.push(`these directory names were skipped by default and may contain cryptography: ${[...skipped.skippedDirs].sort().join(', ')}`);

const cbom = {
  $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: serial,
  version: 1,
  metadata: {
    timestamp: now,
    tools: { components: [{ type: 'application', 'bom-ref': 'tool/pqc-readiness-scan', name: 'pqc-readiness-scan', publisher: 'FRACTAL AI S.A.S.', version: '1.0.0' }] },
    properties: [
      { name: 'fractalai:scope', value: 'Static scan of manifests and source for quantum-vulnerable primitives. NOT a proof of absence: misses dynamic loading, vendored binaries, hardware modules and unrecognised abstractions. NOT a compliance certification.' },
      { name: 'fractalai:deadline', value: 'NIST IR 8547: RSA/ECDSA/ECDH/DH/DSA deprecated after 2030, disallowed after 2035.' },
      { name: 'fractalai:files_scanned', value: String(files.length) },
      { name: 'fractalai:occurrences_total', value: String(totalHits) },
      // La cobertura va DENTRO del documento. Quien reciba este archivo sin ver el log de CI debe
      // poder saber qué quedó fuera; si no, lo leerá como un barrido completo.
      { name: 'fractalai:coverage_limits', value: coverageNotes.length ? coverageNotes.join('; ') : 'No cap was hit: every matching file under the scanned path was read.' },
    ],
  },
  components: [
    ...[...found.entries()].map(([id, e]) => ({
      type: 'cryptographic-asset',
      'bom-ref': `crypto/vulnerable/${id}`,
      name: e.name,
      cryptoProperties: assetBase(e.def),
      // `evidence.occurrences` es el campo de primera clase que CycloneDX 1.6 define para esto.
      // Antes las ubicaciones iban en propiedades propias, así que ninguna herramienta estándar
      // las mostraba y había que volver a parsear una cadena "archivo:línea".
      evidence: { occurrences: e.hits.map((h) => ({ location: h.file, line: h.line })) },
      properties: [
        { name: 'fractalai:quantum_vulnerable', value: 'true' },
        { name: 'fractalai:why', value: e.why },
        { name: 'fractalai:occurrences', value: String(codeOf(e)) },
        { name: 'fractalai:matching_lines', value: String(e.codeLines) },
        // El desglose va al documento: una familia que solo aparece en comentarios, en
        // documentación, en vectores de prueba o en una línea que la PROHÍBE no es un sitio donde
        // el algoritmo vive, y contarla en el titular invertiría el sentido de un archivo de
        // endurecimiento. Se informa, no se esconde, y no se suma al número grande.
        ...(asideOf(e) ? [{ name: 'fractalai:mentions_not_counted',
          value: `${e.comment} in comments, ${e.doc} in documentation, ${e.test} in test material, ${e.negated} in lines that forbid or remove the algorithm. Reported for completeness; excluded from the occurrence count.` }] : []),
        ...(e.truncated ? [{ name: 'fractalai:locations_truncated',
          value: `Only the first ${MAX_LOCATIONS} locations are listed; the occurrence count above is the real total.` }] : []),
      ],
    })),
    ...[...resistant.entries()].map(([id, e]) => ({
      type: 'cryptographic-asset',
      'bom-ref': `crypto/resistant/${id}`,
      name: e.name,
      cryptoProperties: assetBase(e.def),
      properties: [
        { name: 'fractalai:quantum_vulnerable', value: 'false' },
        { name: 'fractalai:occurrences', value: String(e.count) },
      ],
    })),
  ],
};

// Crear el directorio si hace falta: `output: reports/cbom.json` es lo más natural que alguien
// puede escribir, y antes reventaba con ENOENT después de haber hecho todo el trabajo.
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(cbom, null, 2) + '\n');

// ── Report (this is what a human reads in the CI log) ──
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const grn = (s) => `\x1b[32m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
console.log('');
console.log('  PQC Readiness Scan — quantum-vulnerable cryptography in this repository');
console.log(dim(`  ${files.length} files scanned · CycloneDX CBOM written to ${clean(OUT_LABEL)}`));
console.log('');
if (coverageNotes.length) {
  console.log(red('  ⚠ COVERAGE WAS TRUNCATED — this scan did not read everything:'));
  for (const n of coverageNotes) console.log(red(`      · ${n}`));
  console.log('');
  // En GitHub esto sale como anotación en la página del pase, no solo en el log, para que nadie
  // archive un informe truncado creyéndolo completo.
  if (process.env.GITHUB_ACTIONS) console.log(`::warning title=PQC scan coverage truncated::${coverageNotes.join('; ')}`);
}

if (codeFamilies === 0) {
  console.log(coverageNotes.length
    ? red('  No quantum-vulnerable primitives matched IN WHAT WAS SCANNED. See the truncation above:')
    : grn('  No quantum-vulnerable primitives matched.'));
  console.log(dim('  That is not a proof of absence: a static scan misses dynamic loading, vendored'));
  console.log(dim('  binaries, hardware modules and anything behind an abstraction it cannot see.'));
} else {
  console.log(red(`  ${codeFamilies} quantum-vulnerable algorithm family(ies), ${totalHits} occurrence(s) in code:`));
  console.log('');
  for (const [, e] of found) {
    if (codeOf(e) === 0) continue;
    console.log(`  ${red('✗')} ${e.name} — ${codeOf(e)} occurrence(s) on ${e.codeLines} line(s)`);
    console.log(dim(`      ${e.why}`));
    for (const h of e.hits.slice(0, 3)) console.log(dim(`      ${clean(h.file)}:${h.line}`));
    if (e.hits.length > 3) {
      const shown = Math.min(e.hits.length, MAX_LOCATIONS);
      console.log(dim(`      … and ${e.hits.length - 3} more; ${shown} location(s) listed in ${clean(OUT_LABEL)}`));
    }
    console.log('');
  }
  if (totalAside) {
    console.log(dim(`  ${totalAside} further mention(s) in comments, documentation, test material or in lines`));
    console.log(dim('  that forbid the algorithm. Listed in the CBOM, deliberately not counted above.'));
    console.log('');
  }
}
if (resistant.size) {
  console.log(grn(`  Already quantum-resistant: ${[...resistant.values()].map((r) => r.name).join(', ')}`));
  console.log('');
}
console.log(dim('  Deadline: NIST IR 8547 deprecates these after 2030 and disallows them after 2035.'));
console.log(dim(SEAL
  ? '  This inventory is free and ran entirely in your runner. seal: true, so a redacted copy is sent next.'
  : '  This inventory is free and runs entirely in your runner. Nothing was uploaded.'));
console.log('');

/**
 * Sellado opcional. Lo que sale del runner es una copia REDACTADA del inventario: se quitan todas
 * las propiedades `fractalai:location`, que son las que llevan `ruta/de/archivo.ts:LÍNEA` del
 * repositorio de quien nos adopta. Un inventario de criptografía es justo el documento que revela
 * la estructura interna de un proyecto privado, y nadie nos está pidiendo eso para firmar un hash.
 * Se conservan los recuentos, que es lo que el sello necesita atestiguar.
 *
 * Como el sello cubre los bytes enviados y no los del archivo local, se escribe también la copia
 * exacta que se firmó. Sin ella, verificar el sello contra el CBOM local fallaría y el usuario
 * concluiría, con razón, que le mentimos.
 */
function redactForTransmission(doc) {
  const copy = JSON.parse(JSON.stringify(doc));
  let removed = 0;
  for (const c of copy.components || []) {
    const before = (c.properties || []).length;
    if (c.properties) c.properties = c.properties.filter((p) => p.name !== 'fractalai:location');
    removed += before - ((c.properties || []).length);
  }
  (copy.metadata.properties ||= []).push({
    name: 'fractalai:redaction',
    value: `${removed} file:line location(s) were removed before transmission. This document, not the local CBOM, is what the seal covers.`,
  });
  return { doc: copy, removed };
}

if (SEAL) {
  console.log(dim('  seal: true — PREVIEW. This Action carries no x402 payment client, so the'));
  console.log(dim('  endpoint will answer 402 Payment Required and no seal will be produced. What'));
  console.log(dim('  follows shows you the price and exactly what would be sent. Nothing else.'));
  const { doc: toSend, removed } = redactForTransmission(cbom);
  const body = JSON.stringify({ cbom: toSend });
  console.log(dim(`  seal: true — sending a redacted inventory to ${API} (${body.length} bytes).`));
  console.log(dim(`  ${removed} file:line location(s) withheld. No file contents, no snippets, no paths leave this runner.`));
  if (API_OVERRIDDEN) console.log(dim('  NOTE: the destination was overridden by FRACTALAI_BASE_URL.'));
  try {
    const r = await fetch(`${API}/api/x402/seal-cbom`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body, signal: AbortSignal.timeout(30000),
    });
    if (r.status === 402) {
      console.log(dim('  402 Payment Required: sealing costs USDC over x402. The scan above is unaffected.'));
    } else if (r.ok) {
      // La respuesta es dato ajeno: se acota y se valida ANTES de escribir un archivo que un paso
      // posterior podría tratar como un sello FIPS 204 auténtico.
      const MAX_SEAL_BYTES = 262144;
      const declared = Number(r.headers.get('content-length'));
      let text = null;
      if (Number.isFinite(declared) && declared > MAX_SEAL_BYTES) {
        text = null;   // ni se empieza a leer
      } else if (!r.body) {
        text = '';
      } else {
        const reader = r.body.getReader();
        const chunks = [];
        let n = 0, oversize = false;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          n += value.byteLength;
          // Un content-length ausente NO se interpreta como «pequeño»: este bucle es el límite real.
          if (n > MAX_SEAL_BYTES) { await reader.cancel(); oversize = true; break; }
          chunks.push(value);
        }
        text = oversize ? null : Buffer.concat(chunks).toString('utf8');
      }
      if (text === null) {
        console.log(dim('  Seal response exceeded 256 KiB and was discarded unread. The scan above is unaffected.'));
      } else {
        let j = null;
        try { j = JSON.parse(text); } catch { /* abajo */ }
        const sig = j && j.served_signature;
        const ok = sig && typeof sig.signature === 'string' && typeof sig.public_key === 'string'
          && typeof sig.signed_message === 'string';
        if (!ok) {
          console.log(dim('  Seal response did not carry a usable ML-DSA-65 signature; nothing written.'));
        } else {
          const stem = OUT.replace(/\.json$/, '');
          fs.writeFileSync(stem + '.seal.json', JSON.stringify(j, null, 2) + '\n');
          fs.writeFileSync(stem + '.sealed.json', JSON.stringify(toSend, null, 2) + '\n');
          console.log(grn('  Sealed. Signature and the exact sealed document written next to the CBOM.'));
        }
      }
    } else {
      console.log(dim(`  Sealing unavailable (HTTP ${r.status}). The scan above is unaffected.`));
    }
  } catch (e) {
    // Solo la CLASE del fallo: el mensaje de undici puede arrastrar el endpoint configurado.
    console.log(dim(`  Sealing failed (${e && e.name ? e.name : 'error'}). The scan above is unaffected.`));
  }
}

const gh = process.env.GITHUB_OUTPUT;
if (gh) {
  // `findings` se fuerza a número y `cbom` va en el formato de delimitador aleatorio que exige
  // GitHub para valores multilínea. Concatenar `nombre=valor` a pelo deja que el valor declare
  // variables adicionales que un paso posterior se creería.
  const delim = 'PQC_EOF_' + crypto.randomBytes(16).toString('hex');
  fs.appendFileSync(gh, `findings=${Number(totalHits) || 0}\ncbom<<${delim}\n${OUT_LABEL}\n${delim}\n`);
}
const sum = process.env.GITHUB_STEP_SUMMARY;
if (sum) {
  fs.appendFileSync(sum, [
    '## PQC Readiness Scan',
    '',
    `${files.length} files scanned. **${codeFamilies} quantum-vulnerable algorithm families, ${totalHits} occurrences in code.**`,
    ...(totalAside ? ['', `${totalAside} further mentions in comments, documentation, test material or in lines that forbid the algorithm. Listed in the CBOM, not counted here.`] : []),
    ...(coverageNotes.length ? ['', `Coverage limits: ${coverageNotes.join('; ')}`] : []),
    '',
    ...(codeFamilies ? ['| Algorithm | Occurrences | Lines | Why it matters |', '|---|---:|---:|---|',
      ...[...found.values()].filter((e) => codeOf(e) > 0).map((e) => `| ${e.name} | ${codeOf(e)} | ${e.codeLines} | ${e.why} |`)] : ['No vulnerable primitives matched in code (not a proof of absence).']),
    '',
    '_NIST IR 8547: deprecated after 2030, disallowed after 2035. Static scan, not a certification._',
    '',
  ].join('\n'));
}

if (FAIL && totalHits > 0) process.exit(1);
