# PQC Readiness Scan

**Find the quantum-vulnerable cryptography in your repository and get a CycloneDX CBOM.**
One line in your workflow. Free. Runs entirely in your runner — nothing is uploaded.

```yaml
- uses: johnInarti/pqc-readiness-action@v1
```

That's it.

For a tool whose whole pitch is that nothing leaves your runner, pin the commit rather than the
tag — a tag can be moved, a SHA cannot. This action has no dependencies at all: three Node
built-ins and one file, so the SHA is the entire trust boundary.

```yaml
- uses: johnInarti/pqc-readiness-action@<full-40-char-sha>  # v1.0.0
``` The scan writes `cbom.json` and prints an inventory in your job summary.

---

## Why you need this before 2030

NIST IR 8547 sets the dates: **RSA, ECDSA, ECDH, finite-field Diffie-Hellman and DSA are
deprecated after 2030 and disallowed after 2035.** CNSA 2.0 pulls the deadline to 2027 for
US national-security systems.

Every migration plan starts with the same question — *where is that cryptography in our
stack?* — and almost nobody can answer it. This Action answers it in your CI, on every
push, for free.

## What it does

- Scans your manifests and source for known quantum-vulnerable primitives: RSA, ECDSA,
  ECDH/X25519, Ed25519/EdDSA, Diffie-Hellman, DSA.
- Also reports what is **already quantum-resistant** (ML-DSA, ML-KEM, SLH-DSA, AES-256,
  SHA-2/3), so the inventory is not one-sided.
- Emits a **CycloneDX 1.6 CBOM** (Cryptographic Bill of Materials, ECMA-424) with
  `cryptographic-asset` components — the format regulators and SBOM tooling already read.
- Writes a table to your GitHub job summary and exposes `findings` / `cbom` as outputs.

## What it is NOT

Stated plainly, because an inventory you can't trust is worse than none:

- **Not a proof of absence.** A static scan misses dynamic loading, vendored binaries,
  hardware security modules, and any cryptography behind an abstraction it does not
  recognise. Zero findings means "nothing matched", not "you are safe".
- **Not a compliance certification.** It is evidence to start a migration from, not a
  clean bill of health, and no auditor should treat it as one.
- **It skips some directories by default**, including `vendor`, `node_modules`, `dist`,
  `build`, `target` and `out`. A project whose cryptography lives in vendored code will get a
  clean-looking report. Every CBOM states which directory names were skipped, and the
  occurrence count is the true total even when only the first 25 locations are listed.
- **Not a secret collector.** It reads your files in your runner and uploads nothing.
  There is no account, no API key, and no telemetry. Read `scan.mjs` — it is one file.

## Usage

```yaml
name: PQC readiness
on: [push, pull_request]

jobs:
  pqc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: johnInarti/pqc-readiness-action@v1
        id: pqc
      - uses: actions/upload-artifact@v4
        with:
          name: cbom
          path: ${{ steps.pqc.outputs.cbom }}
```

### Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to scan. |
| `output` | `cbom.json` | Where to write the CycloneDX CBOM. |
| `fail-on-findings` | `false` | Exit non-zero if anything vulnerable is found. Leave this off until you have a migration plan, or you will block every PR on day one. |
| `seal` | `false` | Optional, paid. See below. |

### Outputs

| Output | What it is |
|---|---|
| `findings` | Total number of vulnerable occurrences. |
| `cbom` | Path to the CBOM file. |

### Gate a repository once you are ready

```yaml
      - uses: johnInarti/pqc-readiness-action@v1
        with:
          fail-on-findings: true
```

## Optional: a signed inventory — preview, not yet usable

The scan and the CBOM are free forever and that is the whole product today. The rest of this
section describes something you **cannot yet buy**, and we would rather say so here than let
you find a `402 Payment Required` in your own CI log.

The intent: if you need a **third party** to verify that a given inventory was produced at a
given time and was not edited afterwards, FractalAI signs it with **ML-DSA-65 (NIST FIPS 204,
security level 3)** and returns a re-verifiable certificate.

The honest state of it:

- The endpoint is live and prices the request in USDC over [x402](https://x402.org).
- **This Action carries no x402 payment client.** There is no key input and no payment step, so
  the endpoint always answers `402 Payment Required` and no seal is ever produced.
- Setting `seal: true` today therefore only prints the price and exactly what would be sent. It
  changes nothing about the scan, which already ran and already wrote your CBOM.

**What would leave your runner, precisely.** Not the CBOM you have on disk. Every
`fractalai:location` property is stripped first, so no `path/to/file.ts:LINE` from your
repository crosses the wire. What would be sent is the algorithm families, their occurrence
counts, and the file count. No file contents, no code snippets, no secret values, no repository
or organisation name, no identifier of you or your runner. The exact redacted document is
written next to the CBOM so you can read, diff and keep what was sent.

If your repository paths are confidential, that is already handled, and with the default
`seal: false` the process opens **zero** network connections of any kind.

**Verification would be free, open and offline.** A seal is a plain ML-DSA-65 signature, so any
FIPS 204 implementation verifies it. You would never pay us to check our own work, and never
run our code to do it:

```js
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';   // third-party, not ours

const { served_signature: s } = JSON.parse(fs.readFileSync('cbom.seal.json', 'utf8'));

const ok = ml_dsa65.verify(
  Buffer.from(s.signature, 'base64'),        // 3309 bytes
  Buffer.from(s.signed_message, 'utf8'),     // domain-separated claim digest
  Buffer.from(s.public_key, 'base64'),       // 1952 bytes
);
```

The public key travels with the seal, so verification needs no network at all. To confirm the
key is ours and not substituted, compare it against the one we serve free at
`https://fractalai.net.co/api/x402/receipt-key`.

**One honest limit beyond that:** the public-key directory that lets you resolve our signing key
is served over TLS and is **not yet anchored on-chain**. Verifying a seal therefore means
trusting that TLS endpoint for the key, and the cryptography for everything after. We say so
here rather than let you discover it in an audit.

## Security posture

You are being asked to run someone else's code in your CI, so here is exactly what it does
and what was done to make it safe:

- **Inputs never touch a shell.** Every input reaches the scanner through the environment.
  A composite action that writes `--path="${{ inputs.path }}"` inside a `run:` block lets
  the runner paste raw input text into the script before bash parses it, which hands
  command execution to anyone who can influence that input (a pull-request title, an issue
  body, a dispatch field). This action does not do that, and a CI test asserts it on every
  push by feeding it a hostile input and failing if anything executes.
- **The output path is confined to your workspace.** Traversal, absolute paths and
  symlinks are refused, so the action cannot overwrite a file outside the checkout.
- **Step outputs cannot be forged.** The count is written as a number and the path with a
  random heredoc delimiter, so no input value can inject extra step outputs that a later
  step would trust.
- **Repository content never reaches your log unescaped.** Control characters and ANSI
  escapes coming from scanned filenames are stripped, so a hostile repo cannot spoof your
  CI log.
- **No network calls at all unless you set `seal: true`.** No token is read, no permission
  is requested, nothing is uploaded.

Found something we missed? Open an issue. Security reports are welcome and credited.


## Who made this

[FractalAI S.A.S.](https://fractalai.net.co) (Colombia) runs a layer-1 blockchain whose
consensus signs every block with ML-DSA-65 — post-quantum signatures in production, not a
roadmap. We built this scanner for our own migration and are publishing it because the
inventory problem is everyone's.

Found a false positive or a primitive we miss? Open an issue. That is the fastest way to
make this better for everyone.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
Use it, fork it, vendor it, sell services on top of it.
