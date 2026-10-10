# PQC Readiness Scan

[![post-quantum](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/johnInarti/pqc-readiness-action/main/pqc-badge.json)](https://github.com/johnInarti/pqc-readiness-action/blob/main/PQC-REPORT.md)
[![test](https://github.com/johnInarti/pqc-readiness-action/actions/workflows/test.yml/badge.svg)](https://github.com/johnInarti/pqc-readiness-action/actions/workflows/test.yml)

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

- Puts the findings **in your repository's Security tab and inline on pull-request diffs**, by
  emitting SARIF and uploading it to GitHub code scanning. Free on public repositories.
- **Ratchets the inventory down.** Freeze today's counts as a baseline and the job fails only when
  a family goes *up*. Nobody can fix hundreds of occurrences in an afternoon, but every team can
  agree not to add more, so this is the gate you can switch on the first day.
- Writes a **report a person can read** and hand to an auditor, ordered by real urgency rather than
  by the biggest number.
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

## Not every finding is equally urgent

An inventory of 836 occurrences with no order is unusable, and inventing a severity score would be
worse. There is one real cryptographic distinction and it is the only one this tool uses:

**Harvest now, decrypt later.** Key agreement and key transport — ECDH, X25519, finite-field
Diffie-Hellman, and RSA where it carries keys — protect traffic an adversary can **record today**
and decrypt the day a quantum computer exists. Migrating in 2029 does not repair traffic captured
in 2026. These do not wait for the deadline.

**The deadline governs the rest.** A signature made today cannot be forged retroactively. ECDSA,
EdDSA and DSA matter when you must keep signing and verifying after 2030, and earlier for anything
whose validity must outlive it: firmware, trust roots, code signing, long-dated certificates.

RSA is ranked with the first group even though it also signs. A static scan cannot tell key
transport from signing, and where the two readings differ we take the one that implies retroactive
exposure. That is stated here rather than hidden inside a score.

## The ratchet: the gate you can actually switch on

`fail-on-findings` is honest and unusable on day one. A real repository has hundreds of
occurrences, nobody clears them in an afternoon, so the gate stays off forever and the tool becomes
decorative.

Freeze the current state instead, and fail only on regression:

```yaml
- uses: johnInarti/pqc-readiness-action@v1
  with:
    baseline: .github/pqc-baseline.json
    write-baseline: true     # once, then commit the file and remove this line
```

```yaml
- uses: johnInarti/pqc-readiness-action@v1
  with:
    baseline: .github/pqc-baseline.json
    fail-on-increase: true   # from now on
```

The comparison is **per algorithm family, not per total**, on purpose: removing twenty signature
sites and adding one key-agreement site lowers the total and raises your real exposure. A single
number hides exactly the change that matters.

Two deliberate refusals. Asking for `fail-on-increase` with no baseline **fails the job** instead
of passing green, because a gate that silently protects nothing is worse than no gate. And
`write-baseline` is never automatic: overwriting the file forgives every regression since it was
written, so that has to be somebody's decision.

## Findings where your team already looks

```yaml
jobs:
  pqc:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write      # to upload to code scanning
      pull-requests: write        # to comment on the PR
    steps:
      - uses: actions/checkout@v4
      - uses: johnInarti/pqc-readiness-action@v1
        with:
          baseline: .github/pqc-baseline.json
          fail-on-increase: true
          comment-on-pr: true
          report: PQC-REPORT.md
```

That puts the inventory in three places: the Security tab, a sticky comment on the pull request
that is rewritten rather than duplicated on every push, and a committed Markdown report.

**If you do not grant those permissions, nothing breaks.** The upload and the comment are skipped
with a message naming the exact permission that was missing, and the scan still succeeds. A tool
that fails someone else's build over a permission they did not know about deserves to be uninstalled.

## A badge that rewards moving, not a grade for where you started

```markdown
[![post-quantum](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/main/pqc-badge.json)](https://github.com/johnInarti/pqc-readiness-action)
```

```yaml
      - uses: johnInarti/pqc-readiness-action@v1
        with:
          baseline: .github/pqc-baseline.json
          badge: pqc-badge.json
```

Then commit `pqc-badge.json` the way you already commit any generated artefact.

**It renders from your repository, not from a server of ours.** The action writes a shields.io
endpoint file into your tree; shields.io reads it from your raw URL. Nothing about your code, your
counts or your repository reaches us, which keeps the one promise that makes this adoptable inside
a bank. A badge server of our own would have been easier to build and would have broken it.

**What it says, and what it refuses to say.** With a baseline it reads `3 families · holding`,
`3 families · −12 vs baseline`, or `4 families · +1 vs baseline`. Without one it reads
`3 families inventoried`, in neutral, passing no judgement.

It is never red, and it never calls your repository vulnerable or insecure. Not out of politeness:
a repository with eight hundred occurrences did not choose to start there, and a badge that shames
it on day one does not get added to a README — so it would communicate nothing to anyone. A
regression shows amber, because going up is a signal for your team, not a public infraction. What
the badge grades is the only thing a team actually controls, which is the direction.

If the scan could not read everything, the badge says `partial scan` as well. A green badge over a
truncated scan would be the most dishonest thing this tool could produce.

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
| `sarif` | `pqc.sarif` | Where to write the SARIF report. Empty string to skip. |
| `upload-sarif` | `true` | Upload to GitHub code scanning. Needs `security-events: write`; skipped with an explanation if absent. |
| `baseline` | — | Baseline file with the frozen count per family. Commit it. |
| `write-baseline` | `false` | Write or overwrite the baseline from this run. Do it deliberately. |
| `fail-on-increase` | `false` | Fail only when a family goes up against the baseline. Requires `baseline`. |
| `report` | — | Where to write the human-readable Markdown report. |
| `badge` | — | Where to write the shields.io endpoint JSON for a README badge. |
| `comment-on-pr` | `false` | Keep one comment updated on the pull request. Needs `pull-requests: write`. |
| `fail-on-findings` | `false` | Fail if anything vulnerable is found at all. Honest but unusable on day one; prefer `fail-on-increase`. |
| `seal` | `false` | Preview, not yet usable. See below. |
| `token` | job token | Used only for the SARIF upload and the pull-request comment. |

### Outputs

| Output | What it is |
|---|---|
| `findings` | Total vulnerable occurrences found in code. |
| `cbom` | Path to the CBOM file. |
| `sarif` | Path to the SARIF file, empty if none was requested. |
| `increased` | Families that went up against the baseline. `0` with no baseline. |
| `decreased` | Families that went down. |
| `truncated` | `true` when the scan could not read everything, so a clean result must not be read as clean. |

### It never counts itself

A CBOM contains, by definition, the names of the algorithms it inventories. Reading one back would
inflate every number with findings that are our own report — and that is not only a same-run
artefact: anyone who commits their CBOM, which is exactly what we recommend, would poison every
later scan. This action's own outputs are excluded by path, and any CycloneDX, SARIF or baseline
document is excluded **by content**, under any filename. The exclusion is reported, not silent.

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
