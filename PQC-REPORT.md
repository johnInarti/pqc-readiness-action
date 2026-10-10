# Post-quantum readiness inventory

Generated 2026-10-10T17:56:59.843Z by [PQC Readiness Scan](https://github.com/johnInarti/pqc-readiness-action) 1.2.0.

**13 files read. 104 occurrence(s) of quantum-vulnerable cryptography in code, across 8 algorithm family(ies).**

## What this is, and what it is not

This is a **static scan** of manifests and source text. It is evidence to start a migration from.

It is **not a proof of absence.** It cannot see cryptography reached through dynamic loading, compiled into vendored binaries, or performed inside a hardware security module. Zero findings in a family means nothing matched, not that nothing is there.

It is **not a compliance certification**, and no auditor should accept it as one.

### This particular scan did not read everything

- these directory names were skipped by default and may contain cryptography: .git

Any conclusion below is bounded by that list.

### Excluded on purpose, which is not the same as missed

- 3 of this scan's own output file(s) were excluded on purpose

An existing inventory document lists algorithm names by definition. Reading one back would inflate these counts with our own report rather than with your code.

## The deadline

NIST IR 8547 deprecates RSA, ECDSA, ECDH, finite-field Diffie-Hellman and DSA **after 2030** and disallows them **after 2035**. CNSA 2.0 brings that forward to **2027** for US national-security systems.

## First: what is already losing ground

These are key agreement and key transport. The exposure is **retroactive**: an adversary can record protected traffic today and decrypt it once a quantum computer exists, so migrating in 2029 does not repair traffic captured in 2026. These do not wait for the deadline.

| Algorithm | Occurrences | Lines | Replace with |
|---|---:|---:|---|
| RSA | 20 | 11 | ML-KEM (FIPS 203), hybrid during transition |
| ECDH | 10 | 6 | ML-KEM (FIPS 203), hybrid during transition |
| Diffie-Hellman (finite field) | 9 | 4 | ML-KEM (FIPS 203), hybrid during transition |
| X25519 / X448 | 8 | 2 | ML-KEM (FIPS 203), hybrid during transition |

### RSA

Signature and key transport. Deprecated after 2030, disallowed after 2035 (NIST IR 8547). Replace signatures with ML-DSA (FIPS 204), key transport with ML-KEM (FIPS 203).

**Why it cannot wait.** If any of these sites is key transport, traffic captured today is decryptable later. A static scan cannot tell transport from signing, so this is treated as retroactive exposure.

Locations:

- `.github/workflows/test.yml:61`
- `.github/workflows/test.yml:262`
- `scan.mjs:174`
- `scan.mjs:177`
- `scan.mjs:212`
- `scan.mjs:231`
- `scan.mjs:232`
- `scan.mjs:240`
- `scan.mjs:241`
- `scan.mjs:274`
- `scan.mjs:763`
- … 9 more occurrence(s) not listed individually

### ECDH

Key agreement. Harvest-now-decrypt-later applies: traffic captured today can be decrypted once a quantum computer exists. Replace with ML-KEM (FIPS 203), hybrid during transition.

**Why it cannot wait.** Harvest now, decrypt later. Traffic an adversary records today is decryptable once a quantum computer exists, so migrating in 2029 does not repair 2026 traffic.

Locations:

- `.github/workflows/test.yml:119`
- `scan.mjs:188`
- `scan.mjs:194`
- `scan.mjs:198`
- `scan.mjs:201`
- `scan.mjs:763`
- … 4 more occurrence(s) not listed individually

### Diffie-Hellman (finite field)

Finite-field key agreement. Deprecated after 2030. Replace with ML-KEM (FIPS 203).

**Why it cannot wait.** Harvest now, decrypt later. Recorded traffic is decryptable after the fact.

Locations:

- `scan.mjs:209`
- `scan.mjs:212`
- `scan.mjs:241`
- `scan.mjs:763`
- … 5 more occurrence(s) not listed individually

### X25519 / X448

Montgomery-curve key agreement, including the NaCl/libsodium box APIs. Same harvest-now-decrypt-later exposure as ECDH. Replace with ML-KEM (FIPS 203).

**Why it cannot wait.** Harvest now, decrypt later. Same retroactive exposure as ECDH: recorded traffic cannot be un-recorded.

Locations:

- `scan.mjs:197`
- `scan.mjs:200`
- … 6 more occurrence(s) not listed individually

## Second: what the deadline governs

These are signatures. A signature made today cannot be forged retroactively, so the risk arrives at the deadline — and earlier for anything whose validity must outlive it: firmware, trust roots, code signing, long-dated certificates.

| Algorithm | Occurrences | Lines | Replace with |
|---|---:|---:|---|
| ECDSA | 23 | 10 | ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) where a hash-based signature fits |
| Ed25519 / Ed448 (EdDSA) | 15 | 6 | ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) where a hash-based signature fits |
| DSA | 14 | 10 | ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) where a hash-based signature fits |

### ECDSA

Elliptic-curve signature. Deprecated after 2030, disallowed after 2035. Replace with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).

Locations:

- `.github/workflows/test.yml:119`
- `scan.mjs:180`
- `scan.mjs:183`
- `scan.mjs:207`
- `scan.mjs:231`
- `scan.mjs:232`
- `scan.mjs:240`
- `scan.mjs:241`
- `scan.mjs:274`
- `scan.mjs:763`
- … 13 more occurrence(s) not listed individually

### Ed25519 / Ed448 (EdDSA)

Edwards-curve signature. Same quantum exposure as ECDSA. Replace with ML-DSA (FIPS 204).

Locations:

- `scan.mjs:203`
- `scan.mjs:206`
- `scan.mjs:231`
- `scan.mjs:240`
- `scan.mjs:241`
- `scan.mjs:274`
- … 9 more occurrence(s) not listed individually

### DSA

Legacy signature, already discouraged pre-quantum. Replace with ML-DSA (FIPS 204).

Locations:

- `scan.mjs:183`
- `scan.mjs:218`
- `scan.mjs:219`
- `scan.mjs:221`
- `scan.mjs:231`
- `scan.mjs:232`
- `scan.mjs:254`
- `scan.mjs:258`
- `scan.mjs:274`
- `scan.mjs:763`
- … 4 more occurrence(s) not listed individually

## Third: inventory and decisions, not code changes

These are declared dependencies and key material found in the repository. The primitive travels with the build, but this scan does not prove your own code reaches it, so each one needs a human decision rather than an edit.

| Item | Occurrences |
|---|---:|
| X.509 / SSH key material (algorithm from label) | 5 |

## Already quantum-resistant here

- **ML-DSA (FIPS 204)** — 51 occurrence(s)
- **ML-KEM (FIPS 203)** — 23 occurrence(s)
- **SLH-DSA (FIPS 205)** — 16 occurrence(s)
- **AES** — 2 occurrence(s)
- **SHA-3** — 2 occurrence(s)
- **SHA-2** — 35 occurrence(s)

Reported so the inventory is not one-sided: a migration plan that ignores what is already done wastes effort re-doing it.

## Mentions deliberately not counted

256 further mention(s) appear in comments, documentation, test vectors, or in lines that FORBID an algorithm. They are recorded in the CBOM and excluded from the counts above: a hardening policy that says `deny_signature = RSA` is not a place where RSA lives, and counting it would invert the meaning of the file.

## Against the baseline

No change in any algorithm family since the baseline was frozen.

## How to read the numbers

An occurrence is one match on one line. A line matching two families counts once for each, because both are present. The occurrence count is the real total; only the **locations** are capped, and whenever that happens the document says so explicitly.

