# Changelog

Pin a full commit SHA rather than a moving tag. This action has no dependencies at all — three Node
built-ins and two files — so the SHA is the entire trust boundary.

---

## v1.2.0

One mechanism, and it is a different kind of thing from everything else in this action.

### A badge, because asking to be listed cannot bootstrap itself

Every other output of this action lives inside the adopter's pipeline: the CBOM, the SARIF, the
report, the pull-request comment. All useful to them, all invisible to everyone else. That left
propagation with exactly one mechanism — go to curated lists, registries and marketplaces and ask a
human to admit us — and that mechanism cannot start itself. Not as a theory: on the day v1.0.0 was
published, two curated lists declined it in almost the same words, saying there was not yet
"sufficient evidence of independent adoption" and that they would reconsider if it appeared. You
need adopters to get listings and listings to get adopters.

A badge inverts who propagates. It stops being something we ask for and becomes something the
adopter wants to display, and their README becomes the listing. It is the dynamic that spread test
coverage badges.

```yaml
      - uses: johnInarti/pqc-readiness-action@v1
        with:
          baseline: .github/pqc-baseline.json
          badge: pqc-badge.json
```

**It renders from the adopter's repository, not from a server of ours.** The action writes a
shields.io endpoint file into their tree and shields.io reads it from their raw URL. Nothing about
their code, their counts or their repository reaches us. A badge server of our own would have been
easier to build and would have broken the one promise that makes this adoptable inside a bank.

**The decision that determines whether it works at all:** the message and the colour reward
movement rather than grading the starting position. With a baseline it reads `3 families · holding`,
`3 families · −12 vs baseline`, or `4 families · +1 vs baseline`. Without one it reads
`3 families inventoried`, in neutral. It is never red and never calls a repository vulnerable or
insecure — not out of politeness: a repository with eight hundred occurrences did not choose to
start there, and a badge that shames it on day one never gets added to a README, so it would
communicate nothing to anyone. A regression shows amber, because going up is a signal for the team,
not a public infraction. Four regression tests hold this, including one that fails if the badge ever
renders red or accusatory on a first scan.

If the scan could not read everything the badge also says `partial scan`. A green badge over a
truncated scan would be the most dishonest thing this tool could produce.

### Fixed: a truncation alarm that was going off on every normal run

Deliberate exclusions — this action's own outputs, and any existing CycloneDX, SARIF or baseline
document — were being counted as lost coverage, so a perfectly complete scan of a repository that
commits its CBOM, which this README recommends, reported "COVERAGE WAS TRUNCATED" and the badge
said `partial scan`. An alarm that sounds every time stops being an alarm: by the third run nobody
reads it, which is exactly the run where it matters.

The two are now separate. Lost coverage of your code shouts, annotates the run and marks the badge.
A deliberate exclusion is precision, not a gap: it is printed quietly, recorded in the CBOM so the
document can still be audited, and reported in the written report under a heading that says so. It
is not an alarm, and it is not a secret either.

### Tests

61 regression checks, up from 55.

---

## v1.1.0

Three things this release adds, and one real detection bug it fixes.

### Findings where your team already looks

The action now emits **SARIF 2.1.0** and uploads it to GitHub code scanning, so the inventory stops
being a JSON file nobody opens and appears in the repository's Security tab and annotated inline on
pull-request diffs. Free on public repositories. Validated against the published SARIF 2.1.0 schema
in CI, because GitHub rejects an invalid SARIF whole and does not say why.

Deliberately, **no finding is emitted at `error` level**. An `error` blocks reviews in many
configurations, and this is an inventory, not a vulnerability exploitable today. Marking 800 lines
of a large repository as errors on day one achieves exactly one thing: the tool gets switched off.
What is distinguished instead is real urgency, carried in `security-severity`.

Also optional: a **sticky pull-request comment** with what the change does to the inventory,
rewritten rather than duplicated on every push, and a **Markdown report** a person can read and
hand to an auditor.

The upload and the comment need `security-events: write` and `pull-requests: write`. **Without
them nothing breaks:** each is skipped with a message naming the exact missing permission, and the
scan still succeeds. That is implemented through the GitHub API rather than by calling another
action, for a specific reason: composite-action steps do not support `continue-on-error`, so
invoking an action that hard-fails on a missing permission would break the build of an adopter who
did not know the permission existed.

### The ratchet: a gate that can actually be switched on

`fail-on-findings` is honest and unusable on day one. A real repository has hundreds of
occurrences, nobody clears them in an afternoon, so the gate stays off forever.

`baseline` + `fail-on-increase` freeze today's counts and fail only on regression. Nothing asks
anyone to fix the existing inventory; it asks this change not to add to it — the same shape that
made coverage gates adoptable.

The comparison is **per algorithm family, not per total**. Removing twenty signature sites while
adding one key-agreement site lowers the total and raises real exposure; a single number hides
exactly the change that matters. Two refusals are deliberate: asking for `fail-on-increase` with no
baseline **fails** instead of passing green, because a gate that silently protects nothing is worse
than no gate; and `write-baseline` is never automatic, since overwriting forgives every regression
since the file was written.

### Urgency, as a cryptographic fact rather than a score

An inventory of hundreds of occurrences with no order is unusable, and an invented severity scale
would be worse. One real distinction is used:

- **Harvest now, decrypt later** — key agreement and key transport (ECDH, X25519, finite-field
  Diffie-Hellman, and RSA where it carries keys). Traffic an adversary records today is decryptable
  once a quantum computer exists, so migrating in 2029 does not repair 2026 traffic. These do not
  wait for the deadline, and the written report leads with them even when another family has a far
  bigger count.
- **The deadline governs the rest** — signatures cannot be forged retroactively; the risk arrives
  at 2030/2035, and earlier for artefacts whose validity must outlive it.
- **Inventory** — declared dependencies and committed key material need a human decision, not an
  edit.

RSA is ranked with the first group although it also signs: a static scan cannot tell key transport
from signing, and where the readings differ we take the one implying retroactive exposure. The
urgency is written into the CBOM so nothing downstream has to infer it — inferring it from the
CycloneDX `primitive` got RSA wrong, and two places computing the same thing eventually disagree.

### Fixed: `crypto.createECDH` was never detected

The letter-only token boundary introduced in v1.0.0 fixed a 61% detection miss rate, and blocked
CamelCase function names as a side effect: in `crypto.createECDH(...)` the `ECDH` is preceded by the
`e` of `create`. That is the most common Node API for key agreement — the `harvest` case, the one
that cannot wait — and it was invisible. `createDiffieHellman`, `getDiffieHellman` and
`computeSecret` were missed the same way. The boundary is correct and unchanged; the real function
names are now listed explicitly. Found by the test suite itself while exercising the ratchet.

### Fixed: the scan was counting its own output

A CBOM contains, by definition, the names of the algorithms it inventories, so reading one back
inflated every number with findings that were our own report: a fixture with 3 real lines reported
15 occurrences, 12 of them read from the `cbom.json` written seconds earlier. Worse, it was not
only a same-run artefact — anyone who commits their CBOM, which this README recommends, would have
poisoned every later scan. Own outputs are now excluded by path, and any CycloneDX, SARIF or
baseline document is excluded **by content** under any filename. The exclusion is reported in the
coverage limits, not silent.

### Also

- The baseline file itself is excluded by content: it carries the family ids (`rsa`, `ecdsa`) and
  poisoned scans when renamed or copied.
- All derived outputs are now written at a single point, after everything is computed. Writing each
  one next to the code that produced it put two writes *above* the declaration they depended on,
  which threw a `ReferenceError` the moment anyone requested that output, with the scan already
  done. Twice. The lesson is about ordering, not syntax.
- New step outputs: `sarif`, `increased`, `decreased`, `truncated`.

### Tests

52 regression checks on ubuntu, windows and macos, up from 33. New coverage: SARIF schema validity,
stable fingerprints, no `error`-level findings, key agreement outranking signatures, coverage limits
travelling inside the SARIF, the ratchet in six directions including the swap that keeps the total
unchanged, self-pollution by path and by renamed content, lock-file transitive dependencies, the
report's ordering and its own limits, and the urgency recorded in the CBOM. CI also exercises the
ratchet and the report through the action itself on three operating systems, and the code-scanning
upload and pull-request comment on a real pull request with the permissions granted.

---

## v1.0.0

First release. A GitHub Action that statically scans a repository for quantum-vulnerable
cryptography and emits a CycloneDX 1.6 CBOM (ECMA-424). Free, runs entirely in the caller's runner,
uploads nothing, no account and no API key, zero dependencies. Apache-2.0.

Before publication an adversarial pass found **18 real defects**, each reproduced with a command,
all fixed and all covered by regression tests. The list is published rather than buried, because a
tool that asks you to trust its inventory owes you the record of what it got wrong:

- **Command execution on the adopter's runner.** The composite step interpolated `${{ inputs.* }}`
  into its `run:` body, so the runner pasted raw input text into the script before bash parsed it.
  Any workflow wiring an input from a pull-request title handed execution to whoever wrote it.
- Forgeable step outputs; writes outside the workspace via traversal and symlinks; CI log spoofing
  through filenames carrying ANSI escapes.
- **A 61% detection miss rate**, caused by a word boundary treating `_` as a word character, which
  hid most of the OpenSSL, Rust, C and PHP surface — plus six false positives (`rsaCount`,
  `PKCS11`, `PKCS12` reported as RSA).
- Occurrence counts silently capped at 25 and printed as totals; ten mentions on one line counted
  as one.
- Truncated scans and UTF-16 files reported as clean full sweeps.
- ECDH and Diffie-Hellman declared with `cryptoFunctions: ["sign"]` when they do not sign; every
  algorithm primitive declared `unknown`.
- A paid signing option that could never be bought, since the action carries no x402 payment
  client.
- Unbounded buffering of the signing endpoint's response, measured at 1.42 GiB of resident memory
  against a hostile peer.

No ReDoS was found (worst adversarial line 7.93 microseconds across every regex) and symlink
handling was already correct.
