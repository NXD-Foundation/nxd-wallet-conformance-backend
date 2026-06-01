# JAR x5c Certificate Chain — Implementation Plan

This note addresses the OID4VP interoperability question around **VP-001 / x509 JAR** validation: wallets receive a signed authorization request whose `x5c` header currently contains only the **leaf verifier certificate**, while chain validation requires the issuing CA **PID Issuer CA 02**.

## Problem Summary


| Item                                   | Current state                                                       |
| -------------------------------------- | ------------------------------------------------------------------- |
| JAR signing key source                 | `certs/WE-BUILD-Verifier.p12` (ES256, default for x509 VP flows)    |
| `x5c` contents                         | 1 certificate (leaf only)                                           |
| Leaf subject                           | `CN=WE-BUILD Verifier, O=WE-Build, C=EU`                            |
| Leaf issuer                            | `CN=PID Issuer CA 02, O=EUDI Wallet Reference Implementation, C=EU` |
| Leaf SAN                               | `dev-i4mlab.aegean.gr`                                              |
| Repo ships issuing CA?                 | No                                                                  |
| External wallets with chain validation | Fail unless they already trust PID Issuer CA 02                     |


Relevant code paths:

- `utils/cryptoUtils.js` — `loadVerifierP12()`, `extractCertificateChain()`, `buildVpRequestJWT()`
- `utils/routeUtils.js` — `generateVPRequest()` passes `jar_alg` (default `ES256`)
- `certs/README.md` — documents the p12 only

The verifier already supports multi-cert chains: `extractCertificateChain()` parses every PEM block and `buildVpRequestJWT()` assigns the full array to `x5c`. The gap is **content**, not plumbing.

### EUDI preprod PKI endpoints

The leaf certificate references:

- CRL: `https://preprod.pki.eudiw.dev/crl/pid_CA_EU_02.crl`

There is **no reliable public CA-cert download URL** on that host for the EU CA (common `/ca/` and `/certs/` paths return 404). Prefer the reference wallet GitHub source above.

## Implementation Plan

### Phase 1 — Add CA material to the repo

1. Add `certs/pidissuerca02_eu.pem` (copy from EUDI reference wallet raw URL above).
2. Update `certs/README.md`:
  - describe leaf p12 + EU CA pem
  - note provenance (EUDI reference wallet, preprod trust anchor)
  - document that wallets may also configure the same PEM as a trusted reader root

**Acceptance:** file present; `openssl x509 -in certs/pidissuerca02_eu.pem -noout -subject` shows `PID Issuer CA 02`.

### Phase 2 — Extend `loadVerifierP12()` chain assembly

**File:** `utils/cryptoUtils.js`

1. After extracting certs from the p12, if the chain has only one entry:
  - load `certs/pidissuerca02_eu.pem` (path configurable via env, e.g. `WEBUILD_X5C_CA_PEM`)
  - append CA base64 entries that are **not already present** (dedupe by DER)
2. Keep leaf at index `0` (required for `x509_hash` logic and SAN/client_id checks).

Sketch:

```javascript
function appendCaCertsIfNeeded(certChain, caPemPaths = []) {
  const seen = new Set(certChain);
  for (const pemPath of caPemPaths) {
    if (!fs.existsSync(pemPath)) continue;
    for (const derB64 of extractCertificateChain(fs.readFileSync(pemPath, "utf8"))) {
      if (!seen.has(derB64)) {
        certChain.push(derB64);
        seen.add(derB64);
      }
    }
  }
  return certChain;
}
```

Default CA path list:

```javascript
const DEFAULT_VERIFIER_CA_PEMS = [
  path.resolve(process.cwd(), "certs", "pidissuerca02_eu.pem"),
];
```

**Acceptance:** ES256 JAR for x509 flows returns `x5c.length >= 2`, with the verifier leaf still at `x5c[0]`.

### Phase 3 — Tests

**New test file:** `tests/jarX5cChain.test.js` (or extend an existing x509 JAR-focused test file)

Cases:

1. `loadVerifierP12()` / JAR builder with `jar_alg=ES256` produces `x5c` with ≥ 2 certs when CA pem exists.
2. Leaf remains `x5c[0]` and matches WE-BUILD Verifier subject.
3. `openssl verify -CAfile certs/pidissuerca02_eu.pem` succeeds for the leaf extracted from `x5c[0]`.
4. Optional: second cert subject equals `PID Issuer CA 02`.
5. Keep JAR-oriented assertions on chain semantics rather than exact length:
  - prefer `x5c.length >= 2`
  - assert the verifier leaf remains `x5c[0]`
  - avoid reusing credential-issuance `x5c` expectations for JAR-specific tests
6. Regression: define one explicit missing-CA policy at the `loadVerifierP12()` seam and test it. Recommended policy:
  - default: **fail fast** if `WEBUILD_X5C_CA_PEM` or the default CA pem path is configured but unreadable/empty
  - explicit override: allow leaf-only fallback only when an env flag such as `WEBUILD_X5C_ALLOW_LEAF_ONLY=true` is set
  - log a warning on the fallback path so interop regressions are visible

Run:

```bash
npx mocha tests/jarX5cChain.test.js tests/directPostJwt.test.js
```

###  

### Phase 4 — Wallet / interop partner guidance

Reply to external wallets:

> The WE-BUILD verifier JAR is signed with a leaf cert issued by **PID Issuer CA 02 (EU)**. You can either:
>
> 1. Trust `pidissuerca02_eu.pem` as a reader root (same as EUDI reference wallets), or
> 2. Validate the chain using the CA now included in JAR `x5c[1]` (after we deploy Phase 2).

Reference wallet trust-store configuration:

- Android: `configureReaderTrustStore(context, R.raw.pidissuerca02_eu, ...)`
- iOS: `trustedReaderRootCertificates` includes `"pidissuerca02_eu"`



##   

