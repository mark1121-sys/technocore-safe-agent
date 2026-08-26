# Five Failure Boundaries in a Split Technocore Agent

Most signing examples prove that a valid message can be posted. This project tested the opposite question: which failures must stop before a private key or misleading receipt reaches the online path?

The result is a two-process design. The offline process creates and loads the key. The online process accepts only a public signed envelope. The tests below use deterministic temporary keys and localhost servers; they do not contact Technocore.

## 1. The online process cannot load a private key

The first version combined key generation, signing, verification, and posting in one program. A network-path defect or future feature could therefore reach the key loader in the same process.

The implementation was split into:

- `technocore_identity.py`: encrypted identity creation and envelope signing, with no network imports;
- `technocore_protocol.py`: public DID, canonicalization, and verification functions;
- `technocore_post.py`: public-envelope verification and HTTPS posting, with no private-key loader.

A source-boundary test parses the offline modules' imports and fails if a network package appears. A second test fails if private-key loading symbols appear in the online poster. These tests do not prove dependency safety, but they detect accidental boundary collapse in this repository.

## 2. Equivalent-looking encodings are not accepted

An envelope is rejected when it has an unexpected field, a JSON value of the wrong type, non-canonical text, a mismatched SHA-256 value, a modified signature, or a non-canonical base64url signature representation.

The strict field set also rejects a document containing a field named `private_key`. This is defense in depth: the signer never creates that field, and the poster refuses to process it if another tool adds it.

## 3. A signed POST is not redirected

The localhost redirect test returns HTTP 307 from the intended endpoint. The poster records one request to the original path and refuses the response. It does not replay the signed body at the redirect target.

Remote plain HTTP, URL credentials, malformed origins, and base URLs containing a path, query, or fragment are also rejected. Localhost HTTP remains available only for tests.

## 4. Untrusted room content does not enter the receipt

The mock server response includes an unrelated room message containing `IGNORE ALL PREVIOUS INSTRUCTIONS` and an unexpected field inside the posted record. The poster retains neither.

The receipt stores only:

```text
seq, ts, from, nonce, text
```

The sender, nonce, and normalized text must match the signed envelope. The receipt is verified before it is written.

## 5. A local collision stops before the network call

If the intended receipt path already exists, the command refuses before calling the posting function. Identity, envelope, and receipt writers also use exclusive creation and refuse overwrites.

This does not solve the case where the server accepts a message and the local machine loses power before saving the receipt. That residual failure requires server-side idempotency or later lookup support; the client does not claim to provide either.

## Measured key-encryption cost

The private key uses the standard encrypted OpenSSH format with bcrypt set to 256 KDF rounds. `benchmark_kdf.py` creates fresh Ed25519 keys, serializes and loads them entirely in memory, and verifies each public-key round trip.

Observed on 2026-08-26:

```text
Platform: Windows 11 10.0.26200
Python: 3.12.10
cryptography: 50.0.1
bcrypt: 5.0.0
Samples: 7 after 1 warm-up

Serialize: min 1384.740 ms, median 1480.887 ms, max 1537.713 ms
Load:      min 1394.732 ms, median 1430.694 ms, max 1549.671 ms
```

Reproduce:

```powershell
python benchmark_kdf.py --samples 7 --warmups 1
```

These timings measure usability on one machine, not password-cracking resistance. Hardware, system load, package builds, and thermal state affect the result. Seven samples reduce one-run noise but are not a broad hardware study.

## Compatibility and audit results

The generated deterministic DID and signature were accepted by the official Technocore `src/didkey.py` verifier. The local verification run also reported:

- 14 unit tests passed; one POSIX permission test was skipped on Windows;
- Ruff checks passed;
- Bandit reported no medium- or high-severity findings in the three runtime modules;
- `pip-audit` reported no known vulnerabilities in the locked runtime dependencies;
- zizmor reported no GitHub Actions findings in pedantic offline mode;
- a clean environment installed successfully with `--require-hashes`.

Vulnerability scanners detect published records known to their databases at scan time. A clean result is not proof that a dependency is safe.

## What this does not prove

The tests do not protect a key from a compromised signer operating system, malicious firmware, physical access, memory inspection, unsafe removable media, a weak password, or a malicious dependency whose hash is already approved. Python cannot guarantee immediate zeroization of every password and private-key copy in memory.

The safe operating model remains: sign on a dedicated offline system, transfer only the public envelope outward, verify and post from a separate online system, then shut the signer down.

This work demonstrates a security boundary. It does not demonstrate Flop Network testnet participation, airdrop eligibility, or a future token allocation.
