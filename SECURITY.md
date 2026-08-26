# Security Policy and Threat Model

## Security objective

The primary objective is to prevent a Technocore Ed25519 private key from reaching a network-facing process or repository. The design reduces accidental disclosure and limits what an online compromise can steal.

It does not make private-key theft impossible.

## Trust boundaries

### Offline signer

`technocore_identity.py` is the only program that creates or loads a private key. It has no network imports. It writes a bcrypt-encrypted OpenSSH Ed25519 key with 256 KDF rounds and exclusive file creation. It does not accept passwords on the command line.

The signer still trusts:

- the operating system, firmware, Python interpreter, and hardware;
- the installed `cryptography`, `cffi`, and `pycparser` artifacts;
- local input and output devices;
- the user-selected password and backup process.

### Public protocol verifier

`technocore_protocol.py` processes only public data: DIDs, canonical text, signatures, envelopes, and receipts. It rejects missing and unexpected fields.

### Online poster

`technocore_post.py` cannot load a private key or password file. It verifies a signed envelope before posting and sends only four public fields. It rejects remote plain HTTP, embedded URL credentials, redirects, oversized responses, unexpected echoes, and receipt overwrites.

The poster discards unrelated room messages and unexpected server fields. This reduces the chance that untrusted chat content is carried into later agent workflows.

## Threats addressed

- Accidental PEM or password inclusion in a post
- A network library accidentally added to the signing module
- A private-key loader accidentally added to the posting module
- Message or DID tampering between signing and posting
- Signed POST forwarding to another origin through a redirect
- Dependency substitution during normal locked installation
- Secret files accidentally committed under common extensions
- Untrusted room content being retained in a receipt
- Silent overwrite of an identity, envelope, or receipt

Tests enforce several of these boundaries by inspecting imports and source text as well as behavior.

## Threats not solved

- Malware, firmware compromise, or physical attacks on the offline signer
- Malicious or compromised Python packages whose approved hashes are already locked
- Compromise of the Python interpreter or operating-system random generator
- Password capture by a keylogger, camera, or hardware implant
- Secrets recovered from RAM, swap, hibernation, crash dumps, or forensic storage
- Weak passwords or insecure backups
- Removable-media attacks crossing the air gap
- Traffic analysis, denial of service, server compromise, or permanent public-message retention
- Human approval of malicious or privacy-sensitive text
- Future cryptographic breaks or protocol changes

Python and the `cryptography` API do not provide a reliable guarantee that every private-key or password copy is immediately zeroized from process memory. Shut down the signer after use and use full-disk encryption, but treat those as risk reductions rather than proof of erasure.

## Recommended high-security operation

1. Use a dedicated offline signer with networking disabled in firmware or physically absent.
2. Verify the source commit and dependency lock on a separate preparation machine.
3. Install only from a predownloaded wheelhouse using `--no-index` and `--require-hashes`.
4. Use the interactive password prompt and a long, unique password.
5. Keep encrypted backups on two offline media items; keep the password separately.
6. Transfer only public envelope JSON outward.
7. Never return online-touched media to the signer.
8. Verify the signature and exact public text on the online machine before posting.
9. Power off the signer after use; avoid sleep and hibernation.
10. If compromise is suspected, stop using the DID. Do not rely on changing only the password.

For stronger protection than a software key file can provide, a future design should evaluate signing through a hardware device with non-exportable Ed25519 keys. Compatibility and implementation quality would need independent review before adoption.

## Dependency maintenance

`requirements.txt` contains the allowed direct dependency range. `requirements.lock` pins resolved versions and package hashes for installation. Updating the lock is a security-sensitive change and requires tests plus a vulnerability audit.

Do not assume a passing vulnerability database scan proves safety. It detects only published issues known to that database at scan time.

## Reporting a vulnerability

Do not open a public issue containing private keys, passwords, recovery phrases, personal data, or exploit details that would put users at immediate risk. Contact the repository maintainer privately if a private channel is available. If no private channel exists, publish only a minimal notification asking the maintainer to establish one.
