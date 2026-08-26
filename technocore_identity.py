#!/usr/bin/env python3
"""Offline-only encrypted identity and signed-envelope CLI for Technocore."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_protocol import (
    ENVELOPE_SCHEMA,
    VERSION,
    AgentError,
    did_from_public_key,
    encode_signature,
    normalize_text,
    validate_nonce,
    validate_room,
)

DEFAULT_IDENTITY = Path.home() / ".technocore-safe-agent" / "identity.key"
MIN_PASSWORD_BYTES = 16
MAX_PASSWORD_BYTES = 1_024
OPENSSH_KDF_ROUNDS = 256


def next_nonce() -> str:
    return validate_nonce(time.time_ns())


def make_envelope(
    private_key: Ed25519PrivateKey,
    room: str,
    text: str,
    nonce: str | None = None,
) -> dict[str, Any]:
    clean_text = normalize_text(text)
    clean_room = validate_room(room)
    clean_nonce = validate_nonce(nonce or next_nonce())
    canonical = f"{clean_room}|{clean_nonce}|{clean_text}"
    return {
        "schema": ENVELOPE_SCHEMA,
        "room": clean_room,
        "did": did_from_public_key(private_key.public_key()),
        "nonce": clean_nonce,
        "text": clean_text,
        "sig": encode_signature(private_key.sign(canonical.encode("utf-8"))),
        "canonical_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def write_encrypted_identity(
    private_key: Ed25519PrivateKey, path: Path, password: bytes
) -> None:
    validate_password(password, new_identity=True)
    try:
        encryption = (
            serialization.PrivateFormat.OpenSSH.encryption_builder()
            .kdf_rounds(OPENSSH_KDF_ROUNDS)
            .build(password)
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=encryption,
        )
    except UnsupportedAlgorithm as exc:
        raise AgentError("encrypted OpenSSH key support is unavailable") from exc
    path = path.expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise AgentError(
            f"identity already exists; refusing to overwrite: {path}"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def load_identity(path: Path, password: bytes) -> Ed25519PrivateKey:
    validate_password(password)
    path = path.expanduser()
    try:
        pem = path.read_bytes()
    except OSError as exc:
        raise AgentError(f"cannot read identity {path}: {exc}") from exc
    try:
        key = serialization.load_ssh_private_key(pem, password=password)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise AgentError(
            "identity password is wrong or the key file is invalid"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AgentError("identity file does not contain an Ed25519 private key")
    return key


def validate_password(password: bytes, *, new_identity: bool = False) -> None:
    if not password:
        raise AgentError("identity password must not be empty")
    if len(password) > MAX_PASSWORD_BYTES:
        raise AgentError(
            f"identity password must be at most {MAX_PASSWORD_BYTES} UTF-8 bytes"
        )
    if new_identity and len(password) < MIN_PASSWORD_BYTES:
        raise AgentError(
            f"new identity password must be at least {MIN_PASSWORD_BYTES} UTF-8 bytes"
        )


def read_password_file(path: Path) -> bytes:
    path = path.expanduser()
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as exc:
        raise AgentError(f"cannot read password file {path}: {exc}") from exc
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise AgentError("password file must not be accessible by group or other users")
    password = raw.rstrip(b"\r\n")
    if b"\r" in password or b"\n" in password or not password:
        raise AgentError("password file must contain exactly one non-empty line")
    return password


def password_for(args: argparse.Namespace, *, new_identity: bool = False) -> bytes:
    if args.password_file:
        password = read_password_file(args.password_file)
    else:
        password = getpass.getpass("Identity password: ").encode("utf-8")
        if new_identity:
            confirmation = getpass.getpass("Confirm identity password: ").encode(
                "utf-8"
            )
            if password != confirmation:
                raise AgentError("password confirmation does not match")
    validate_password(password, new_identity=new_identity)
    return password


def read_message(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    try:
        return args.text_file.expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise AgentError(f"cannot read message file {args.text_file}: {exc}") from exc


def write_json_exclusive(path: Path, document: dict[str, Any]) -> Path:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise AgentError(f"refusing to overwrite existing file: {path}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def add_identity_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--identity",
        type=Path,
        default=DEFAULT_IDENTITY,
        help=f"bcrypt-encrypted OpenSSH Ed25519 key (default: {DEFAULT_IDENTITY})",
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        help="read password from a protected one-line file instead of prompting",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline-only Ed25519 did:key generation and signing."
    )
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="create a new encrypted local identity")
    add_identity_options(keygen)
    show_did = commands.add_parser("did", help="print the public DID for an identity")
    add_identity_options(show_did)

    sign = commands.add_parser("sign", help="create a signed envelope offline")
    add_identity_options(sign)
    sign.add_argument("--room", required=True)
    source = sign.add_mutually_exclusive_group(required=True)
    source.add_argument("--text")
    source.add_argument("--text-file", type=Path)
    sign.add_argument("--nonce")
    sign.add_argument("--out", type=Path, required=True)
    return parser


def run(args: argparse.Namespace) -> int:
    if args.command == "keygen":
        password = password_for(args, new_identity=True)
        key = Ed25519PrivateKey.generate()
        write_encrypted_identity(key, args.identity, password)
        print(f"Identity created: {args.identity.expanduser().resolve()}")
        print(f"Public DID: {did_from_public_key(key.public_key())}")
        print("This signing program imports no network client.")
        return 0

    password = password_for(args)
    key = load_identity(args.identity, password)
    if args.command == "did":
        print(did_from_public_key(key.public_key()))
        return 0

    envelope = make_envelope(key, args.room, read_message(args), args.nonce)
    destination = write_json_exclusive(args.out, envelope)
    print(f"Signed envelope: {destination.resolve()}")
    print(f"Canonical SHA-256: {envelope['canonical_sha256']}")
    print("This signing program imports no network client.")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except AgentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
