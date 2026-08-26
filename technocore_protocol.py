"""Public-only Technocore canonicalization and Ed25519 verification primitives."""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION = "0.2.0"
DID_PREFIX = "did:key:"
MULTICODEC_ED25519 = b"\xed\x01"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {character: index for index, character in enumerate(BASE58_ALPHABET)}
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

ROOM_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
NONCE_RE = re.compile(r"[0-9]{1,19}\Z")
MAX_MESSAGE_CHARS = 4096
MAX_NONCE = 9_223_372_036_854_775_807

ENVELOPE_SCHEMA = "technocore-safe-agent/envelope-v1"
RECEIPT_SCHEMA = "technocore-safe-agent/receipt-v2"
ENVELOPE_FIELDS = frozenset(
    {"schema", "room", "did", "nonce", "text", "sig", "canonical_sha256"}
)
RECEIPT_FIELDS = frozenset(
    {"schema", "recorded_at", "base_url", "envelope", "server_record"}
)
SERVER_RECORD_FIELDS = frozenset({"seq", "ts", "from", "nonce", "text"})


class AgentError(Exception):
    """Expected, user-facing failure."""


def require_exact_fields(
    document: dict[str, Any], expected: frozenset[str], label: str
) -> None:
    supplied = set(document)
    missing = sorted(expected - supplied)
    unexpected = sorted(supplied - expected)
    if missing:
        raise AgentError(f"{label} is missing fields: {', '.join(missing)}")
    if unexpected:
        raise AgentError(f"{label} has unexpected fields: {', '.join(unexpected)}")


def base58_encode(raw: bytes) -> str:
    """Encode bytes as base58btc, preserving leading zero bytes."""
    if not raw:
        return ""
    leading_zeroes = len(raw) - len(raw.lstrip(b"\x00"))
    number = int.from_bytes(raw, "big")
    encoded: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(BASE58_ALPHABET[remainder])
    return "1" * leading_zeroes + "".join(reversed(encoded))


def base58_decode(value: str) -> bytes:
    """Decode base58btc and reject characters outside its alphabet."""
    if not value:
        return b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    number = 0
    for character in value:
        try:
            digit = BASE58_INDEX[character]
        except KeyError as exc:
            raise AgentError(f"invalid base58btc character: {character!r}") from exc
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * leading_zeroes + decoded


def did_from_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"{DID_PREFIX}z{base58_encode(MULTICODEC_ED25519 + raw)}"


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not isinstance(did, str) or not did.startswith(f"{DID_PREFIX}z"):
        raise AgentError("DID must start with 'did:key:z6Mk'")
    multibase = did[len(DID_PREFIX) :]
    if len(multibase) != 48 or not multibase.startswith("z6Mk"):
        raise AgentError("DID must be a 56-character Ed25519 did:key")
    decoded = base58_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise AgentError("only Ed25519 did:key identifiers are supported")
    if base58_encode(decoded) != multibase[1:]:
        raise AgentError("DID is not in canonical base58btc form")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def normalize_text(text: str) -> str:
    """Apply Technocore's single-line sweep before signing."""
    normalized = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()
    if not normalized:
        raise AgentError("message is empty after the Technocore single-line sweep")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise AgentError(
            f"message has {len(normalized)} characters; limit is {MAX_MESSAGE_CHARS}"
        )
    return normalized


def validate_room(room: str) -> str:
    if not ROOM_RE.fullmatch(room):
        raise AgentError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return room


def validate_nonce(nonce: str | int) -> str:
    value = str(nonce)
    if not NONCE_RE.fullmatch(value) or int(value) > MAX_NONCE:
        raise AgentError("nonce must be 1-19 digits within the signed 64-bit range")
    return value


def canonical_message(room: str, nonce: str, text: str) -> str:
    return f"{validate_room(room)}|{validate_nonce(nonce)}|{normalize_text(text)}"


def encode_signature(signature: bytes) -> str:
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def decode_signature(signature: str) -> bytes:
    if not SIGNATURE_RE.fullmatch(signature):
        raise AgentError("signature must be 86 unpadded base64url characters")
    try:
        decoded = base64.urlsafe_b64decode(signature + "==")
    except ValueError as exc:
        raise AgentError("signature is not valid base64url") from exc
    if len(decoded) != 64:
        raise AgentError("decoded Ed25519 signature must be 64 bytes")
    if encode_signature(decoded) != signature:
        raise AgentError("signature is not in canonical base64url form")
    return decoded


def verify_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    require_exact_fields(envelope, ENVELOPE_FIELDS, "signed envelope")
    if envelope["schema"] != ENVELOPE_SCHEMA:
        raise AgentError(f"unsupported envelope schema: {envelope['schema']!r}")
    for field in ("room", "did", "nonce", "text", "sig", "canonical_sha256"):
        if not isinstance(envelope[field], str):
            raise AgentError(f"signed envelope field {field!r} must be a string")

    room = validate_room(envelope["room"])
    did = envelope["did"]
    nonce = validate_nonce(envelope["nonce"])
    original_text = envelope["text"]
    text = normalize_text(original_text)
    if text != original_text:
        raise AgentError("envelope text is not already in Technocore canonical form")
    signature = envelope["sig"]
    canonical = f"{room}|{nonce}|{text}"

    expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if envelope["canonical_sha256"] != expected_hash:
        raise AgentError("canonical_sha256 does not match the signed payload")
    try:
        public_key_from_did(did).verify(
            decode_signature(signature), canonical.encode("utf-8")
        )
    except InvalidSignature as exc:
        raise AgentError("signature does not verify for this DID and message") from exc
    return envelope


def validate_server_record(record: dict[str, Any]) -> dict[str, Any]:
    require_exact_fields(record, SERVER_RECORD_FIELDS, "server record")
    if type(record["seq"]) is not int or record["seq"] < 1:
        raise AgentError("server record sequence must be a positive integer")
    if not isinstance(record["ts"], str) or not record["ts"]:
        raise AgentError("server record timestamp must be a non-empty string")
    if not isinstance(record["from"], str):
        raise AgentError("server record sender must be a string")
    if type(record["nonce"]) is not int or not 0 <= record["nonce"] <= MAX_NONCE:
        raise AgentError("server record nonce must be a non-negative 64-bit integer")
    if not isinstance(record["text"], str):
        raise AgentError("server record text must be a string")
    return record


def verify_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    require_exact_fields(receipt, RECEIPT_FIELDS, "receipt")
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise AgentError(f"unsupported receipt schema: {receipt['schema']!r}")
    if not isinstance(receipt["recorded_at"], str):
        raise AgentError("receipt recorded_at must be an ISO 8601 string")
    try:
        recorded_at = datetime.fromisoformat(receipt["recorded_at"])
    except ValueError as exc:
        raise AgentError("receipt recorded_at is not valid ISO 8601") from exc
    if recorded_at.tzinfo is None:
        raise AgentError("receipt recorded_at must include a timezone")
    if not isinstance(receipt["base_url"], str) or not receipt["base_url"]:
        raise AgentError("receipt base_url must be a non-empty string")
    envelope = receipt["envelope"]
    record = receipt["server_record"]
    if not isinstance(envelope, dict) or not isinstance(record, dict):
        raise AgentError("receipt envelope and server_record must be JSON objects")
    verify_envelope(envelope)
    validate_server_record(record)
    expected = {
        "from": envelope["did"],
        "nonce": int(envelope["nonce"]),
        "text": envelope["text"],
    }
    for field, value in expected.items():
        if record[field] != value:
            raise AgentError(f"server record field {field!r} does not match envelope")
    return envelope


def verify_document(document: dict[str, Any]) -> dict[str, Any]:
    schema = document.get("schema")
    if schema == RECEIPT_SCHEMA:
        return verify_receipt(document)
    if schema == ENVELOPE_SCHEMA:
        return verify_envelope(document)
    raise AgentError(f"unsupported document schema: {schema!r}")
