#!/usr/bin/env python3
"""Online-only verification and posting of public Technocore envelopes."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from technocore_protocol import (
    ENVELOPE_SCHEMA,
    RECEIPT_SCHEMA,
    SERVER_RECORD_FIELDS,
    VERSION,
    AgentError,
    validate_server_record,
    verify_document,
    verify_envelope,
)

DEFAULT_BASE_URL = "https://technocore.chat"
MAX_DOCUMENT_BYTES = 65_536
MAX_RESPONSE_BYTES = 1_000_000


class NoRedirectHandler(HTTPRedirectHandler):
    """Keep a signed POST body on the explicitly selected origin."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def read_json_document(path: Path) -> dict[str, Any]:
    path = path.expanduser()
    try:
        if path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise AgentError("JSON document exceeds the 64 KiB safety limit")
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AgentError(f"cannot read {path}: {exc}") from exc
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AgentError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise AgentError("JSON document must be an object")
    return document


def validate_base_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
    except ValueError as exc:
        raise AgentError("base URL is malformed") from exc
    if parsed.username or parsed.password:
        raise AgentError("base URL must not contain credentials")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise AgentError(
            "base URL must be an origin without a path, query, or fragment"
        )
    local_http = parsed.scheme == "http" and hostname in {
        "127.0.0.1",
        "localhost",
        "::1",
    }
    if parsed.scheme != "https" and not local_http:
        raise AgentError(
            "base URL must use HTTPS; HTTP is allowed only for localhost tests"
        )
    if not parsed.netloc:
        raise AgentError("base URL must include a hostname")
    return f"{parsed.scheme}://{parsed.netloc}"


def sanitize_server_record(record: dict[str, Any]) -> dict[str, Any]:
    """Retain only the five fields needed as evidence; discard room contents."""
    missing = sorted(SERVER_RECORD_FIELDS - set(record))
    if missing:
        raise AgentError(f"Technocore posted record is missing: {', '.join(missing)}")
    sanitized = {
        field: record[field] for field in ("seq", "ts", "from", "nonce", "text")
    }
    return validate_server_record(sanitized)


def post_envelope(
    envelope: dict[str, Any], base_url: str = DEFAULT_BASE_URL, timeout: float = 20.0
) -> dict[str, Any]:
    verify_envelope(envelope)
    if timeout <= 0 or timeout > 120:
        raise AgentError("timeout must be greater than 0 and at most 120 seconds")
    origin = validate_base_url(base_url)
    room = quote(str(envelope["room"]), safe="")
    endpoint = f"{origin}/r/{room}?format=json"
    body = json.dumps(
        {
            "did": envelope["did"],
            "sig": envelope["sig"],
            "nonce": envelope["nonce"],
            "text": envelope["text"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "User-Agent": f"technocore-safe-agent/{VERSION}",
        },
    )
    try:
        with build_opener(NoRedirectHandler()).open(
            request, timeout=timeout
        ) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise AgentError(f"Technocore returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise AgentError(f"Technocore request failed: {exc.reason}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AgentError("Technocore response exceeded the 1 MB safety limit")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AgentError("Technocore response was not valid UTF-8 JSON") from exc
    if not isinstance(result, dict) or not isinstance(result.get("posted"), dict):
        raise AgentError("Technocore response did not include a posted record")
    posted = sanitize_server_record(result["posted"])
    expected = {
        "from": envelope["did"],
        "nonce": int(envelope["nonce"]),
        "text": envelope["text"],
    }
    for field, value in expected.items():
        if posted[field] != value:
            raise AgentError(f"Technocore echoed an unexpected {field!r} value")
    return posted


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify and post public Technocore envelopes without loading a private key."
    )
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify", help="verify an envelope or receipt offline")
    verify.add_argument("document", type=Path)

    post = commands.add_parser(
        "post-envelope", help="post a pre-signed public envelope"
    )
    post.add_argument("document", type=Path)
    post.add_argument("--base-url", default=DEFAULT_BASE_URL)
    post.add_argument("--timeout", type=float, default=20.0)
    post.add_argument("--receipt", type=Path)
    post.add_argument(
        "--confirm-public",
        action="store_true",
        help="confirm that the DID and message are intended for public posting",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    document = read_json_document(args.document)
    if args.command == "verify":
        envelope = verify_document(document)
        print(f"Valid signature: {envelope['did']}")
        print(f"Room: {envelope['room']}  Nonce: {envelope['nonce']}")
        print(f"Text: {envelope['text']}")
        return 0

    if document.get("schema") != ENVELOPE_SCHEMA:
        raise AgentError("post-envelope accepts a signed envelope, not a receipt")
    envelope = verify_envelope(document)
    if not args.confirm_public:
        raise AgentError(
            "review the public DID and text with 'verify', then add --confirm-public"
        )
    receipt_path = args.receipt or Path("receipts") / (
        f"{envelope['room']}-{envelope['nonce']}.json"
    )
    if receipt_path.expanduser().exists():
        raise AgentError(
            f"receipt already exists; no message was posted: {receipt_path}"
        )
    origin = validate_base_url(args.base_url)
    record = post_envelope(envelope, origin, args.timeout)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "base_url": origin,
        "envelope": envelope,
        "server_record": record,
    }
    verify_document(receipt)
    destination = write_json_exclusive(receipt_path, receipt)
    print(f"Posted sequence: {record['seq']}")
    print(f"Public DID: {envelope['did']}")
    print(f"Receipt: {destination.resolve()}")
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
