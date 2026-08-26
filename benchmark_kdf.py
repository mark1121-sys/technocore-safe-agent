#!/usr/bin/env python3
"""Measure encrypted identity serialization and load cost without writing a key."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import statistics
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_identity import OPENSSH_KDF_ROUNDS

BENCHMARK_PASSWORD = b"benchmark-only-password-not-used-for-real-keys"


def timed_sample() -> tuple[float, float]:
    key = Ed25519PrivateKey.generate()
    encryption = (
        serialization.PrivateFormat.OpenSSH.encryption_builder()
        .kdf_rounds(OPENSSH_KDF_ROUNDS)
        .build(BENCHMARK_PASSWORD)
    )

    started = time.perf_counter_ns()
    encrypted = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=encryption,
    )
    serialize_ms = (time.perf_counter_ns() - started) / 1_000_000

    started = time.perf_counter_ns()
    loaded = serialization.load_ssh_private_key(encrypted, password=BENCHMARK_PASSWORD)
    load_ms = (time.perf_counter_ns() - started) / 1_000_000
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("benchmark loaded an unexpected key type")
    if loaded.public_key().public_bytes_raw() != key.public_key().public_bytes_raw():
        raise RuntimeError("benchmark key round trip failed")
    return serialize_ms, load_ms


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "min": round(min(values), 3),
        "median": round(statistics.median(values), 3),
        "max": round(max(values), 3),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark the fixed OpenSSH bcrypt KDF configuration in memory."
    )
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=1)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not 3 <= args.samples <= 100:
        raise SystemExit("--samples must be between 3 and 100")
    if not 0 <= args.warmups <= 10:
        raise SystemExit("--warmups must be between 0 and 10")

    for _ in range(args.warmups):
        timed_sample()

    serialize_times: list[float] = []
    load_times: list[float] = []
    for _ in range(args.samples):
        serialize_ms, load_ms = timed_sample()
        serialize_times.append(serialize_ms)
        load_times.append(load_ms)

    result = {
        "schema": "technocore-safe-agent/kdf-benchmark-v1",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cryptography": importlib.metadata.version("cryptography"),
        "bcrypt": importlib.metadata.version("bcrypt"),
        "openssh_kdf_rounds": OPENSSH_KDF_ROUNDS,
        "samples": args.samples,
        "warmups": args.warmups,
        "serialize_ms": summarize(serialize_times),
        "load_ms": summarize(load_times),
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
