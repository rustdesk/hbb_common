#!/usr/bin/env python3
"""Patch RustDesk hbb_common compile-time self-host defaults.

Designed to fail closed against the RustDesk 1.4.9 hbb_common source shape.
It never reads or handles the private key. The supplied public key must be
the content of id_ed25519.pub.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shutil
import tempfile


PROD_PATTERN = re.compile(
    r'pub static ref PROD_RENDEZVOUS_SERVER:\s*RwLock<String>\s*='
    r'\s*RwLock::new\("(?P<value>[^"]*)"\.to_owned\(\)\);'
)

KEY_PATTERN = re.compile(
    r'pub const RS_PUB_KEY:\s*&str\s*=\s*"(?P<value>[A-Za-z0-9+/=]+)";'
)

FALLBACK_PATTERN = re.compile(
    r'pub const RENDEZVOUS_SERVERS:\s*&\[&str\]\s*='
    r'\s*&\[(?P<value>[^\]]*)\];'
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Embed a self-hosted RustDesk server and public key in hbb_common."
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=Path("src/config.rs"),
        help="Path to hbb_common/src/config.rs (default: src/config.rs).",
    )
    parser.add_argument(
        "--server",
        required=True,
        help="FQDN/IP with optional port; do not include a scheme or path.",
    )

    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--public-key-file",
        type=Path,
        help="File containing the single-line id_ed25519.pub value.",
    )
    key_group.add_argument(
        "--public-key",
        help="Literal id_ed25519.pub value.",
    )

    parser.add_argument(
        "--strict-self-host-only",
        action="store_true",
        help="Also replace RENDEZVOUS_SERVERS to remove the public fallback.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that the requested values are already present; do not modify.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create <file>.bak before the first modification.",
    )
    return parser.parse_args()


def validate_server(raw: str) -> str:
    server = raw.strip()
    if not server:
        raise ValueError("server is empty")
    if any(ch.isspace() for ch in server):
        raise ValueError("server must not contain whitespace")
    if "://" in server:
        raise ValueError("server must not include a URL scheme")
    if any(ch in server for ch in ("/", "\\", ",", '"', "'")):
        raise ValueError("server must not contain a path, comma, quote, or backslash")

    host: str
    port: int | None = None

    if server.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:]+)\]:(\d{1,5})", server)
        if not match:
            raise ValueError(
                "IPv6 must use bracketed host plus explicit port, e.g. [2001:db8::1]:21116"
            )
        ipaddress.IPv6Address(match.group(1))
        host = match.group(1)
        port = int(match.group(2))
    elif server.count(":") == 0:
        host = server
    elif server.count(":") == 1:
        host, port_text = server.rsplit(":", 1)
        if not host or not port_text.isdigit():
            raise ValueError("invalid host:port")
        port = int(port_text)
    else:
        raise ValueError(
            "raw IPv6 is ambiguous; use [IPv6]:port or a DNS hostname"
        )

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("port must be in 1..65535")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253:
            raise ValueError("DNS name is too long")
        labels = host.rstrip(".").split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError(
                "invalid DNS hostname; use ASCII/Punycode labels without underscores"
            )
    return server


def load_public_key(args: argparse.Namespace) -> tuple[str, bytes]:
    if args.public_key_file is not None:
        value = args.public_key_file.read_text(encoding="utf-8").strip()
    else:
        value = args.public_key.strip()

    if any(ch.isspace() for ch in value):
        raise ValueError("public key must be a single Base64 token")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"public key is not valid Base64: {exc}") from exc
    if len(decoded) != 32:
        raise ValueError(
            f"expected a 32-byte Ed25519 public key, decoded length is {len(decoded)}"
        )
    return value, decoded


def single_match(pattern: re.Pattern[str], text: str, name: str) -> re.Match[str]:
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise RuntimeError(
            f"{name}: expected exactly one source match, found {len(matches)}; "
            "review the new upstream source manually"
        )
    return matches[0]


def replace_once(
    pattern: re.Pattern[str],
    text: str,
    replacement: str,
    name: str,
) -> str:
    single_match(pattern, text, name)
    updated, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise RuntimeError(f"{name}: replacement count was {count}")
    return updated


def extract_values(text: str) -> tuple[str, str, str]:
    prod = single_match(PROD_PATTERN, text, "PROD_RENDEZVOUS_SERVER").group("value")
    key = single_match(KEY_PATTERN, text, "RS_PUB_KEY").group("value")
    fallback = single_match(FALLBACK_PATTERN, text, "RENDEZVOUS_SERVERS").group("value")
    return prod, key, fallback


def atomic_write(path: Path, content: str) -> None:
    mode = path.stat().st_mode
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        dir=path.parent,
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temp_path, mode)
    os.replace(temp_path, path)


def main() -> int:
    args = parse_args()
    source_path = args.file.resolve()
    if not source_path.is_file():
        raise FileNotFoundError(source_path)

    server = validate_server(args.server)
    public_key, decoded_key = load_public_key(args)
    fingerprint = hashlib.sha256(decoded_key).hexdigest()

    original = source_path.read_text(encoding="utf-8")
    current_prod, current_key, current_fallback = extract_values(original)

    desired_fallback = f'"{server}"'
    fallback_ok = (
        not args.strict_self_host_only
        or current_fallback.strip() == desired_fallback
    )

    if args.check:
        errors: list[str] = []
        if current_prod != server:
            errors.append(
                f"PROD_RENDEZVOUS_SERVER is {current_prod!r}, expected {server!r}"
            )
        if current_key != public_key:
            errors.append("RS_PUB_KEY does not match the supplied public key")
        if not fallback_ok:
            errors.append(
                "RENDEZVOUS_SERVERS is not locked to the requested self-host server"
            )
        if errors:
            raise RuntimeError("; ".join(errors))
        print(f"check=ok server={server} public_key_sha256={fingerprint}")
        return 0

    updated = replace_once(
        PROD_PATTERN,
        original,
        (
            "pub static ref PROD_RENDEZVOUS_SERVER: RwLock<String> = "
            f'RwLock::new("{server}".to_owned());'
        ),
        "PROD_RENDEZVOUS_SERVER",
    )
    updated = replace_once(
        KEY_PATTERN,
        updated,
        f'pub const RS_PUB_KEY: &str = "{public_key}";',
        "RS_PUB_KEY",
    )

    if args.strict_self_host_only:
        updated = replace_once(
            FALLBACK_PATTERN,
            updated,
            f'pub const RENDEZVOUS_SERVERS: &[&str] = &["{server}"];',
            "RENDEZVOUS_SERVERS",
        )

    if updated == original:
        print(f"changed=no server={server} public_key_sha256={fingerprint}")
        return 0

    if not args.no_backup:
        backup_path = source_path.with_name(source_path.name + ".bak")
        if not backup_path.exists():
            shutil.copy2(source_path, backup_path)

    atomic_write(source_path, updated)

    # Re-read and verify the final file.
    final_text = source_path.read_text(encoding="utf-8")
    final_prod, final_key, final_fallback = extract_values(final_text)
    if final_prod != server or final_key != public_key:
        raise RuntimeError("post-write verification failed")
    if args.strict_self_host_only and final_fallback.strip() != desired_fallback:
        raise RuntimeError("post-write strict fallback verification failed")

    print(f"changed=yes server={server} public_key_sha256={fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
