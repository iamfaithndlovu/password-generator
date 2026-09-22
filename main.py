"""
Offline password generator and encrypted local vault.

Passwords are generated with Python's secrets module and stored locally in an
AES-256-GCM encrypted vault. The app never sends credentials over the network.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import string
import struct
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import pyotp
import qrcode_terminal
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DEFAULT_VAULT_PATH = Path.home() / ".password_vault" / "vault.enc"
SAFE_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/|~"
AMBIGUOUS_CHARS = "0O1lI"
COMMON_WEAK_WORDS = ("password", "admin", "letmein", "welcome", "qwerty")


@dataclass
class PasswordEntry:
    service: str
    username: str
    password: str
    created_at: float
    updated_at: float
    last_used_at: Optional[float] = None
    usage_count: int = 0
    url: Optional[str] = None
    notes: Optional[str] = None
    totp_secret: Optional[str] = None

    @classmethod
    def from_dict(cls, service: str, data: Dict[str, Any]) -> "PasswordEntry":
        now = time.time()
        return cls(
            service=data.get("service") or service,
            username=data.get("username") or service,
            password=data["password"],
            created_at=float(data.get("created_at", data.get("created", now))),
            updated_at=float(data.get("updated_at", data.get("created", now))),
            last_used_at=data.get("last_used_at", data.get("last_used")),
            usage_count=int(data.get("usage_count", 0)),
            url=data.get("url"),
            notes=data.get("notes"),
            totp_secret=data.get("totp_secret"),
        )


class VaultError(Exception):
    """Raised when a vault operation cannot be completed safely."""


class OfflinePasswordVault:
    MAGIC = b"PWVLT3"
    VERSION = 3
    KDF_ITERATIONS = 600_000
    SALT_SIZE = 16
    NONCE_SIZE = 12
    HEADER_FORMAT = ">6sBI16s12s"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    # Compatibility with the original repository's v2 vault format.
    LEGACY_V2_HEADER_SIZE = 44
    LEGACY_V2_ITERATIONS = 600_000

    def __init__(self, vault_file: Path | str = DEFAULT_VAULT_PATH):
        self.vault_file = Path(vault_file).expanduser()
        self.key: Optional[bytes] = None
        self.entries: Dict[str, PasswordEntry] = {}
        self._salt: Optional[bytes] = None
        self._nonce: Optional[bytes] = None
        self._iterations = self.KDF_ITERATIONS
        self._data_offset = self.HEADER_SIZE

    @property
    def exists(self) -> bool:
        return self.vault_file.exists()

    def setup(self, master_password: str, force: bool = False) -> None:
        if self.vault_file.exists() and not force:
            raise VaultError(f"Vault already exists: {self.vault_file}")

        ok, reason = validate_master_password(master_password)
        if not ok:
            raise VaultError(reason)

        self._salt = os.urandom(self.SALT_SIZE)
        self._iterations = self.KDF_ITERATIONS
        self.key = self._derive_key(master_password, self._salt, self._iterations)
        self.entries = {}
        self._save()

    def unlock(self, master_password: str) -> None:
        if not self.vault_file.exists():
            raise VaultError(f"Vault not found: {self.vault_file}")

        metadata = self._read_header()
        self._salt = metadata["salt"]
        self._nonce = metadata["nonce"]
        self._iterations = metadata["iterations"]
        self._data_offset = metadata["data_offset"]
        self.key = self._derive_key(master_password, self._salt, self._iterations)

        try:
            ciphertext = self.vault_file.read_bytes()[self._data_offset :]
            if not ciphertext:
                self.entries = {}
                return

            plaintext = AESGCM(self.key).decrypt(self._nonce, ciphertext, None)
            raw_entries = json.loads(plaintext.decode("utf-8"))
            self.entries = {
                normalize_service_name(service): PasswordEntry.from_dict(service, data)
                for service, data in raw_entries.items()
            }
        except (InvalidTag, json.JSONDecodeError, KeyError, TypeError) as exc:
            self.key = None
            self.entries = {}
            raise VaultError("Wrong master password or corrupted vault.") from exc

    def add(
        self,
        service: str,
        username: str,
        password: Optional[str] = None,
        length: int = 24,
        symbols: bool = True,
        avoid_ambiguous: bool = True,
        url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> PasswordEntry:
        self._require_unlocked()
        key = normalize_service_name(service)
        now = time.time()
        existing = self.entries.get(key)
        generated = password or generate_password(
            length=length,
            symbols=symbols,
            avoid_ambiguous=avoid_ambiguous,
        )

        self.entries[key] = PasswordEntry(
            service=key,
            username=username,
            password=generated,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            last_used_at=existing.last_used_at if existing else None,
            usage_count=existing.usage_count if existing else 0,
            url=url if url is not None else (existing.url if existing else None),
            notes=notes if notes is not None else (existing.notes if existing else None),
            totp_secret=existing.totp_secret if existing else None,
        )
        self._save()
        return self.entries[key]

    def get(self, service: str, count_usage: bool = True) -> PasswordEntry:
        self._require_unlocked()
        key = normalize_service_name(service)
        if key not in self.entries:
            raise VaultError(f"No saved password for '{service}'.")

        entry = self.entries[key]
        if count_usage:
            entry.usage_count += 1
            entry.last_used_at = time.time()
            self._save()
        return entry

    def delete(self, service: str) -> None:
        self._require_unlocked()
        key = normalize_service_name(service)
        if key not in self.entries:
            raise VaultError(f"No saved password for '{service}'.")
        del self.entries[key]
        self._save()

    def list_entries(self) -> Iterable[PasswordEntry]:
        self._require_unlocked()
        return (self.entries[key] for key in sorted(self.entries))

    def setup_totp(self, service: str) -> str:
        entry = self.get(service, count_usage=False)
        entry.totp_secret = pyotp.random_base32()
        entry.updated_at = time.time()
        self._save()
        return entry.totp_secret

    def get_totp_code(self, service: str) -> str:
        entry = self.get(service, count_usage=False)
        if not entry.totp_secret:
            raise VaultError(f"No TOTP secret saved for '{service}'.")
        return pyotp.TOTP(entry.totp_secret).now()

    def lock(self) -> None:
        self.key = None
        self.entries.clear()
        self._salt = None
        self._nonce = None

    def _read_header(self) -> Dict[str, Any]:
        raw = self.vault_file.read_bytes()
        if len(raw) >= self.HEADER_SIZE:
            magic, version, iterations, salt, nonce = struct.unpack(
                self.HEADER_FORMAT, raw[: self.HEADER_SIZE]
            )
            if magic == self.MAGIC and version == self.VERSION:
                return {
                    "iterations": iterations,
                    "salt": salt,
                    "nonce": nonce,
                    "data_offset": self.HEADER_SIZE,
                }

        if len(raw) >= self.LEGACY_V2_HEADER_SIZE and raw[28:30] == b"V2":
            return {
                "iterations": self.LEGACY_V2_ITERATIONS,
                "salt": raw[:16],
                "nonce": raw[16:28],
                "data_offset": self.LEGACY_V2_HEADER_SIZE,
            }

        raise VaultError("Unsupported or corrupted vault file.")

    def _save(self) -> None:
        self._require_unlocked()
        if not self._salt:
            raise VaultError("Vault salt is missing.")

        self.vault_file.parent.mkdir(parents=True, exist_ok=True)
        self._nonce = os.urandom(self.NONCE_SIZE)
        payload = {
            key: asdict(entry)
            for key, entry in sorted(self.entries.items(), key=lambda item: item[0])
        }
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        ciphertext = AESGCM(self.key).encrypt(self._nonce, plaintext, None)
        header = struct.pack(
            self.HEADER_FORMAT,
            self.MAGIC,
            self.VERSION,
            self._iterations,
            self._salt,
            self._nonce,
        )

        temp_file = self.vault_file.with_suffix(self.vault_file.suffix + ".tmp")
        temp_file.write_bytes(header + ciphertext)
        os.replace(temp_file, self.vault_file)

    def _require_unlocked(self) -> None:
        if not self.key:
            raise VaultError("Vault is locked. Unlock it with your master password.")

    @staticmethod
    def _derive_key(master_password: str, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(master_password.encode("utf-8"))


def validate_master_password(password: str) -> tuple[bool, str]:
    if len(password) < 14:
        return False, "Master password must be at least 14 characters."

    lowered = password.lower()
    if any(word in lowered for word in COMMON_WEAK_WORDS):
        return False, "Master password contains a common weak word."

    classes = sum(
        bool(check)
        for check in (
            any(ch.islower() for ch in password),
            any(ch.isupper() for ch in password),
            any(ch.isdigit() for ch in password),
            any(ch in string.punctuation for ch in password),
        )
    )
    if classes < 3:
        return False, "Master password must use at least 3 character types."

    return True, "Master password is strong enough."


def generate_password(
    length: int = 24,
    symbols: bool = True,
    digits: bool = True,
    uppercase: bool = True,
    lowercase: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    if length < 12:
        raise VaultError("Generated passwords must be at least 12 characters.")

    groups = []
    if lowercase:
        groups.append(string.ascii_lowercase)
    if uppercase:
        groups.append(string.ascii_uppercase)
    if digits:
        groups.append(string.digits)
    if symbols:
        groups.append(SAFE_SYMBOLS)

    if len(groups) < 2:
        raise VaultError("Use at least two character groups for a strong password.")
    if length < len(groups):
        raise VaultError("Length is too short for the selected character groups.")

    if avoid_ambiguous:
        groups = [
            "".join(ch for ch in group if ch not in AMBIGUOUS_CHARS)
            for group in groups
        ]

    groups = [group for group in groups if group]
    alphabet = "".join(groups)
    required = [secrets.choice(group) for group in groups]
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    characters = required + remaining
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def normalize_service_name(service: str) -> str:
    cleaned = service.strip().lower()
    if not cleaned:
        raise VaultError("Service name cannot be empty.")
    return cleaned


def prompt_master_password(confirm: bool = False) -> str:
    password = getpass.getpass("Master password: ")
    if confirm:
        second = getpass.getpass("Confirm master password: ")
        if password != second:
            raise VaultError("Master passwords do not match.")
    return password


def unlock_from_args(args: argparse.Namespace) -> OfflinePasswordVault:
    vault = OfflinePasswordVault(args.vault)
    vault.unlock(prompt_master_password())
    return vault


def format_time(timestamp: Optional[float]) -> str:
    if not timestamp:
        return "never"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")


def print_entry(entry: PasswordEntry, reveal_password: bool = False) -> None:
    print(f"Service : {entry.service}")
    print(f"Username: {entry.username}")
    if reveal_password:
        print(f"Password: {entry.password}")
    print(f"Created : {format_time(entry.created_at)}")
    print(f"Updated : {format_time(entry.updated_at)}")
    print(f"Used    : {entry.usage_count} times, last used {format_time(entry.last_used_at)}")
    if entry.url:
        print(f"URL     : {entry.url}")
    if entry.notes:
        print(f"Notes   : {entry.notes}")
    if entry.totp_secret:
        print("TOTP    : configured")


def cmd_setup(args: argparse.Namespace) -> int:
    vault = OfflinePasswordVault(args.vault)
    vault.setup(prompt_master_password(confirm=True), force=args.force)
    print(f"Created encrypted offline vault: {vault.vault_file}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    print(
        generate_password(
            length=args.length,
            symbols=not args.no_symbols,
            digits=not args.no_digits,
            avoid_ambiguous=not args.allow_ambiguous,
        )
    )
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    vault = unlock_from_args(args)
    password = getpass.getpass("Password to save (leave blank to generate): ")
    password = password or None
    entry = vault.add(
        service=args.service,
        username=args.username,
        password=password,
        length=args.length,
        symbols=not args.no_symbols,
        avoid_ambiguous=not args.allow_ambiguous,
        url=args.url,
        notes=args.notes,
    )
    print_entry(entry, reveal_password=True)
    print("Saved locally in the encrypted vault.")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    vault = unlock_from_args(args)
    entry = vault.get(args.service)
    print_entry(entry, reveal_password=args.reveal)
    if not args.reveal:
        print("Use --reveal to print the password.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    vault = unlock_from_args(args)
    entries = list(vault.list_entries())
    if not entries:
        print("Vault is empty.")
        return 0

    print(f"{'Service':24} {'Username':24} {'Uses':>4} {'Updated':16} TOTP")
    print("-" * 80)
    for entry in entries:
        print(
            f"{entry.service[:24]:24} {entry.username[:24]:24} "
            f"{entry.usage_count:>4} {format_time(entry.updated_at):16} "
            f"{'yes' if entry.totp_secret else 'no'}"
        )
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    vault = unlock_from_args(args)
    if not args.yes:
        answer = input(f"Delete saved password for '{args.service}'? [y/N] ")
        if answer.strip().lower() != "y":
            print("Delete cancelled.")
            return 0
    vault.delete(args.service)
    print(f"Deleted '{normalize_service_name(args.service)}'.")
    return 0


def cmd_totp(args: argparse.Namespace) -> int:
    vault = unlock_from_args(args)
    if args.totp_command == "setup":
        secret = vault.setup_totp(args.service)
        entry = vault.get(args.service, count_usage=False)
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=entry.username,
            issuer_name="Offline Password Vault",
        )
        qrcode_terminal.draw(uri)
        print(f"Backup secret: {secret}")
        return 0

    print(vault.get_totp_code(args.service))
    return 0


def cmd_interactive(args: argparse.Namespace) -> int:
    vault = OfflinePasswordVault(args.vault)
    if not vault.exists:
        print("No vault found. Let's create one.")
        vault.setup(prompt_master_password(confirm=True))
    else:
        vault.unlock(prompt_master_password())

    while True:
        print("\n1. Generate password")
        print("2. Save password")
        print("3. List saved passwords")
        print("4. Show saved password")
        print("5. Delete saved password")
        print("6. Get TOTP code")
        print("7. Exit")
        choice = input("Choose: ").strip()

        try:
            if choice == "1":
                length = int(input("Length [24]: ") or "24")
                print(generate_password(length=length))
            elif choice == "2":
                service = input("Service: ")
                username = input("Username: ")
                password = getpass.getpass("Password (blank to generate): ") or None
                entry = vault.add(service, username, password=password)
                print_entry(entry, reveal_password=True)
            elif choice == "3":
                for entry in vault.list_entries():
                    print(f"- {entry.service} ({entry.username})")
            elif choice == "4":
                print_entry(vault.get(input("Service: ")), reveal_password=True)
            elif choice == "5":
                vault.delete(input("Service: "))
                print("Deleted.")
            elif choice == "6":
                print(vault.get_totp_code(input("Service: ")))
            elif choice == "7":
                vault.lock()
                return 0
            else:
                print("Choose a number from 1 to 7.")
        except (ValueError, VaultError) as exc:
            print(f"Error: {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate strong passwords and store them offline in an encrypted vault."
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=DEFAULT_VAULT_PATH,
        help=f"Encrypted vault file path. Default: {DEFAULT_VAULT_PATH}",
    )

    subparsers = parser.add_subparsers(dest="command")

    setup = subparsers.add_parser("setup", help="Create a new encrypted vault.")
    setup.add_argument("--force", action="store_true", help="Overwrite an existing vault.")
    setup.set_defaults(func=cmd_setup)

    generate = subparsers.add_parser("generate", help="Generate a strong password.")
    generate.add_argument("-l", "--length", type=int, default=24)
    generate.add_argument("--no-symbols", action="store_true")
    generate.add_argument("--no-digits", action="store_true")
    generate.add_argument("--allow-ambiguous", action="store_true")
    generate.set_defaults(func=cmd_generate)

    add = subparsers.add_parser("add", help="Save a generated or manually entered password.")
    add.add_argument("service")
    add.add_argument("-u", "--username", required=True)
    add.add_argument("-l", "--length", type=int, default=24)
    add.add_argument("--no-symbols", action="store_true")
    add.add_argument("--allow-ambiguous", action="store_true")
    add.add_argument("--url")
    add.add_argument("--notes")
    add.set_defaults(func=cmd_add)

    get = subparsers.add_parser("get", help="Show saved credential metadata.")
    get.add_argument("service")
    get.add_argument("--reveal", action="store_true", help="Print the saved password.")
    get.set_defaults(func=cmd_get)

    list_cmd = subparsers.add_parser("list", help="List saved services without passwords.")
    list_cmd.set_defaults(func=cmd_list)

    delete = subparsers.add_parser("delete", help="Delete a saved password.")
    delete.add_argument("service")
    delete.add_argument("-y", "--yes", action="store_true")
    delete.set_defaults(func=cmd_delete)

    totp = subparsers.add_parser("totp", help="Manage saved TOTP secrets.")
    totp_subparsers = totp.add_subparsers(dest="totp_command", required=True)
    totp_setup = totp_subparsers.add_parser("setup", help="Add a TOTP secret to a service.")
    totp_setup.add_argument("service")
    totp_setup.set_defaults(func=cmd_totp)
    totp_code = totp_subparsers.add_parser("code", help="Print the current TOTP code.")
    totp_code.add_argument("service")
    totp_code.set_defaults(func=cmd_totp)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        args.func = cmd_interactive

    try:
        return args.func(args)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return 130
    except VaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
