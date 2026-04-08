#!/usr/bin/env python3
import argparse
import base64
import getpass
import json
import os
import secrets
import string
import sys
from datetime import datetime, timezone
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

APP_NAME = "WS_Password Manager"
DEFAULT_VAULT = Path.home() / ".WS_Password_vault.json"
KDF_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def derive_key(master_password: str, salt: bytes, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4) -> bytes:
    raw = hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )
    return base64.urlsafe_b64encode(raw)


class VaultError(Exception):
    pass


class PasswordVault:
    def __init__(self, vault_path: Path):
        self.vault_path = vault_path.expanduser().resolve()
        self.meta = None
        self.entries = None
        self.fernet = None

    def exists(self) -> bool:
        return self.vault_path.exists()

    def initialize(self, master_password: str) -> None:
        if self.exists():
            raise VaultError(f"Vault already exists at {self.vault_path}")
        salt = secrets.token_bytes(16)
        self.meta = {
            "app": APP_NAME,
            "version": 1,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "kdf": {
                "name": "argon2id",
                "version": KDF_VERSION,
                "salt": b64e(salt),
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 4,
                "hash_len": 32,
            },
        }
        self.entries = []
        self.fernet = Fernet(derive_key(master_password, salt))
        self._save()

    def unlock(self, master_password: str) -> None:
        if not self.exists():
            raise VaultError(f"Vault does not exist at {self.vault_path}")
        with open(self.vault_path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        self.meta = blob["meta"]
        salt = b64d(self.meta["kdf"]["salt"])
        self.fernet = Fernet(
            derive_key(
                master_password,
                salt,
                time_cost=self.meta["kdf"].get("time_cost", 3),
                memory_cost=self.meta["kdf"].get("memory_cost", 65536),
                parallelism=self.meta["kdf"].get("parallelism", 4),
            )
        )
        try:
            decrypted = self.fernet.decrypt(blob["ciphertext"].encode("utf-8"))
        except InvalidToken as e:
            raise VaultError("Invalid master password or corrupted vault") from e
        self.entries = json.loads(decrypted.decode("utf-8"))

    def _save(self) -> None:
        if self.meta is None or self.entries is None or self.fernet is None:
            raise VaultError("Vault is not unlocked")
        payload = json.dumps(self.entries, ensure_ascii=False, indent=2).encode("utf-8")
        ciphertext = self.fernet.encrypt(payload).decode("utf-8")
        self.meta["updated_at"] = utc_now()
        blob = {"meta": self.meta, "ciphertext": ciphertext}
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.vault_path.with_suffix(self.vault_path.suffix + ".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(blob, f, indent=2)
        os.replace(temp_path, self.vault_path)
        try:
            os.chmod(self.vault_path, 0o600)
        except PermissionError:
            pass

    def list_entries(self):
        return sorted(self.entries, key=lambda x: (x["service"].lower(), x["username"].lower()))

    def add_entry(self, service: str, username: str, password: str, notes: str = "") -> None:
        for entry in self.entries:
            if entry["service"].lower() == service.lower() and entry["username"].lower() == username.lower():
                raise VaultError("Entry already exists for that service and username")
        self.entries.append({
            "id": secrets.token_hex(8),
            "service": service,
            "username": username,
            "password": password,
            "notes": notes,
            "created_at": utc_now(),
            "updated_at": utc_now(),
        })
        self._save()

    def get_entry(self, service: str, username: str | None = None):
        matches = [e for e in self.entries if e["service"].lower() == service.lower()]
        if username:
            matches = [e for e in matches if e["username"].lower() == username.lower()]
        return matches

    def delete_entry(self, service: str, username: str | None = None) -> int:
        before = len(self.entries)
        kept = []
        for entry in self.entries:
            service_match = entry["service"].lower() == service.lower()
            username_match = username is None or entry["username"].lower() == username.lower()
            if service_match and username_match:
                continue
            kept.append(entry)
        deleted = before - len(kept)
        if deleted == 0:
            raise VaultError("No matching entry found")
        self.entries = kept
        self._save()
        return deleted

    def search_entries(self, keyword: str):
        q = keyword.lower()
        results = []
        for entry in self.entries:
            haystack = " ".join([entry["service"], entry["username"], entry.get("notes", "")]).lower()
            if q in haystack:
                results.append(entry)
        return sorted(results, key=lambda x: (x["service"].lower(), x["username"].lower()))


def prompt_master(confirm: bool = False) -> str:
    master = getpass.getpass("Master password: ")
    if not master:
        raise VaultError("Master password cannot be empty")
    if confirm:
        again = getpass.getpass("Confirm master password: ")
        if master != again:
            raise VaultError("Master passwords do not match")
    return master



def prompt_password() -> str:
    pwd = getpass.getpass("Entry password: ")
    if not pwd:
        raise VaultError("Password cannot be empty")
    return pwd



def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/"
    return "".join(secrets.choice(alphabet) for _ in range(length))



def print_entries(entries, reveal: bool = False) -> None:
    if not entries:
        print("No entries found.")
        return
    for entry in entries:
        print(f"- Service   : {entry['service']}")
        print(f"  Username  : {entry['username']}")
        print(f"  Password  : {entry['password'] if reveal else '******** (use --reveal to show)'}")
        if entry.get("notes"):
            print(f"  Notes     : {entry['notes']}")
        print(f"  Created   : {entry['created_at']}")
        print(f"  Updated   : {entry['updated_at']}")
        print()



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Encrypted local password manager")
    parser.add_argument("--vault", default=str(DEFAULT_VAULT), help="Path to the encrypted vault file")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create a new encrypted vault")

    add_p = sub.add_parser("add", help="Add a new credential")
    add_p.add_argument("service")
    add_p.add_argument("username")
    add_p.add_argument("--password", help="Password value; omit to be prompted securely")
    add_p.add_argument("--notes", default="")
    add_p.add_argument("--generate", action="store_true", help="Generate a strong random password")
    add_p.add_argument("--length", type=int, default=24, help="Generated password length")

    get_p = sub.add_parser("get", help="Retrieve credentials")
    get_p.add_argument("service")
    get_p.add_argument("--username")
    get_p.add_argument("--reveal", action="store_true")

    del_p = sub.add_parser("delete", help="Delete credentials")
    del_p.add_argument("service")
    del_p.add_argument("--username")

    search_p = sub.add_parser("search", help="Search entries by keyword")
    search_p.add_argument("keyword")
    search_p.add_argument("--reveal", action="store_true")

    list_p = sub.add_parser("list", help="List stored entries")
    list_p.add_argument("--reveal", action="store_true")

    gen_p = sub.add_parser("generate", help="Generate a strong password")
    gen_p.add_argument("--length", type=int, default=24)

    return parser



def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    vault = PasswordVault(Path(args.vault))

    try:
        if args.command == "generate":
            print(generate_password(args.length))
            return 0

        if args.command == "init":
            master = prompt_master(confirm=True)
            vault.initialize(master)
            print(f"Vault created at {vault.vault_path}")
            return 0

        master = prompt_master(confirm=False)
        vault.unlock(master)

        if args.command == "add":
            entry_password = generate_password(args.length) if args.generate else (args.password or prompt_password())
            vault.add_entry(args.service, args.username, entry_password, args.notes)
            print("Entry added successfully.")
            if args.generate:
                print(f"Generated password: {entry_password}")
            return 0

        if args.command == "get":
            print_entries(vault.get_entry(args.service, args.username), reveal=args.reveal)
            return 0

        if args.command == "delete":
            deleted = vault.delete_entry(args.service, args.username)
            print(f"Deleted {deleted} entr{'y' if deleted == 1 else 'ies'}.")
            return 0

        if args.command == "search":
            print_entries(vault.search_entries(args.keyword), reveal=args.reveal)
            return 0

        if args.command == "list":
            print_entries(vault.list_entries(), reveal=args.reveal)
            return 0

        parser.print_help()
        return 1
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
