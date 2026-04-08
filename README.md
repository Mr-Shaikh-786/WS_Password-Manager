# WS_Password Manager

A secure local password manager written in Python that stores credentials encrypted on disk using symmetric authenticated encryption. The vault uses a master password, derives an encryption key with Argon2id, and stores entries inside an encrypted JSON-based file format.

## Features

- Master-password protected vault
- Encrypted local storage on disk
- Argon2id-based key derivation with random salt
- Symmetric authenticated encryption with Fernet
- Add, retrieve, list, search, and delete credential entries
- Optional strong password generation
- File permissions tightened to owner-only where supported
- Simple CLI interface for local use

## Security design

- **Key derivation:** The master password is never stored directly. A 32-byte encryption key is derived from the master password using **Argon2id** with a random 16-byte salt.
- **Encryption:** Vault contents are encrypted using **Fernet**, which provides authenticated symmetric encryption and tamper detection.
- **Storage format:** The vault file contains metadata such as KDF settings and salt, plus one encrypted ciphertext blob containing the JSON entry list.
- **Permissions:** The vault file is written atomically and permissions are set to `0600` when possible.

## Project structure

```text
WS_Password-Manager/
├── password_manager.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- pip

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

By default, the vault is stored at:

```bash
~/.WS_Password_vault.json
```

You can also specify a custom vault path with `--vault`.

### 1. Initialize a new vault

```bash
python3 password_manager.py init
```

You will be prompted to set and confirm a master password.

### 2. Add a credential

Prompt securely for the entry password:

```bash
python3 password_manager.py add github alice
```

Add with an inline password:

```bash
python3 password_manager.py add github alice --password "MyStrongPassword@123"
```

Generate a strong password automatically:

```bash
python3 password_manager.py add github alice --generate --length 24 --notes "Personal account"
```

### 3. Retrieve a credential

```bash
python3 password_manager.py get github --username alice --reveal
```

### 4. Search entries

```bash
python3 password_manager.py search git --reveal
```

### 5. List all entries

```bash
python3 password_manager.py list
```

### 6. Delete an entry

```bash
python3 password_manager.py delete github --username alice
```

### 7. Generate a standalone password

```bash
python3 password_manager.py generate --length 32
```

## Example vault format

The file on disk remains encrypted. A simplified example looks like this:

```json
{
  "meta": {
    "app": "WS_Password Manager",
    "version": 1,
    "created_at": "2026-04-08T00:00:00+00:00",
    "updated_at": "2026-04-08T00:00:00+00:00",
    "kdf": {
      "name": "argon2id",
      "version": 1,
      "salt": "base64-url-salt",
      "time_cost": 3,
      "memory_cost": 65536,
      "parallelism": 4,
      "hash_len": 32
    }
  },
  "ciphertext": "gAAAAAB...encrypted-fernet-token..."
}
```


## Notes

- Keep your master password strong and memorable.
- If you lose the master password, the vault cannot be decrypted.

---
