# Secure Password Manager

Command-line password manager for the security course project.

It implements:
- AES-GCM vault encryption using a SHA-256 master-password key.
- ElGamal digital signatures from scratchV for integrity verification.
- Diffie-Hellman key exchange from scratch for secure vault export.
- A CLI workflow for setup, credential management, signing, verification, export, and import.

## Requirements

Install dependencies:

```powershell
py -m pip install -r requirement.txt
```

The only external crypto dependency is `pycryptodome`, used for AES-GCM. SHA-256 is imported from standard/allowed hash libraries. ElGamal signatures and Diffie-Hellman are implemented directly in the project.

## Run

From the project root:

```powershell
cd D:\secuirty\Secure-Password-Manager
py main.py
```

## CLI Workflow

Use the menu to:

1. Setup a new user
2. Add credential
3. Retrieve credential
4. Update credential
5. Delete credential
6. List websites
7. Export vault to another user

Every vault modification is followed by a new ElGamal signature. Every read/export operation verifies the vault signature before showing or exporting data.

## Module Summary

### Module 1: ElGamal Key Management

`modules/elgamal.py`

Reads `p` and `alpha` from `data/config.json`, generates an ElGamal private/public key pair, and saves:

- `keys/<username>_private_key.json`
- `keys/<username>_public_key.json`

### Module 2: Vault Encryption

`modules/vault.py`

Derives an AES-256 data key as:

```text
SHA-256(master_password)
```

The full credential list is encrypted with AES-GCM and stored in:

```text
vaults/<username>_vault.json
```

### Module 3: Digital Signatures

`modules/signatures.py`

Signs the encrypted vault fields:

```text
nonce, ciphertext, tag
```

The signature is stored inside the vault JSON. If the vault is edited manually, verification fails before decrypting credentials.

### Module 4: Secure Export with Diffie-Hellman

`modules/dh_export.py`

Each export session creates ephemeral DH keys. Both DH public keys are signed with long-term ElGamal keys. After both signatures are verified, both users derive the same AES-256 session key using SHA-256 of the shared secret.

The sender's decrypted vault data is encrypted with the session key, signed, verified by the receiver, decrypted, then re-encrypted with the receiver's master password and re-signed with the receiver's ElGamal private key.

Export packages are saved under:

```text
exports/
```

## Quick Checks

Compile all modules:

```powershell
py -m py_compile main.py modules\vault.py modules\signatures.py modules\dh_export.py modules\elgamal.py
```

Run the Module 4 standalone demo:

```powershell
cd modules
py dh_export.py
```
