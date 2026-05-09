"""
Module 2: Vault Encryption & Credential Management
"""

import os
import json
import base64
try:
    from modules.signatures import sign_vault, verify_vault
except ImportError:
    from signatures import sign_vault, verify_vault
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


# Key derivation

def derive_key(master_password: str) -> bytes:
    """
    Derive a 32-byte AES-256 key from the master password using SHA-256.

    AES-256 requires a key of exactly 32 bytes, and SHA-256 outputs exactly
    32 bytes, so the SHA-256 digest of the password is used directly as
    the AES key (the "data key").

    Args:
        master_password: The user's master password (any length).

    Returns:
        A 32-byte key suitable for AES-256.
    """
    return SHA256.new(master_password.encode('utf-8')).digest()


# Encryption / decryption of the credentials list

def encrypt_vault(credentials: list, key: bytes) -> dict:
    """
    Encrypt the credentials list using AES-GCM.

    A fresh random 12-byte nonce is generated for every encryption.
    NEVER reuse a nonce with the same key — doing so breaks GCM completely.

    Args:
        credentials: A list of credential dicts, e.g.
                     [{"website": "...", "username": "...", "password": "..."}]
        key: The 32-byte AES key from derive_key().

    Returns:
        A dict with base64-encoded "nonce", "ciphertext", and "tag" fields,
        ready to be saved as JSON.
    """
    # Serialize the credentials list to a JSON string, then to bytes.
    plaintext_bytes = json.dumps(credentials).encode('utf-8')

    # Generate a fresh, cryptographically random 12-byte nonce.
    nonce = os.urandom(12)

    # Create the AES-GCM cipher and encrypt + authenticate in one step.
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)

    # Base64-encode the binary fields so they can be stored inside JSON.
    return {
        "nonce":      base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag":        base64.b64encode(tag).decode('utf-8'),
    }


def decrypt_vault(vault_data: dict, key: bytes) -> list:
    """
    Decrypt a vault dict and return the credentials list.

    AES-GCM verifies the authentication tag during decryption. If the wrong
    key is used (i.e., wrong master password) OR the ciphertext was tampered
    with, decrypt_and_verify raises ValueError ("MAC check failed").

    Args:
        vault_data: A dict containing base64-encoded "nonce", "ciphertext", "tag".
        key: The 32-byte AES key from derive_key().

    Returns:
        The list of credential dicts.

    Raises:
        ValueError: If the master password is wrong or the data is corrupted.
    """
    # Decode the base64 fields back to raw bytes.
    nonce      = base64.b64decode(vault_data["nonce"])
    ciphertext = base64.b64decode(vault_data["ciphertext"])
    tag        = base64.b64decode(vault_data["tag"])

    # Recreate the cipher with the same key and nonce.
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # decrypt_and_verify raises ValueError if anything is wrong.
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)

    # Convert bytes -> JSON string -> Python list.
    return json.loads(plaintext_bytes.decode('utf-8'))


# Vault file I/O

def load_vault(vault_path: str) -> dict:
    """Read the JSON vault file from disk."""
    with open(vault_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_vault(vault_data: dict, vault_path: str) -> None:
    """Write the vault dict to disk as a pretty-printed JSON file."""
    with open(vault_path, 'w', encoding='utf-8') as f:
        json.dump(vault_data, f, indent=2)


def vault_exists(vault_path: str) -> bool:
    """Return True if a vault file exists at the given path."""
    return os.path.exists(vault_path)


# High-level operations: add / retrieve / update / delete
#
# Each operation follows the same pattern:
#   1. Derive the AES key from the master password.
#   2. Load the vault file from disk.
#   3. Decrypt it in memory to get the credentials list.
#   4. Modify the list (or read from it).
#   5. Re-encrypt the list and save it back.
#
# After each modification, Module 3 should be called to re-sign the vault.
# Before each read, Module 3 should be called to verify the signature.
# Those calls are done by the main CLI, not inside Module 2.

def initialize_vault(vault_path: str, master_password: str, private_key: dict) -> None:
    """
    Create a brand-new empty vault. Should be called once during setup.

    Args:
        vault_path: Where the vault file will be saved.
        master_password: The master password chosen by the user.
        private_key: ElGamal private key dict used to sign the vault.
    """
    if vault_exists(vault_path):
        raise FileExistsError(
            f"A vault already exists at '{vault_path}'. "
            "Refusing to overwrite it."
        )

    key = derive_key(master_password)
    vault_data = encrypt_vault([], key)   # empty list of credentials
    save_vault(sign_vault(vault_data, private_key), vault_path)
    print(f"New vault created at '{vault_path}'.")


def add_credential(vault_path: str, master_password: str, private_key: dict, public_key: dict,
                   website: str, username: str, password: str) -> None:
    """
    Add a new credential to the vault. Creates the vault if it doesn't exist.
    """
    key = derive_key(master_password)

    # Load existing credentials, or start with an empty list for a brand-new vault.
    if vault_exists(vault_path):
        vault_data  = load_vault(vault_path)
        if not verify_vault(vault_data, public_key):
            raise ValueError("Vault signature invalid — refusing to modify a tampered vault.")
        credentials = decrypt_vault(vault_data, key)
    else:
        credentials = []

    credentials.append({
        "website":  website,
        "username": username,
        "password": password,
    })

    new_vault_data = encrypt_vault(credentials, key)
    save_vault(sign_vault(new_vault_data, private_key), vault_path)
    print(f"Credential for '{website}' added successfully.")


def retrieve_credential(vault_path: str, master_password: str, public_key: dict,
                        website: str) -> list:
    """
    Retrieve all credentials matching the given website.

    Returns:
        A list of matching credential dicts (may be empty).
    """
    key = derive_key(master_password)
    vault_data  = load_vault(vault_path)
    if not verify_vault(vault_data, public_key):
        raise ValueError("Vault signature invalid — refusing to read a tampered vault.")
    credentials = decrypt_vault(vault_data, key)

    matches = [c for c in credentials if c["website"] == website]
    if not matches:
        print(f"No credentials found for '{website}'.")
    return matches


def list_websites(vault_path: str, master_password: str, public_key: dict) -> list:
    """
    Return the list of all websites stored in the vault (without passwords).
    Useful for showing the user what's in their vault.
    """
    key = derive_key(master_password)
    vault_data  = load_vault(vault_path)
    if not verify_vault(vault_data, public_key):
        raise ValueError("Vault signature invalid — refusing to read a tampered vault.")
    credentials = decrypt_vault(vault_data, key)
    return [c["website"] for c in credentials]


def update_credential(vault_path: str, master_password: str, private_key: dict, public_key: dict,
                      website: str,
                      new_username: str, new_password: str) -> None:
    """
    Update the username and password for a given website. Updates ALL entries
    matching the website (in case there are duplicates).
    """
    key = derive_key(master_password)
    vault_data  = load_vault(vault_path)
    if not verify_vault(vault_data, public_key):
        raise ValueError("Vault signature invalid — refusing to modify a tampered vault.")
    credentials = decrypt_vault(vault_data, key)

    updated_count = 0
    for c in credentials:
        if c["website"] == website:
            c["username"] = new_username
            c["password"] = new_password
            updated_count += 1

    if updated_count == 0:
        print(f"No credential found for '{website}'.")
        return

    new_vault_data = encrypt_vault(credentials, key)
    save_vault(sign_vault(new_vault_data, private_key), vault_path)
    print(f"Updated {updated_count} credential(s) for '{website}'.")


def delete_credential(vault_path: str, master_password: str, private_key: dict, public_key: dict,
                      website: str) -> None:
    """
    Delete all credentials matching the given website.
    """
    key = derive_key(master_password)
    vault_data  = load_vault(vault_path)
    if not verify_vault(vault_data, public_key):
        raise ValueError("Vault signature invalid — refusing to modify a tampered vault.")
    credentials = decrypt_vault(vault_data, key)

    new_credentials = [c for c in credentials if c["website"] != website]
    deleted_count   = len(credentials) - len(new_credentials)

    if deleted_count == 0:
        print(f"No credential found for '{website}'.")
        return

    new_vault_data = encrypt_vault(new_credentials, key)
    save_vault(sign_vault(new_vault_data, private_key), vault_path)
    print(f"Deleted {deleted_count} credential(s) for '{website}'.")


# Standalone test — runs only when this file is executed directly.

if __name__ == "__main__":
    VAULT  = "vault.json"
    PWD    = "my_master_password"
    PR_KEY = json.load(open("keys/test_user_private_key.json"))
    PU_KEY = json.load(open("keys/test_user_public_key.json"))

    # Clean up any leftover vault from a previous test run.
    if vault_exists(VAULT):
        os.remove(VAULT)

    print("=== Test 1: Create a new vault and add credentials ===")
    initialize_vault(VAULT, PWD, PR_KEY)
    add_credential(VAULT, PWD, PR_KEY, PU_KEY, "github.com",   "mazen",           "ghp_secret_token")
    add_credential(VAULT, PWD, PR_KEY, PU_KEY, "gmail.com",    "mazen@gmail.com", "MyGmailPwd!")
    add_credential(VAULT, PWD, PR_KEY, PU_KEY, "facebook.com", "mazen.fb",        "FbPassword123")

    print("\n=== Test 2: List all websites ===")
    print(list_websites(VAULT, PWD, PU_KEY))

    print("\n=== Test 3: Retrieve a credential ===")
    print(retrieve_credential(VAULT, PWD, PU_KEY, "github.com"))

    print("\n=== Test 4: Update a credential ===")
    update_credential(VAULT, PWD, PR_KEY, PU_KEY, "github.com", "mazen_new", "new_token_xyz")
    print(retrieve_credential(VAULT, PWD, PU_KEY, "github.com"))

    print("\n=== Test 5: Wrong password should be rejected ===")
    try:
        retrieve_credential(VAULT, PWD + "_wrong", PU_KEY, "github.com")
        print("FAIL: wrong password was accepted!")
    except ValueError as e:
        print(f"PASS: wrong password correctly rejected ({e})")

    print("\n=== Test 6: Delete a credential ===")
    delete_credential(VAULT, PWD, PR_KEY, PU_KEY, "gmail.com")
    print(list_websites(VAULT, PWD, PU_KEY))

    print("\n=== Test 7: Tampering with the vault should be detected ===")
    # Flip a single bit in the ciphertext to simulate tampering.
    vault_data = load_vault(VAULT)
    ct_bytes   = bytearray(base64.b64decode(vault_data["ciphertext"]))
    ct_bytes[0] ^= 0x01                                    # flip one bit
    vault_data["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode('utf-8')
    save_vault(vault_data, VAULT)

    try:
        retrieve_credential(VAULT, PWD, PU_KEY, "github.com")
        print("FAIL: tampered vault was accepted!")
    except ValueError as e:
        print(f"PASS: tampered vault correctly rejected ({e})")

    print("\n=== Test 8: Signature catches tampering before AES-GCM ===")
    # Restore a clean signed vault, flip a ciphertext byte WITHOUT re-signing,
    # then confirm the error comes from Module 3 (not AES-GCM).
    if vault_exists(VAULT):
        os.remove(VAULT)
    initialize_vault(VAULT, PWD, PR_KEY)
    add_credential(VAULT, PWD, PR_KEY, PU_KEY, "github.com", "mazen", "ghp_secret_token")

    vault_data = load_vault(VAULT)
    ct_bytes   = bytearray(base64.b64decode(vault_data["ciphertext"]))
    ct_bytes[0] ^= 0x01
    vault_data["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode('utf-8')
    save_vault(vault_data, VAULT)          # saved WITHOUT re-signing — signature now invalid

    try:
        retrieve_credential(VAULT, PWD, PU_KEY, "github.com")
        print("FAIL: tampered vault was accepted!")
    except ValueError as e:
        if "Vault signature invalid" in str(e):
            print(f"PASS: Module 3 caught tampering before AES-GCM ({e})")
        else:
            print(f"FAIL: wrong exception raised ({e})")

    print("\nAll tests complete.")
