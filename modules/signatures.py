from hashlib import sha256
import json
import math
import os
import secrets


def _data_to_string(data):
    if isinstance(data, str):
        return data
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _vault_contents_to_sign(vault_data):
    return {
        "nonce": vault_data["nonce"],
        "ciphertext": vault_data["ciphertext"],
        "tag": vault_data["tag"]
    }


def generate_k(p):
    k = secrets.randbelow(p - 3) + 2
    while math.gcd(k, p - 1) != 1:
        k = secrets.randbelow(p - 3) + 2
    return k


def extended_euclidean(a, b):
    old_r, r = a, b
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    if old_r != 1:
        raise ValueError("Modular inverse does not exist")

    return old_s % b


def sign_message(message, p, alpha, x):
    message = _data_to_string(message)
    message_hash = sha256(message.encode("utf-8")).hexdigest()
    message_number = int(message_hash, 16)

    k = generate_k(p)
    k_inverse = extended_euclidean(k, p - 1)

    s1 = pow(alpha, k, p)
    s2 = ((message_number - x * s1) * k_inverse) % (p - 1)

    return {
        "S1": str(s1),
        "S2": str(s2)
    }


def verify_signature(message, signature, p, alpha, y):
    try:
        message = _data_to_string(message)
        s1 = int(signature["S1"])
        s2 = int(signature["S2"])
    except (KeyError, TypeError, ValueError):
        return False

    if not 0 < s1 < p:
        return False
    if not 0 <= s2 < p - 1:
        return False

    message_hash = sha256(message.encode("utf-8")).hexdigest()
    message_number = int(message_hash, 16)

    left_side = pow(alpha, message_number, p)
    right_side = (pow(y, s1, p) * pow(s1, s2, p)) % p
    return left_side == right_side


def sign_vault(username, encrypted_vault, p, alpha, x):
    vault = f"vaults/{username}_vault.json"
    signature = sign_message(encrypted_vault, p, alpha, x)

    if os.path.exists(vault):
        with open(vault, "r") as file:
            vault_data = json.load(file)
    else:
        vault_data = {}

    vault_data["encrypted_vault"] = encrypted_vault
    vault_data["signature"] = signature

    with open(vault, "w") as file:
        json.dump(vault_data, file, indent=4)

    print(f"[*] Success: Vault for '{username}' has been signed.")
    return signature


def verify_vault(username, encrypted_vault, p, alpha, y):
    vault = f"vaults/{username}_vault.json"

    try:
        with open(vault, "r") as file:
            vault_data = json.load(file)
        signature = vault_data["signature"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        print("[!] ERROR: No valid signature found. Vault is unverified.")
        return False

    if verify_signature(encrypted_vault, signature, p, alpha, y):
        print(f"[*] SUCCESS: Vault integrity verified for '{username}'.")
        return True

    print("[!] SECURITY WARNING: The vault digital signature is invalid.")
    return False


def sign_vault_file(vault_path, p, alpha, x):
    with open(vault_path, "r", encoding="utf-8") as file:
        vault_data = json.load(file)

    signature = sign_message(_vault_contents_to_sign(vault_data), p, alpha, x)
    vault_data["signature"] = signature

    with open(vault_path, "w", encoding="utf-8") as file:
        json.dump(vault_data, file, indent=2)

    return signature


def verify_vault_file(vault_path, p, alpha, y):
    try:
        with open(vault_path, "r", encoding="utf-8") as file:
            vault_data = json.load(file)

        signature = vault_data["signature"]
        signed_contents = _vault_contents_to_sign(vault_data)
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        return False

    return verify_signature(signed_contents, signature, p, alpha, y)

