import base64
import json
import os
import secrets
import sys
from hashlib import sha256

from Crypto.Cipher import AES  # type: ignore

modules_folder = os.path.dirname(__file__)
sys.path.append(modules_folder)

from signatures import sign_message, verify_signature


def _message_to_sign(message_data):
    # sort_keys=True makes the JSON order stable before signing.
    message_text = json.dumps(message_data, sort_keys=True)
    return message_text


def read_dh_parameters(config_file="data/config.json"):
    if not os.path.exists(config_file):
        raise FileNotFoundError("Config file not found")

    with open(config_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    if "p" not in data or "alpha" not in data:
        raise KeyError("Missing DH parameters in config file")

    parameters = {
        "q": int(data["p"]),
        "alpha": int(data["alpha"])
    }
    return parameters


def generate_private_key(q):
    if q <= 4:
        raise ValueError("q is too small for Diffie-Hellman")

    private_key = secrets.randbelow(q - 3) + 2
    return private_key


def generate_dh_public_key(alpha, private_key, q):
    public_key = pow(alpha, private_key, q)
    return public_key


def generate_dh_key_pair(q, alpha):
    private_key = generate_private_key(q)
    public_key = generate_dh_public_key(alpha, private_key, q)

    key_pair = {
        "private_key": private_key,
        "public_key": public_key
    }
    return key_pair


def validate_dh_public_key(public_key, q):
    try:
        public_key = int(public_key)
    except (TypeError, ValueError):
        return False

    if public_key <= 1:
        return False

    if public_key >= q - 1:
        return False

    return True


def generate_shared_secret(other_public_key, private_key, q):
    if not validate_dh_public_key(other_public_key, q):
        raise ValueError("Invalid DH public key")

    other_public_key = int(other_public_key)
    shared_secret = pow(other_public_key, private_key, q)
    return shared_secret


def derive_session_key(shared_secret):
    shared_secret_text = str(shared_secret)
    shared_secret_bytes = shared_secret_text.encode("utf-8")
    session_key = sha256(shared_secret_bytes).digest()
    return session_key


def create_signed_dh_public_key(
    dh_public_key,
    q,
    dh_alpha,
    signature_p,
    signature_alpha,
    signer_private_key,
    sender_username=None
):
    if not validate_dh_public_key(dh_public_key, q):
        raise ValueError("Invalid DH public key")

    dh_message = {
        "type": "dh_public_key",
        "sender": sender_username,
        "q": str(q),
        "alpha": str(dh_alpha),
        "dh_public_key": str(dh_public_key)
    }

    message_text = _message_to_sign(dh_message)
    signature = sign_message(
        message_text,
        signature_p,
        signature_alpha,
        signer_private_key
    )

    signed_message = {
        "message": dh_message,
        "signature": signature
    }
    return signed_message


def verify_signed_dh_public_key(
    signed_dh_message,
    q,
    dh_alpha,
    signature_p,
    signature_alpha,
    signer_public_key
):
    try:
        dh_message = signed_dh_message["message"]
        signature = signed_dh_message["signature"]
    except (KeyError, TypeError):
        return False

    if dh_message.get("type") != "dh_public_key":
        return False

    if int(dh_message["q"]) != q:
        return False

    if int(dh_message["alpha"]) != dh_alpha:
        return False

    dh_public_key = dh_message["dh_public_key"]
    if not validate_dh_public_key(dh_public_key, q):
        return False

    message_text = _message_to_sign(dh_message)
    is_valid = verify_signature(
        message_text,
        signature,
        signature_p,
        signature_alpha,
        signer_public_key
    )
    return is_valid


def get_dh_public_from_signed_message(signed_dh_message):
    dh_public_key = signed_dh_message["message"]["dh_public_key"]
    return int(dh_public_key)


def create_signed_dh_key_exchange_message(
    q,
    dh_alpha,
    signature_p,
    signature_alpha,
    signer_private_key,
    sender_username=None
):
    dh_key_pair = generate_dh_key_pair(q, dh_alpha)
    dh_private_key = dh_key_pair["private_key"]
    dh_public_key = dh_key_pair["public_key"]

    signed_message = create_signed_dh_public_key(
        dh_public_key,
        q,
        dh_alpha,
        signature_p,
        signature_alpha,
        signer_private_key,
        sender_username
    )

    result = {
        "private_key": dh_private_key,
        "signed_message": signed_message
    }
    return result


def _to_base64(data_bytes):
    encoded_bytes = base64.b64encode(data_bytes)
    encoded_text = encoded_bytes.decode("utf-8")
    return encoded_text


def _from_base64(data_text):
    data_bytes = base64.b64decode(data_text)
    return data_bytes


def encrypt_with_session_key(vault_data, session_key):
    if len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes for AES-256")

    cipher = AES.new(session_key, AES.MODE_GCM)

    plaintext_text = json.dumps(vault_data)
    plaintext_bytes = plaintext_text.encode("utf-8")

    encryption_result = cipher.encrypt_and_digest(plaintext_bytes)
    ciphertext = encryption_result[0]
    tag = encryption_result[1]

    encrypted_package = {
        "nonce": _to_base64(cipher.nonce),
        "ciphertext": _to_base64(ciphertext),
        "tag": _to_base64(tag)
    }
    return encrypted_package


def decrypt_with_session_key(encrypted_package, session_key):
    if len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes for AES-256")

    nonce = _from_base64(encrypted_package["nonce"])
    ciphertext = _from_base64(encrypted_package["ciphertext"])
    tag = _from_base64(encrypted_package["tag"])

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)

    plaintext_text = plaintext_bytes.decode("utf-8")
    vault_data = json.loads(plaintext_text)
    return vault_data


def create_export_package(encrypted_vault, sender_dh_public, p, alpha, sender_private_key):
    export_content = {
        "sender_dh_public": str(sender_dh_public),
        "encrypted_vault": encrypted_vault
    }

    message_text = _message_to_sign(export_content)
    signature = sign_message(message_text, p, alpha, sender_private_key)

    export_package = {
        "sender_dh_public": str(sender_dh_public),
        "encrypted_vault": encrypted_vault,
        "signature": signature
    }
    return export_package


def verify_export_package(export_package, p, alpha, sender_public_key):
    try:
        sender_dh_public = export_package["sender_dh_public"]
        encrypted_vault = export_package["encrypted_vault"]
        signature = export_package["signature"]
    except (KeyError, TypeError):
        return False

    export_content = {
        "sender_dh_public": str(sender_dh_public),
        "encrypted_vault": encrypted_vault
    }

    message_text = _message_to_sign(export_content)
    is_valid = verify_signature(
        message_text,
        signature,
        p,
        alpha,
        sender_public_key
    )
    return is_valid


def export_vault(vault_data, shared_secret, sender_dh_public, p, alpha, sender_private_key):
    session_key = derive_session_key(shared_secret)
    encrypted_vault = encrypt_with_session_key(vault_data, session_key)

    export_package = create_export_package(
        encrypted_vault,
        sender_dh_public,
        p,
        alpha,
        sender_private_key
    )
    return export_package


def import_vault(
    export_package,
    receiver_private_dh=None,
    q=None,
    session_key=None,
    signature_p=None,
    signature_alpha=None,
    sender_public_key=None
):
    if sender_public_key is not None:
        if signature_p is None:
            raise ValueError("Signature p is required for verification")

        if signature_alpha is None:
            raise ValueError("Signature alpha is required for verification")

        signature_is_valid = verify_export_package(
            export_package,
            signature_p,
            signature_alpha,
            sender_public_key
        )

        if not signature_is_valid:
            raise ValueError("Invalid export signature. Import aborted.")

    if session_key is None:
        if receiver_private_dh is None:
            raise ValueError("Receiver DH private key is required")

        if q is None:
            raise ValueError("DH parameter q is required")

        sender_dh_public = int(export_package["sender_dh_public"])
        shared_secret = generate_shared_secret(
            sender_dh_public,
            receiver_private_dh,
            q
        )
        session_key = derive_session_key(shared_secret)

    encrypted_vault = export_package["encrypted_vault"]
    vault_data = decrypt_with_session_key(encrypted_vault, session_key)
    return vault_data


def save_export_package(username, export_package):
    os.makedirs("exports", exist_ok=True)

    filename = f"exports/{username}_export_package.json"
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(export_package, file, indent=4)

    print("Export package saved successfully")


def load_export_package(username):
    filename = f"exports/{username}_export_package.json"

    with open(filename, "r", encoding="utf-8") as file:
        export_package = json.load(file)

    return export_package


def _demo_module_4():
    project_root = os.path.dirname(os.path.dirname(__file__))
    config_file = os.path.join(project_root, "data", "config.json")

    dh_parameters = read_dh_parameters(config_file)
    q = dh_parameters["q"]
    dh_alpha = dh_parameters["alpha"]

    signature_p = q
    signature_alpha = dh_alpha

    alice_signature_private = 118
    alice_signature_public = pow(signature_alpha, alice_signature_private, signature_p)

    bob_signature_private = 77
    bob_signature_public = pow(signature_alpha, bob_signature_private, signature_p)

    alice_dh_result = create_signed_dh_key_exchange_message(
        q,
        dh_alpha,
        signature_p,
        signature_alpha,
        alice_signature_private,
        "alice"
    )

    alice_dh_private = alice_dh_result["private_key"]
    alice_signed_dh = alice_dh_result["signed_message"]

    bob_dh_result = create_signed_dh_key_exchange_message(
        q,
        dh_alpha,
        signature_p,
        signature_alpha,
        bob_signature_private,
        "bob"
    )

    bob_dh_private = bob_dh_result["private_key"]
    bob_signed_dh = bob_dh_result["signed_message"]

    alice_dh_is_valid = verify_signed_dh_public_key(
        alice_signed_dh,
        q,
        dh_alpha,
        signature_p,
        signature_alpha,
        alice_signature_public
    )

    bob_dh_is_valid = verify_signed_dh_public_key(
        bob_signed_dh,
        q,
        dh_alpha,
        signature_p,
        signature_alpha,
        bob_signature_public
    )

    if not alice_dh_is_valid:
        raise ValueError("Alice DH signature is invalid")

    if not bob_dh_is_valid:
        raise ValueError("Bob DH signature is invalid")

    alice_dh_public = get_dh_public_from_signed_message(alice_signed_dh)
    bob_dh_public = get_dh_public_from_signed_message(bob_signed_dh)

    alice_shared_secret = generate_shared_secret(
        bob_dh_public,
        alice_dh_private,
        q
    )

    bob_shared_secret = generate_shared_secret(
        alice_dh_public,
        bob_dh_private,
        q
    )

    if alice_shared_secret != bob_shared_secret:
        raise ValueError("DH shared secrets do not match")

    vault_data = {
        "gmail": {
            "username": "alice@example.com",
            "password": "demo-password"
        }
    }

    export_package = export_vault(
        vault_data,
        alice_shared_secret,
        alice_dh_public,
        signature_p,
        signature_alpha,
        alice_signature_private
    )

    imported_vault = import_vault(
        export_package,
        receiver_private_dh=bob_dh_private,
        q=q,
        signature_p=signature_p,
        signature_alpha=signature_alpha,
        sender_public_key=alice_signature_public
    )

    export_signature_is_valid = verify_export_package(
        export_package,
        signature_p,
        signature_alpha,
        alice_signature_public
    )

    print("[*] Module 4 demo started")
    print("[*] Alice signed DH public key verified:", alice_dh_is_valid)
    print("[*] Bob signed DH public key verified:", bob_dh_is_valid)
    shared_secret_matched = alice_shared_secret == bob_shared_secret
    print("[*] Shared secret matched:", shared_secret_matched)
    print("[*] Export package signature verified:", export_signature_is_valid)
    print("[*] Imported vault:")
    print(json.dumps(imported_vault, indent=4))


if __name__ == "__main__":
    _demo_module_4()
