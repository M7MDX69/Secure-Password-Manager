import json
import os

from modules import dh_export
from modules import elgamal
from modules import signatures
from modules import vault


KEYS_DIR = "keys"
VAULTS_DIR = "vaults"
EXPORTS_DIR = "exports"


def ensure_directories():
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(VAULTS_DIR, exist_ok=True)
    os.makedirs(EXPORTS_DIR, exist_ok=True)


def private_key_path(username):
    return os.path.join(KEYS_DIR, f"{username}_private_key.json")


def public_key_path(username):
    return os.path.join(KEYS_DIR, f"{username}_public_key.json")


def vault_path(username):
    return os.path.join(VAULTS_DIR, f"{username}_vault.json")


def load_private_key(username):
    with open(private_key_path(username), "r", encoding="utf-8") as file:
        data = json.load(file)
    return int(data["private_key"])


def load_public_key(username):
    with open(public_key_path(username), "r", encoding="utf-8") as file:
        data = json.load(file)

    return {
        "username": data["username"],
        "p": int(data["p"]),
        "alpha": int(data["alpha"]),
        "public_key": int(data["public_key"])
    }


def user_exists(username):
    return (
        os.path.exists(private_key_path(username))
        and os.path.exists(public_key_path(username))
        and os.path.exists(vault_path(username))
    )


def require_user(username):
    if not user_exists(username):
        raise FileNotFoundError(
            f"User '{username}' is not initialized. Run setup first."
        )


def sign_user_vault(username):
    public_data = load_public_key(username)
    private_key = load_private_key(username)
    return signatures.sign_vault_file(
        vault_path(username),
        public_data["p"],
        public_data["alpha"],
        private_key
    )


def verify_user_vault(username):
    public_data = load_public_key(username)
    return signatures.verify_vault_file(
        vault_path(username),
        public_data["p"],
        public_data["alpha"],
        public_data["public_key"]
    )


def ask_master_password(confirm=False):
    password = input("Master password: ")
    if confirm:
        repeated = input("Confirm master password: ")
        if password != repeated:
            raise ValueError("Master passwords do not match")
    return password


def setup_user():
    username = input("Username: ").strip()
    if not username:
        print("[!] Username is required.")
        return

    if user_exists(username):
        print(f"[*] User '{username}' already exists. Setup skipped.")
        return

    p, alpha = elgamal.read_parameters()
    private_key = elgamal.generate_private_key(p)
    public_key = elgamal.generate_public_key(p, alpha, private_key)

    elgamal.save_private_key(username, private_key)
    elgamal.save_public_key(username, p, alpha, public_key)

    master_password = ask_master_password(confirm=True)
    vault.initialize_vault(vault_path(username), master_password)
    sign_user_vault(username)

    print(f"[*] Setup complete for '{username}'.")


def add_credential():
    username = input("Username: ").strip()
    require_user(username)

    if not verify_user_vault(username):
        print("[!] Vault signature is invalid. Operation aborted.")
        return

    master_password = ask_master_password()
    website = input("Website: ").strip()
    account_username = input("Account username: ").strip()
    account_password = input("Account password: ")

    vault.add_credential(
        vault_path(username),
        master_password,
        website,
        account_username,
        account_password
    )
    sign_user_vault(username)
    print("[*] Vault re-signed.")


def retrieve_credential():
    username = input("Username: ").strip()
    require_user(username)

    if not verify_user_vault(username):
        print("[!] Vault signature is invalid. Operation aborted.")
        return

    master_password = ask_master_password()
    website = input("Website: ").strip()
    matches = vault.retrieve_credential(vault_path(username), master_password, website)

    for item in matches:
        print(json.dumps(item, indent=2))


def update_credential():
    username = input("Username: ").strip()
    require_user(username)

    if not verify_user_vault(username):
        print("[!] Vault signature is invalid. Operation aborted.")
        return

    master_password = ask_master_password()
    website = input("Website to update: ").strip()
    new_username = input("New account username: ").strip()
    new_password = input("New account password: ")

    vault.update_credential(
        vault_path(username),
        master_password,
        website,
        new_username,
        new_password
    )
    sign_user_vault(username)
    print("[*] Vault re-signed.")


def delete_credential():
    username = input("Username: ").strip()
    require_user(username)

    if not verify_user_vault(username):
        print("[!] Vault signature is invalid. Operation aborted.")
        return

    master_password = ask_master_password()
    website = input("Website to delete: ").strip()

    vault.delete_credential(vault_path(username), master_password, website)
    sign_user_vault(username)
    print("[*] Vault re-signed.")


def list_websites():
    username = input("Username: ").strip()
    require_user(username)

    if not verify_user_vault(username):
        print("[!] Vault signature is invalid. Operation aborted.")
        return

    master_password = ask_master_password()
    websites = vault.list_websites(vault_path(username), master_password)

    if not websites:
        print("[*] Vault is empty.")
        return

    for website in websites:
        print("-", website)


def export_to_user():
    sender = input("Sender username: ").strip()
    receiver = input("Receiver username: ").strip()
    require_user(sender)
    require_user(receiver)

    if not verify_user_vault(sender):
        print("[!] Sender vault signature is invalid. Export aborted.")
        return

    sender_master_password = input("Sender master password: ")
    receiver_master_password = input("Receiver master password for imported vault: ")

    sender_public = load_public_key(sender)
    receiver_public = load_public_key(receiver)
    sender_private = load_private_key(sender)
    receiver_private = load_private_key(receiver)

    dh_parameters = dh_export.read_dh_parameters()
    q = dh_parameters["q"]
    dh_alpha = dh_parameters["alpha"]

    sender_dh_result = dh_export.create_signed_dh_key_exchange_message(
        q,
        dh_alpha,
        sender_public["p"],
        sender_public["alpha"],
        sender_private,
        sender
    )

    sender_dh_private = sender_dh_result["private_key"]
    sender_signed_dh = sender_dh_result["signed_message"]

    receiver_dh_result = dh_export.create_signed_dh_key_exchange_message(
        q,
        dh_alpha,
        receiver_public["p"],
        receiver_public["alpha"],
        receiver_private,
        receiver
    )

    receiver_dh_private = receiver_dh_result["private_key"]
    receiver_signed_dh = receiver_dh_result["signed_message"]

    if not dh_export.verify_signed_dh_public_key(
        sender_signed_dh,
        q,
        dh_alpha,
        sender_public["p"],
        sender_public["alpha"],
        sender_public["public_key"]
    ):
        print("[!] Sender signed DH public key is invalid. Export aborted.")
        return

    if not dh_export.verify_signed_dh_public_key(
        receiver_signed_dh,
        q,
        dh_alpha,
        receiver_public["p"],
        receiver_public["alpha"],
        receiver_public["public_key"]
    ):
        print("[!] Receiver signed DH public key is invalid. Export aborted.")
        return

    sender_vault_data = vault.load_vault(vault_path(sender))
    sender_data_key = vault.derive_key(sender_master_password)
    decrypted_sender_vault = vault.decrypt_vault(sender_vault_data, sender_data_key)

    receiver_dh_public = dh_export.get_dh_public_from_signed_message(receiver_signed_dh)
    sender_shared_secret = dh_export.generate_shared_secret(
        receiver_dh_public,
        sender_dh_private,
        q
    )
    sender_dh_public = dh_export.get_dh_public_from_signed_message(sender_signed_dh)

    export_package = dh_export.export_vault(
        decrypted_sender_vault,
        sender_shared_secret,
        sender_dh_public,
        sender_public["p"],
        sender_public["alpha"],
        sender_private
    )

    export_file = os.path.join(EXPORTS_DIR, f"{sender}_to_{receiver}_export_package.json")
    with open(export_file, "w", encoding="utf-8") as file:
        json.dump(export_package, file, indent=2)

    imported_vault = dh_export.import_vault(
        export_package,
        receiver_private_dh=receiver_dh_private,
        q=q,
        signature_p=sender_public["p"],
        signature_alpha=sender_public["alpha"],
        sender_public_key=sender_public["public_key"]
    )

    receiver_data_key = vault.derive_key(receiver_master_password)
    receiver_new_vault_data = vault.encrypt_vault(imported_vault, receiver_data_key)
    vault.save_vault(receiver_new_vault_data, vault_path(receiver))
    sign_user_vault(receiver)

    print(f"[*] Export package saved to '{export_file}'.")
    print(f"[*] Vault imported and re-signed for receiver '{receiver}'.")


def show_menu():
    print()
    print("Secure Password Manager")
    print("1. Setup new user")
    print("2. Add credential")
    print("3. Retrieve credential")
    print("4. Update credential")
    print("5. Delete credential")
    print("6. List websites")
    print("7. Export vault to another user")
    print("0. Exit")


def main():
    ensure_directories()

    actions = {
        "1": setup_user,
        "2": add_credential,
        "3": retrieve_credential,
        "4": update_credential,
        "5": delete_credential,
        "6": list_websites,
        "7": export_to_user
    }

    while True:
        show_menu()
        choice = input("Choose: ").strip()

        if choice == "0":
            print("Goodbye.")
            break

        action = actions.get(choice)
        if action is None:
            print("[!] Invalid choice.")
            continue

        try:
            action()
        except ValueError as error:
            print(f"[!] {error}")
        except FileNotFoundError as error:
            print(f"[!] {error}")
        except KeyError as error:
            print(f"[!] Missing data: {error}")


if __name__ == "__main__":
    main()
