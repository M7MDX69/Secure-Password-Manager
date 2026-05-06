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


def signed_dh_path(owner, peer):
    return os.path.join(EXPORTS_DIR, f"{owner}_signed_dh_for_{peer}.json")


def dh_private_path(owner, peer):
    return os.path.join(EXPORTS_DIR, f"{owner}_dh_private_for_{peer}.json")


def export_package_path(sender, receiver):
    return os.path.join(EXPORTS_DIR, f"{sender}_to_{receiver}_export_package.json")


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_private_key(username):
    with open(private_key_path(username), "r", encoding="utf-8") as file:
        data = json.load(file)

    return {
        "p": int(data["p"]),
        "alpha": int(data["alpha"]),
        "private_key": int(data["private_key"])
    }


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
        private_key["private_key"]
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

    elgamal.save_private_key(username, p, alpha, private_key)
    elgamal.save_public_key(username, p, alpha, public_key)

    master_password = ask_master_password(confirm=True)
    private_key_dict = load_private_key(username)

    vault.initialize_vault(
        vault_path(username),
        master_password,
        private_key_dict
    )

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

    private_key_dict = load_private_key(username)
    public_key_dict = load_public_key(username)

    vault.add_credential(
        vault_path(username),
        master_password,
        private_key_dict,
        public_key_dict,
        website,
        account_username,
        account_password
    )

    print("[*] Credential added and vault signed.")


def retrieve_credential():
    username = input("Username: ").strip()
    require_user(username)

    if not verify_user_vault(username):
        print("[!] Vault signature is invalid. Operation aborted.")
        return

    public_key_dict = load_public_key(username)
    master_password = ask_master_password()
    website = input("Website: ").strip()

    matches = vault.retrieve_credential(
        vault_path(username),
        master_password,
        public_key_dict,
        website
    )

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

    private_key_dict = load_private_key(username)
    public_key_dict = load_public_key(username)

    vault.update_credential(
        vault_path(username),
        master_password,
        private_key_dict,
        public_key_dict,
        website,
        new_username,
        new_password
    )

    print("[*] Credential updated and vault signed.")


def delete_credential():
    username = input("Username: ").strip()
    require_user(username)

    if not verify_user_vault(username):
        print("[!] Vault signature is invalid. Operation aborted.")
        return

    master_password = ask_master_password()
    website = input("Website to delete: ").strip()

    private_key_dict = load_private_key(username)
    public_key_dict = load_public_key(username)

    vault.delete_credential(
        vault_path(username),
        master_password,
        private_key_dict,
        public_key_dict,
        website
    )

    print("[*] Credential deleted and vault signed.")


def list_websites():
    username = input("Username: ").strip()
    require_user(username)

    if not verify_user_vault(username):
        print("[!] Vault signature is invalid. Operation aborted.")
        return

    public_key_dict = load_public_key(username)
    master_password = ask_master_password()

    websites = vault.list_websites(
        vault_path(username),
        master_password,
        public_key_dict
    )

    if not websites:
        print("[*] Vault is empty.")
        return

    for website in websites:
        print("-", website)


def prepare_receiver_dh_session():
    sender = input("Sender username: ").strip()
    receiver = input("Receiver username: ").strip()

    require_user(sender)
    require_user(receiver)

    receiver_public = load_public_key(receiver)
    receiver_private = load_private_key(receiver)

    dh_parameters = dh_export.read_dh_parameters()
    q = dh_parameters["q"]
    dh_alpha = dh_parameters["alpha"]

    receiver_dh_result = dh_export.create_signed_dh_key_exchange_message(
        q,
        dh_alpha,
        receiver_public["p"],
        receiver_public["alpha"],
        receiver_private["private_key"],
        receiver_private["private_key"],
        
    )

    receiver_dh_private_data = {
        "q": q,
        "alpha": dh_alpha,
        "private_key": receiver_dh_result["private_key"]
    }

    save_json(
        dh_private_path(receiver, sender),
        receiver_dh_private_data
    )

    save_json(
        signed_dh_path(receiver, sender),
        receiver_dh_result["signed_message"]
    )

    print("[*] Receiver DH session prepared.")
    print(f"[*] Receiver signed DH message saved to '{signed_dh_path(receiver, sender)}'.")
    print(f"[*] Receiver DH private key saved locally to '{dh_private_path(receiver, sender)}'.")


def export_vault_package():
    sender = input("Sender username: ").strip()
    receiver = input("Receiver username: ").strip()

    require_user(sender)
    require_user(receiver)

    if not verify_user_vault(sender):
        print("[!] Sender vault signature is invalid. Export aborted.")
        return

    receiver_signed_dh_file = signed_dh_path(receiver, sender)

    if not os.path.exists(receiver_signed_dh_file):
        print("[!] Receiver DH session was not prepared.")
        print("[!] Ask the receiver to run option 7 first.")
        return

    sender_master_password = input("Sender master password: ")

    sender_public = load_public_key(sender)
    sender_private = load_private_key(sender)
    receiver_public = load_public_key(receiver)

    dh_parameters = dh_export.read_dh_parameters()
    q = dh_parameters["q"]
    dh_alpha = dh_parameters["alpha"]

    receiver_signed_dh = load_json(receiver_signed_dh_file)

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

    sender_dh_result = dh_export.create_signed_dh_key_exchange_message(
        q,
        dh_alpha,
        sender_public["p"],
        sender_public["alpha"],
        sender_private["private_key"],
        sender
    )

    sender_dh_private = sender_dh_result["private_key"]
    sender_signed_dh = sender_dh_result["signed_message"]

    receiver_dh_public = dh_export.get_dh_public_from_signed_message(
        receiver_signed_dh
    )

    sender_shared_secret = dh_export.generate_shared_secret(
        receiver_dh_public,
        sender_dh_private,
        q
    )

    sender_vault_data = vault.load_vault(vault_path(sender))
    sender_data_key = vault.derive_key(sender_master_password)
    decrypted_sender_vault = vault.decrypt_vault(
        sender_vault_data,
        sender_data_key
    )

    sender_dh_public = dh_export.get_dh_public_from_signed_message(
        sender_signed_dh
    )

    export_package = dh_export.export_vault(
        decrypted_sender_vault,
        sender_shared_secret,
        sender_dh_public,
        sender_public["p"],
        sender_public["alpha"],
        sender_private["private_key"]
    )

    export_package["sender_username"] = sender
    export_package["receiver_username"] = receiver
    export_package["sender_signed_dh"] = sender_signed_dh
    export_package["receiver_signed_dh"] = receiver_signed_dh

    export_file = export_package_path(sender, receiver)
    save_json(export_file, export_package)

    print("[*] Export package created successfully.")
    print(f"[*] Export package saved to '{export_file}'.")
    print("[*] Send this package to the receiver.")


def import_vault_package():
    sender = input("Sender username: ").strip()
    receiver = input("Receiver username: ").strip()

    require_user(sender)
    require_user(receiver)

    export_file = export_package_path(sender, receiver)
    receiver_dh_private_file = dh_private_path(receiver, sender)

    if not os.path.exists(export_file):
        print("[!] Export package file was not found.")
        return

    if not os.path.exists(receiver_dh_private_file):
        print("[!] Receiver DH private key was not found.")
        print("[!] The receiver must prepare the DH session before import.")
        return

    export_package = load_json(export_file)
    receiver_dh_private_data = load_json(receiver_dh_private_file)

    q = receiver_dh_private_data["q"]
    dh_alpha = receiver_dh_private_data["alpha"]
    receiver_private_dh = receiver_dh_private_data["private_key"]

    sender_public = load_public_key(sender)

    sender_signed_dh = export_package.get("sender_signed_dh")

    if sender_signed_dh is None:
        print("[!] Sender signed DH message is missing. Import aborted.")
        return

    if not dh_export.verify_signed_dh_public_key(
        sender_signed_dh,
        q,
        dh_alpha,
        sender_public["p"],
        sender_public["alpha"],
        sender_public["public_key"]
    ):
        print("[!] Sender signed DH public key is invalid. Import aborted.")
        return

    imported_vault = dh_export.import_vault(
        export_package,
        receiver_private_dh=receiver_private_dh,
        q=q,
        signature_p=sender_public["p"],
        signature_alpha=sender_public["alpha"],
        sender_public_key=sender_public["public_key"]
    )

    receiver_master_password = input("Receiver master password for imported vault: ")

    receiver_data_key = vault.derive_key(receiver_master_password)
    receiver_new_vault_data = vault.encrypt_vault(
        imported_vault,
        receiver_data_key
    )

    vault.save_vault(receiver_new_vault_data, vault_path(receiver))
    sign_user_vault(receiver)

    print("[*] Vault imported successfully.")
    print(f"[*] Receiver vault was encrypted and signed for '{receiver}'.")


def show_menu():
    print()
    print("Secure Password Manager")
    print("1. Setup new user")
    print("2. Add credential")
    print("3. Retrieve credential")
    print("4. Update credential")
    print("5. Delete credential")
    print("6. List websites")
    print("7. Prepare receiver DH session")
    print("8. Export vault package")
    print("9. Import vault package")
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
        "7": prepare_receiver_dh_session,
        "8": export_vault_package,
        "9": import_vault_package
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