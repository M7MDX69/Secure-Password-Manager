import customtkinter as ctk
from tkinter import messagebox
import json
import os

from modules import dh_export, elgamal, signatures, vault


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


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


def user_exists(username):
    return (
        os.path.exists(private_key_path(username))
        and os.path.exists(public_key_path(username))
        and os.path.exists(vault_path(username))
    )


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


def verify_user_vault(username):
    public_data = load_public_key(username)

    return signatures.verify_vault_file(
        vault_path(username),
        public_data["p"],
        public_data["alpha"],
        public_data["public_key"]
    )


def sign_user_vault(username):
    public_data = load_public_key(username)
    private_data = load_private_key(username)

    return signatures.sign_vault_file(
        vault_path(username),
        public_data["p"],
        public_data["alpha"],
        private_data
    )


class FormDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, fields):
        super().__init__(parent)

        self.title(title)
        self.geometry(f"400x{200 + len(fields) * 75}")
        self.resizable(False, False)

        self.result = None
        self.entries = {}

        self.update_idletasks()
        self.grab_set()

        for i, (label_text, is_password) in enumerate(fields):
            label = ctk.CTkLabel(
                self,
                text=label_text,
                font=("Roboto", 14)
            )
            label.pack(
                pady=(15 if i == 0 else 5, 0),
                padx=20,
                anchor="w"
            )

            entry = ctk.CTkEntry(
                self,
                show="*" if is_password else "",
                width=350,
                height=35
            )
            entry.pack(pady=5, padx=20)

            self.entries[label_text] = entry

        submit_btn = ctk.CTkButton(
            self,
            text="Submit",
            command=self.on_submit,
            width=200,
            height=45,
            font=("Roboto", 15, "bold")
        )
        submit_btn.pack(pady=30)

        parent.wait_window(self)

    def on_submit(self):
        self.result = {
            label: entry.get().strip()
            for label, entry in self.entries.items()
        }
        self.destroy()


class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Secure Password Manager")
        self.geometry("500x750")

        ensure_directories()

        title_label = ctk.CTkLabel(
            self,
            text="Secure Password Manager",
            font=("Roboto", 24, "bold")
        )
        title_label.pack(pady=30)

        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=40)

        buttons = [
            ("Setup New User", self.setup_user),
            ("Add Credential", self.add_credential),
            ("Retrieve Credential", self.retrieve_credential),
            ("Update Credential", self.update_credential),
            ("Delete Credential", self.delete_credential),
            ("List Websites", self.list_websites),
            ("Prepare Receiver Session", self.prepare_receiver_session),
            ("Export Vault Package", self.export_vault_package),
            ("Import Vault Package", self.import_vault_package)
        ]

        for text, command in buttons:
            btn = ctk.CTkButton(
                self.main_frame,
                text=text,
                command=command,
                height=45,
                font=("Roboto", 14)
            )
            btn.pack(pady=8, fill="x")

    def setup_user(self):
        dialog = FormDialog(
            self,
            "Setup New User",
            [
                ("Username", False),
                ("Master Password", True),
                ("Confirm Password", True)
            ]
        )

        if not dialog.result:
            return

        username = dialog.result["Username"]
        password = dialog.result["Master Password"]
        confirm_password = dialog.result["Confirm Password"]

        if not username or not password:
            messagebox.showwarning("Error", "All fields are required.")
            return

        if password != confirm_password:
            messagebox.showwarning("Error", "Passwords do not match.")
            return

        if user_exists(username):
            messagebox.showinfo("Info", f"User '{username}' already exists.")
            return

        try:
            p, alpha = elgamal.read_parameters()

            private_key = elgamal.generate_private_key(p)
            public_key = elgamal.generate_public_key(
                p,
                alpha,
                private_key
            )

            elgamal.save_private_key(
                username,
                p,
                alpha,
                private_key
            )

            elgamal.save_public_key(
                username,
                p,
                alpha,
                public_key
            )

            private_key_dict = load_private_key(username)

            vault.initialize_vault(
                vault_path(username),
                password,
                private_key_dict
            )

            messagebox.showinfo(
                "Success",
                f"Setup complete for '{username}'."
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def add_credential(self):
        dialog = FormDialog(
            self,
            "Add Credential",
            [
                ("Username", False),
                ("Master Password", True),
                ("Website", False),
                ("Account Username", False),
                ("Account Password", True)
            ]
        )

        if not dialog.result:
            return

        try:
            username = dialog.result["Username"]

            if not user_exists(username):
                raise FileNotFoundError("User not found. Run setup first.")

            if not verify_user_vault(username):
                raise ValueError("Vault signature is invalid.")

            vault.add_credential(
                vault_path(username),
                dialog.result["Master Password"],
                load_private_key(username),
                load_public_key(username),
                dialog.result["Website"],
                dialog.result["Account Username"],
                dialog.result["Account Password"]
            )

            messagebox.showinfo(
                "Success",
                f"Credential for {dialog.result['Website']} added."
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def retrieve_credential(self):
        dialog = FormDialog(
            self,
            "Retrieve Credential",
            [
                ("Username", False),
                ("Master Password", True),
                ("Website", False)
            ]
        )

        if not dialog.result:
            return

        try:
            username = dialog.result["Username"]

            if not user_exists(username):
                raise FileNotFoundError("User not found.")

            if not verify_user_vault(username):
                raise ValueError("Vault signature is invalid.")

            matches = vault.retrieve_credential(
                vault_path(username),
                dialog.result["Master Password"],
                load_public_key(username),
                dialog.result["Website"]
            )

            if not matches:
                messagebox.showinfo(
                    "Result",
                    "No credentials found for that website."
                )
                return

            result_text = "\n\n".join(
                [
                    f"Website: {item['website']}\n"
                    f"Username: {item['username']}\n"
                    f"Password: {item['password']}"
                    for item in matches
                ]
            )

            messagebox.showinfo("Credentials Found", result_text)

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def update_credential(self):
        dialog = FormDialog(
            self,
            "Update Credential",
            [
                ("Username", False),
                ("Master Password", True),
                ("Website", False),
                ("New Acc Username", False),
                ("New Acc Password", True)
            ]
        )

        if not dialog.result:
            return

        try:
            username = dialog.result["Username"]

            if not user_exists(username):
                raise FileNotFoundError("User not found.")

            if not verify_user_vault(username):
                raise ValueError("Vault signature is invalid.")

            vault.update_credential(
                vault_path(username),
                dialog.result["Master Password"],
                load_private_key(username),
                load_public_key(username),
                dialog.result["Website"],
                dialog.result["New Acc Username"],
                dialog.result["New Acc Password"]
            )

            messagebox.showinfo(
                "Success",
                f"Credential for {dialog.result['Website']} updated."
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def delete_credential(self):
        dialog = FormDialog(
            self,
            "Delete Credential",
            [
                ("Username", False),
                ("Master Password", True),
                ("Website to Delete", False)
            ]
        )

        if not dialog.result:
            return

        try:
            username = dialog.result["Username"]

            if not user_exists(username):
                raise FileNotFoundError("User not found.")

            if not verify_user_vault(username):
                raise ValueError("Vault signature is invalid.")

            vault.delete_credential(
                vault_path(username),
                dialog.result["Master Password"],
                load_private_key(username),
                load_public_key(username),
                dialog.result["Website to Delete"]
            )

            messagebox.showinfo(
                "Success",
                f"Credential for {dialog.result['Website to Delete']} deleted."
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def list_websites(self):
        dialog = FormDialog(
            self,
            "List Websites",
            [
                ("Username", False),
                ("Master Password", True)
            ]
        )

        if not dialog.result:
            return

        try:
            username = dialog.result["Username"]

            if not user_exists(username):
                raise FileNotFoundError("User not found.")

            if not verify_user_vault(username):
                raise ValueError("Vault signature is invalid.")

            websites = vault.list_websites(
                vault_path(username),
                dialog.result["Master Password"],
                load_public_key(username)
            )

            if not websites:
                messagebox.showinfo(
                    "Vault Contents",
                    "Vault is empty."
                )
                return

            messagebox.showinfo(
                "Vault Contents",
                "Websites in your vault:\n\n" + "\n".join(
                    f"- {website}" for website in websites
                )
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def prepare_receiver_session(self):
        dialog = FormDialog(
            self,
            "Prepare Receiver Session",
            [
                ("Sender Username", False),
                ("Receiver Username", False)
            ]
        )

        if not dialog.result:
            return

        try:
            sender = dialog.result["Sender Username"]
            receiver = dialog.result["Receiver Username"]

            if not user_exists(sender) or not user_exists(receiver):
                raise FileNotFoundError("Both users must be set up first.")

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
                receiver
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

            messagebox.showinfo(
                "Success",
                "Receiver session prepared successfully."
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def export_vault_package(self):
        dialog = FormDialog(
            self,
            "Export Vault Package",
            [
                ("Sender Username", False),
                ("Sender Master Password", True),
                ("Receiver Username", False)
            ]
        )

        if not dialog.result:
            return

        try:
            sender = dialog.result["Sender Username"]
            receiver = dialog.result["Receiver Username"]

            if not user_exists(sender) or not user_exists(receiver):
                raise FileNotFoundError("Both users must be set up first.")

            if not verify_user_vault(sender):
                raise ValueError("Sender vault signature is invalid.")

            receiver_signed_file = signed_dh_path(receiver, sender)

            if not os.path.exists(receiver_signed_file):
                raise FileNotFoundError(
                    "Receiver session was not prepared first."
                )

            sender_public = load_public_key(sender)
            sender_private = load_private_key(sender)
            receiver_public = load_public_key(receiver)

            dh_parameters = dh_export.read_dh_parameters()
            q = dh_parameters["q"]
            dh_alpha = dh_parameters["alpha"]

            receiver_signed_dh = load_json(receiver_signed_file)

            receiver_dh_is_valid = dh_export.verify_signed_dh_public_key(
                receiver_signed_dh,
                q,
                dh_alpha,
                receiver_public["p"],
                receiver_public["alpha"],
                receiver_public["public_key"]
            )

            if not receiver_dh_is_valid:
                raise ValueError("Receiver signed key is invalid.")

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

            sender_data_key = vault.derive_key(
                dialog.result["Sender Master Password"]
            )

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

            messagebox.showinfo(
                "Success",
                f"Export package saved:\n{export_file}"
            )

        except Exception as error:
            messagebox.showerror("Export Error", str(error))

    def import_vault_package(self):
        dialog = FormDialog(
            self,
            "Import Vault Package",
            [
                ("Sender Username", False),
                ("Receiver Username", False),
                ("Receiver Master Password", True)
            ]
        )

        if not dialog.result:
            return

        try:
            sender = dialog.result["Sender Username"]
            receiver = dialog.result["Receiver Username"]

            if not user_exists(sender) or not user_exists(receiver):
                raise FileNotFoundError("Both users must be set up first.")

            export_file = export_package_path(sender, receiver)
            receiver_private_file = dh_private_path(receiver, sender)

            if not os.path.exists(export_file):
                raise FileNotFoundError("Export package was not found.")

            if not os.path.exists(receiver_private_file):
                raise FileNotFoundError(
                    "Receiver session was not prepared first."
                )

            export_package = load_json(export_file)
            receiver_dh_private_data = load_json(receiver_private_file)

            q = receiver_dh_private_data["q"]
            dh_alpha = receiver_dh_private_data["alpha"]
            receiver_private_dh = receiver_dh_private_data["private_key"]

            sender_public = load_public_key(sender)

            sender_signed_dh = export_package.get("sender_signed_dh")

            if sender_signed_dh is None:
                raise ValueError("Sender signed key is missing.")

            sender_dh_is_valid = dh_export.verify_signed_dh_public_key(
                sender_signed_dh,
                q,
                dh_alpha,
                sender_public["p"],
                sender_public["alpha"],
                sender_public["public_key"]
            )

            if not sender_dh_is_valid:
                raise ValueError("Sender signed key is invalid.")

            imported_vault = dh_export.import_vault(
                export_package,
                receiver_private_dh=receiver_private_dh,
                q=q,
                signature_p=sender_public["p"],
                signature_alpha=sender_public["alpha"],
                sender_public_key=sender_public["public_key"]
            )

            receiver_data_key = vault.derive_key(
                dialog.result["Receiver Master Password"]
            )

            receiver_new_vault = vault.encrypt_vault(
                imported_vault,
                receiver_data_key
            )

            vault.save_vault(
                receiver_new_vault,
                vault_path(receiver)
            )

            sign_user_vault(receiver)

            messagebox.showinfo(
                "Success",
                f"Vault imported successfully for '{receiver}'."
            )

        except Exception as error:
            messagebox.showerror("Import Error", str(error))


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()