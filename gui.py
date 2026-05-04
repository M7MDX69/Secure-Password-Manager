import customtkinter as ctk
from tkinter import messagebox
import json
import os

# Import your existing cryptography modules
from modules import dh_export, elgamal, signatures, vault

# Set the modern theme
ctk.set_appearance_mode("Dark")  # Options: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"

KEYS_DIR = "keys"
VAULTS_DIR = "vaults"
EXPORTS_DIR = "exports"

def ensure_directories():
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(VAULTS_DIR, exist_ok=True)
    os.makedirs(EXPORTS_DIR, exist_ok=True)

# --- Helper Functions (Reused from main.py) ---
def private_key_path(username): return os.path.join(KEYS_DIR, f"{username}_private_key.json")
def public_key_path(username): return os.path.join(KEYS_DIR, f"{username}_public_key.json")
def vault_path(username): return os.path.join(VAULTS_DIR, f"{username}_vault.json")

def user_exists(username):
    return os.path.exists(private_key_path(username)) and os.path.exists(public_key_path(username)) and os.path.exists(vault_path(username))

def load_private_key(username):
    with open(private_key_path(username), "r", encoding="utf-8") as file:
        data = json.load(file)
    return {"p": int(data["p"]), "alpha": int(data["alpha"]), "private_key": int(data["private_key"])}

def load_public_key(username):
    with open(public_key_path(username), "r", encoding="utf-8") as file:
        data = json.load(file)
    return {"username": data["username"], "p": int(data["p"]), "alpha": int(data["alpha"]), "public_key": int(data["public_key"])}

def verify_user_vault(username):
    public_data = load_public_key(username)
    return signatures.verify_vault_file(vault_path(username), public_data["p"], public_data["alpha"], public_data["public_key"])

# --- Custom Form Dialog for Inputs ---
class FormDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, fields):
        super().__init__(parent)
        self.title(title)
        # FIX: Increased the base height and multiplier so it doesn't clip!
        self.geometry(f"400x{200 + len(fields)*75}")
        self.resizable(False, False)
        self.result = None
        self.entries = {}

        # Center the window
        self.update_idletasks()
        self.grab_set()

        # Create input fields
        for i, (label_text, is_password) in enumerate(fields):
            label = ctk.CTkLabel(self, text=label_text, font=("Roboto", 14))
            label.pack(pady=(15 if i==0 else 5, 0), padx=20, anchor="w")
            
            entry = ctk.CTkEntry(self, show="*" if is_password else "", width=350, height=35)
            entry.pack(pady=5, padx=20)
            self.entries[label_text] = entry

        # FIX: Made the button wider and added more padding at the bottom
        submit_btn = ctk.CTkButton(self, text="Submit", command=self.on_submit, width=200, height=45, font=("Roboto", 15, "bold"))
        submit_btn.pack(pady=30)
        
        parent.wait_window(self)

    def on_submit(self):
        self.result = {label: entry.get().strip() for label, entry in self.entries.items()}
        self.destroy()

# --- Main Application Window ---
class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Password Manager")
        self.geometry("500x600")
        ensure_directories()

        # Title Label
        title_label = ctk.CTkLabel(self, text="🛡️ Secure Password Manager", font=("Roboto", 24, "bold"))
        title_label.pack(pady=30)

        # Main Frame for buttons
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=40)

        # Buttons for each action
        buttons = [
            ("Setup New User", self.setup_user),
            ("Add Credential", self.add_credential),
            ("Retrieve Credential", self.retrieve_credential),
            ("Update Credential", self.update_credential),
            ("Delete Credential", self.delete_credential),
            ("List Websites", self.list_websites),
            ("Export Vault to Another User", self.export_vault)
        ]

        for text, command in buttons:
            btn = ctk.CTkButton(self.main_frame, text=text, command=command, height=45, font=("Roboto", 14))
            btn.pack(pady=10, fill="x")

    # --- UI Actions ---
    def setup_user(self):
        dialog = FormDialog(self, "Setup New User", [("Username", False), ("Master Password", True), ("Confirm Password", True)])
        if not dialog.result: return

        username = dialog.result["Username"]
        pwd = dialog.result["Master Password"]
        conf_pwd = dialog.result["Confirm Password"]

        if not username or not pwd:
            messagebox.showwarning("Error", "All fields are required.")
            return
        if pwd != conf_pwd:
            messagebox.showwarning("Error", "Passwords do not match.")
            return
        if user_exists(username):
            messagebox.showinfo("Info", f"User '{username}' already exists.")
            return

        try:
            p, alpha = elgamal.read_parameters()
            priv_k = elgamal.generate_private_key(p)
            pub_k = elgamal.generate_public_key(p, alpha, priv_k)

            elgamal.save_private_key(username, p, alpha, priv_k)
            elgamal.save_public_key(username, p, alpha, pub_k)

            private_key_dict = load_private_key(username)
            vault.initialize_vault(vault_path(username), pwd, private_key_dict)
            messagebox.showinfo("Success", f"Setup complete for '{username}'.\nKeys and Vault created.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def add_credential(self):
        dialog = FormDialog(self, "Add Credential", [("Username", False), ("Master Password", True), ("Website", False), ("Account Username", False), ("Account Password", True)])
        if not dialog.result: return

        try:
            user = dialog.result["Username"]
            if not user_exists(user): raise FileNotFoundError("User not found. Run setup first.")
            if not verify_user_vault(user): raise ValueError("Vault signature is invalid. Tampering detected!")

            vault.add_credential(
                vault_path(user), dialog.result["Master Password"], 
                load_private_key(user), load_public_key(user),
                dialog.result["Website"], dialog.result["Account Username"], dialog.result["Account Password"]
            )
            messagebox.showinfo("Success", f"Credential for {dialog.result['Website']} added and vault signed.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def retrieve_credential(self):
        dialog = FormDialog(self, "Retrieve Credential", [("Username", False), ("Master Password", True), ("Website", False)])
        if not dialog.result: return

        try:
            user = dialog.result["Username"]
            if not user_exists(user): raise FileNotFoundError("User not found.")
            if not verify_user_vault(user): raise ValueError("Vault signature is invalid!")

            matches = vault.retrieve_credential(vault_path(user), dialog.result["Master Password"], load_public_key(user), dialog.result["Website"])
            
            if not matches:
                messagebox.showinfo("Result", "No credentials found for that website.")
            else:
                result_text = "\n\n".join([f"Website: {m['website']}\nUsername: {m['username']}\nPassword: {m['password']}" for m in matches])
                messagebox.showinfo("Credentials Found", result_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_credential(self):
        dialog = FormDialog(self, "Update Credential", [("Username", False), ("Master Password", True), ("Website", False), ("New Acc Username", False), ("New Acc Password", True)])
        if not dialog.result: return

        try:
            user = dialog.result["Username"]
            if not user_exists(user): raise FileNotFoundError("User not found.")
            if not verify_user_vault(user): raise ValueError("Vault signature is invalid!")

            vault.update_credential(
                vault_path(user), dialog.result["Master Password"], 
                load_private_key(user), load_public_key(user),
                dialog.result["Website"], dialog.result["New Acc Username"], dialog.result["New Acc Password"]
            )
            messagebox.showinfo("Success", f"Credential for {dialog.result['Website']} updated successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_credential(self):
        dialog = FormDialog(self, "Delete Credential", [("Username", False), ("Master Password", True), ("Website to Delete", False)])
        if not dialog.result: return

        try:
            user = dialog.result["Username"]
            if not user_exists(user): raise FileNotFoundError("User not found.")
            if not verify_user_vault(user): raise ValueError("Vault signature is invalid!")

            vault.delete_credential(vault_path(user), dialog.result["Master Password"], load_private_key(user), load_public_key(user), dialog.result["Website to Delete"])
            messagebox.showinfo("Success", f"Credential for {dialog.result['Website to Delete']} deleted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def list_websites(self):
        dialog = FormDialog(self, "List Websites", [("Username", False), ("Master Password", True)])
        if not dialog.result: return

        try:
            user = dialog.result["Username"]
            if not user_exists(user): raise FileNotFoundError("User not found.")
            if not verify_user_vault(user): raise ValueError("Vault signature is invalid!")

            websites = vault.list_websites(vault_path(user), dialog.result["Master Password"], load_public_key(user))
            
            if not websites:
                messagebox.showinfo("Vault Contents", "Vault is empty.")
            else:
                messagebox.showinfo("Vault Contents", "Websites in your vault:\n\n" + "\n".join(f"- {w}" for w in websites))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_vault(self):
        dialog = FormDialog(self, "Export Vault", [("Sender Username", False), ("Sender Master Password", True), ("Receiver Username", False), ("Receiver Master Password", True)])
        if not dialog.result: return
        
        try:
            sender = dialog.result["Sender Username"]
            receiver = dialog.result["Receiver Username"]
            if not user_exists(sender) or not user_exists(receiver): raise FileNotFoundError("Both users must be set up first.")
            if not verify_user_vault(sender): raise ValueError("Sender vault signature is invalid!")

            s_pub, r_pub = load_public_key(sender), load_public_key(receiver)
            s_priv, r_priv = load_private_key(sender), load_private_key(receiver)
            q, dh_alpha = dh_export.read_dh_parameters()["q"], dh_export.read_dh_parameters()["alpha"]

            s_dh_res = dh_export.create_signed_dh_key_exchange_message(q, dh_alpha, s_pub["p"], s_pub["alpha"], s_priv, sender)
            r_dh_res = dh_export.create_signed_dh_key_exchange_message(q, dh_alpha, r_pub["p"], r_pub["alpha"], r_priv, receiver)

            if not dh_export.verify_signed_dh_public_key(s_dh_res["signed_message"], q, dh_alpha, s_pub["p"], s_pub["alpha"], s_pub["public_key"]):
                raise ValueError("Sender DH key signature invalid.")
            if not dh_export.verify_signed_dh_public_key(r_dh_res["signed_message"], q, dh_alpha, r_pub["p"], r_pub["alpha"], r_pub["public_key"]):
                raise ValueError("Receiver DH key signature invalid.")

            s_vault_data = vault.load_vault(vault_path(sender))
            s_data_key = vault.derive_key(dialog.result["Sender Master Password"])
            decrypted_s_vault = vault.decrypt_vault(s_vault_data, s_data_key)

            s_dh_pub = dh_export.get_dh_public_from_signed_message(s_dh_res["signed_message"])
            r_dh_pub = dh_export.get_dh_public_from_signed_message(r_dh_res["signed_message"])
            s_shared_secret = dh_export.generate_shared_secret(r_dh_pub, s_dh_res["private_key"], q)

            pkg = dh_export.export_vault(decrypted_s_vault, s_shared_secret, s_dh_pub, s_pub["p"], s_pub["alpha"], s_priv)
            imported = dh_export.import_vault(pkg, receiver_private_dh=r_dh_res["private_key"], q=q, signature_p=s_pub["p"], signature_alpha=s_pub["alpha"], sender_public_key=s_pub["public_key"])

            r_data_key = vault.derive_key(dialog.result["Receiver Master Password"])
            r_new_vault = vault.encrypt_vault(imported, r_data_key)
            vault.save_vault(r_new_vault, vault_path(receiver))
            
            signatures.sign_vault_file(vault_path(receiver), r_pub["p"], r_pub["alpha"], r_priv)

            messagebox.showinfo("Success", f"Vault successfully exported from {sender} to {receiver}!")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()