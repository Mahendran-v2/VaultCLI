import customtkinter as ctk
from tkinter import messagebox, ttk
import pyperclip
import threading
import time
import os
import bcrypt
from cryptography.fernet import Fernet

# ---------- YOUR ORIGINAL FILE LOGIC ----------
PASSWORD_FILE = "passwords.txt"
MASTER_FILE = "master.hash"
KEY_FILE = "secret.key"

# ---------- KEY MANAGEMENT ----------
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f: f.write(key)
    else:
        with open(KEY_FILE, "rb") as f: key = f.read()
    return key

# Initialize Fernet with your key
fernet = Fernet(load_key())

def encode_password(password):
    return fernet.encrypt(password.encode()).decode()

def decode_password(encoded_password):
    return fernet.decrypt(encoded_password.encode()).decode()

# ---------- THE GUI CLASS ----------
class ShieldPassUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ShieldPass - Vault")
        self.geometry("950x600")
        ctk.set_appearance_mode("dark")

        # Start by hiding the main window for authentication
        self.withdraw()
        self.login_ui()

    # --- AUTHENTICATION (Replaces your authenticate() function) ---
    def login_ui(self):
        self.login = ctk.CTkToplevel(self)
        self.login.geometry("350x250")
        self.login.title("Master Login")
        self.login.attributes("-topmost", True)

        ctk.CTkLabel(self.login, text="🔒 VAULT LOCKED", font=("Arial", 18, "bold")).pack(pady=20)
        self.master_input = ctk.CTkEntry(self.login, show="*", placeholder_text="Enter Master Password", width=200)
        self.master_input.pack(pady=10)

        ctk.CTkButton(self.login, text="Unlock", command=self.authenticate_gui).pack(pady=20)

    def authenticate_gui(self):
        if not os.path.exists(MASTER_FILE):
            messagebox.showerror("Error", "Master file missing. Please set up your master password.")
            return

        with open(MASTER_FILE, "rb") as f:
            stored_hash = f.read()
        
        attempt = self.master_input.get().encode()

        if bcrypt.checkpw(attempt, stored_hash):
            self.login.destroy()
            self.deiconify() # Reveal main window
            self.setup_main_ui()
            self.refresh_table()
        else:
            messagebox.showerror("Denied", "Incorrect Master Password")

    # --- MAIN INTERFACE ---
    def setup_main_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(self.sidebar, text="ShieldPass Pro", font=("Arial", 18, "bold")).pack(pady=30)
        
        ctk.CTkButton(self.sidebar, text="+ Add Account", command=self.add_account_ui).pack(pady=10, padx=20)
        ctk.CTkButton(self.sidebar, text="↻ Refresh List", command=self.refresh_table, fg_color="transparent", border_width=1).pack(pady=10, padx=20)
        ctk.CTkButton(self.sidebar, text="🗑 Delete Selected", fg_color="#e74c3c", hover_color="#c0392b", command=self.delete_selected).pack(side="bottom", pady=20, padx=20)

        # Main Area
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        # Table (Treeview)
        self.tree = ttk.Treeview(self.main_frame, columns=("Site", "User"), show="headings")
        self.tree.heading("Site", text="WEBSITE / SERVICE")
        self.tree.heading("User", text="USERNAME")
        self.tree.pack(fill="both", expand=True, padx=20, pady=20)

        # Bottom Bar for Copy Actions
        self.action_bar = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.action_bar.pack(fill="x", padx=20, pady=(0, 20))

        ctk.CTkButton(self.action_bar, text="Copy Username", width=150, command=lambda: self.copy_to_clip("user")).pack(side="left", padx=5)
        ctk.CTkButton(self.action_bar, text="Copy Password", width=150, fg_color="#2ecc71", hover_color="#27ae60", command=lambda: self.copy_to_clip("pass")).pack(side="left", padx=5)

    # --- FEATURES (Integrated Logic) ---
    def refresh_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "r") as f:
                for line in f:
                    if "|" in line:
                        site, user, _ = line.strip().split("|")
                        self.tree.insert("", "end", values=(site, user))

    def copy_to_clip(self, type):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Selection", "Please select an account from the list!")
            return

        item = self.tree.item(selected[0])
        site_name, user_name = item['values']

        if type == "user":
            pyperclip.copy(user_name)
            messagebox.showinfo("Copied", "Username copied to clipboard!")
        
        elif type == "pass":
            with open(PASSWORD_FILE, "r") as f:
                for line in f:
                    s, u, enc_p = line.strip().split("|")
                    if s == site_name and u == user_name:
                        decrypted = decode_password(enc_p)
                        pyperclip.copy(decrypted)
                        
                        # Security: Wipe clipboard after 20 seconds
                        threading.Thread(target=self.clear_clipboard_timer, daemon=True).start()
                        messagebox.showinfo("Security", "Password copied! Clipboard will be wiped in 20s.")
                        break

    def clear_clipboard_timer(self):
        time.sleep(20)
        pyperclip.copy("")
        print("Clipboard wiped.")

    def add_account_ui(self):
        # Uses CTkInputDialog to match your old input() flow
        site = ctk.CTkInputDialog(text="Site Name:", title="Add Account").get_input()
        if not site: return
        user = ctk.CTkInputDialog(text="Username:", title="Add Account").get_input()
        if not user: return
        pw = ctk.CTkInputDialog(text="Password:", title="Add Account").get_input()
        if not pw: return

        encoded = encode_password(pw)
        with open(PASSWORD_FILE, "a") as f:
            f.write(f"{site}|{user}|{encoded}\n")
        
        self.refresh_table()
        messagebox.showinfo("Success", f"Account for {site} saved!")

    def delete_selected(self):
        selected = self.tree.selection()
        if not selected: return

        item = self.tree.item(selected[0])
        site_name, user_name = item['values']

        # Confirmation popup
        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {site_name}?")
        if confirm:
            lines = []
            with open(PASSWORD_FILE, "r") as f:
                for line in f:
                    s, u, _ = line.strip().split("|")
                    if s == site_name and u == user_name:
                        continue
                    lines.append(line)
            
            with open(PASSWORD_FILE, "w") as f:
                f.writelines(lines)
            
            self.refresh_table()

if __name__ == "__main__":
    app = ShieldPassUI()
    app.mainloop()