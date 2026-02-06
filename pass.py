from cryptography.fernet import Fernet
import bcrypt
import os
import getpass
import time

# ---------- FILES ----------
PASSWORD_FILE = "passwords.txt"
MASTER_FILE = "master.hash"
KEY_FILE = "secret.key"

# ---------- KEY MANAGEMENT ----------

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

fernet = Fernet(load_key())

# ---------- AUTHENTICATION ----------

def authenticate():
    if not os.path.exists(MASTER_FILE):
        print("Master password not set")
        return False

    with open(MASTER_FILE, "rb") as f:
        stored_hash = f.read()

    attempts = 3
    while attempts > 0:
        attempt = getpass.getpass("Enter master password: ").encode()

        if bcrypt.checkpw(attempt, stored_hash):
            print("Access granted\n")
            return True
        else:
            attempts -= 1
            print(f"Wrong password. Attempts left: {attempts}")

    print("Too many failed attempts. Locked.")
    return False


def verify_master():
    with open(MASTER_FILE, "rb") as f:
        stored_hash = f.read()

    attempt = getpass.getpass("Re-enter master password: ").encode()
    return bcrypt.checkpw(attempt, stored_hash)

# ---------- ENCRYPTION ----------

def encode_password(password):
    return fernet.encrypt(password.encode()).decode()

def decode_password(encoded_password):
    return fernet.decrypt(encoded_password.encode()).decode()

# ---------- UTILITIES ----------

def site_exists(site_name):
    if not os.path.exists(PASSWORD_FILE):
        return False
    with open(PASSWORD_FILE, "r") as file:
        for line in file:
            site, _, _ = line.strip().split("|")
            if site.lower() == site_name.lower():
                return True
    return False

# ---------- FEATURES ----------

def add_password():
    site = input("Site name: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    if site_exists(site):
        print("Site already exists. Use update option.\n")
        return

    encoded = encode_password(password)

    with open(PASSWORD_FILE, "a") as file:
        file.write(f"{site}|{username}|{encoded}\n")

    print("Password saved successfully\n")


def view_password():
    site_name = input("Enter exact site name: ")

    confirm = input("Type SHOW to reveal password: ")
    if confirm != "SHOW":
        print("Cancelled\n")
        return

    if not verify_master():
        print("Authentication failed\n")
        return

    with open(PASSWORD_FILE, "r") as file:
        for line in file:
            site, username, encoded = line.strip().split("|")
            if site.lower() == site_name.lower():
                print(f"\nSite: {site}")
                print(f"Username: {username}")
                print(f"Password: {decode_password(encoded)}")
                time.sleep(5)
                print("\nPassword hidden\n")
                return

    print("Site not found\n")


def search_password():
    keyword = input("Search site: ").lower()

    if not os.path.exists(PASSWORD_FILE):
        print("No passwords saved\n")
        return

    found = False
    with open(PASSWORD_FILE, "r") as file:
        for line in file:
            site, username, _ = line.strip().split("|")
            if keyword in site.lower():
                print(f"Found: {site} | Username: {username}")
                found = True

    if not found:
        print("No matching sites found\n")


def update_password():
    site_name = input("Enter site to update: ")

    if not verify_master():
        print("Authentication failed\n")
        return

    updated = False
    lines = []

    with open(PASSWORD_FILE, "r") as file:
        for line in file:
            site, username, encoded = line.strip().split("|")
            if site.lower() == site_name.lower():
                new_password = getpass.getpass("New password: ")
                encoded = encode_password(new_password)
                updated = True
            lines.append(f"{site}|{username}|{encoded}\n")

    if updated:
        with open(PASSWORD_FILE, "w") as file:
            file.writelines(lines)
        print("Password updated successfully\n")
    else:
        print("Site not found\n")


def delete_password():
    site_name = input("Enter site to delete: ")

    if not verify_master():
        print("Authentication failed\n")
        return

    confirm = input(f"Type the site name again to confirm deletion ({site_name}): ")
    if confirm != site_name:
        print("Cancelled\n")
        return

    if not os.path.exists(PASSWORD_FILE):
        print("No passwords saved\n")
        return

    deleted = False
    lines = []

    with open(PASSWORD_FILE, "r") as file:
        for line in file:
            site, username, encoded = line.strip().split("|")
            if site.lower() == site_name.lower():
                deleted = True
                continue
            lines.append(line)

    if deleted:
        with open(PASSWORD_FILE, "w") as file:
            file.writelines(lines)
        print("Password deleted successfully\n")
    else:
        print("Site not found\n")

# ---------- MENU ----------

def menu():
    while True:
        print("1. Add Password")
        print("2. View Password")
        print("3. Search Password")
        print("4. Update Password")
        print("5. Delete Password")
        print("6. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            add_password()
        elif choice == "2":
            view_password()
        elif choice == "3":
            search_password()
        elif choice == "4":
            update_password()
        elif choice == "5":
            delete_password()
        elif choice == "6":
            print("Goodbye")
            break
        else:
            print("Invalid choice\n")

# ---------- RUN ----------

if authenticate():
    menu()
