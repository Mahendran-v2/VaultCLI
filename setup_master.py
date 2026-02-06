import bcrypt
import getpass

password = getpass.getpass("Set master password: ").encode()

hashed = bcrypt.hashpw(password, bcrypt.gensalt())

with open("master.hash", "wb") as f:
    f.write(hashed)

print("Master password set successfully")
