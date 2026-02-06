# VaultCLI
A secure command-line password manager built with Python, using bcrypt for master authentication and Fernet encryption for password storage.

VaultCLI is a command-line based password manager written in Python.

It uses bcrypt to securely hash and verify the master password, ensuring that the master credential is never stored in plain text. All stored passwords are encrypted using Fernet symmetric encryption from the cryptography library.

The application supports adding, viewing, searching, updating, and deleting stored credentials, with sensitive actions protected by re-authentication. Encryption keys are generated and stored locally, and passwords are hidden automatically after display to reduce shoulder-surfing risks.

This project demonstrates core security concepts such as authentication, encryption, secure file handling, and defensive programming.
