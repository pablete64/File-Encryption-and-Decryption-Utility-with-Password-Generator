# File Encryption and Decryption Utility with Password Generator

This project provides a secure way to encrypt and decrypt files using AES encryption in GCM mode. It also includes a password generator to create strong passwords for file encryption. The program has a graphical user interface (GUI) built with Tkinter that allows users to easily select files, input passwords, and perform encryption or decryption tasks.

## Features:
- **Password Generator**: Generates strong passwords with a mix of uppercase, lowercase, digits, and special characters.
- **File Encryption**: Encrypts files using AES with a key derived from the password and a random salt.
- **File Decryption**: Decrypts encrypted files by reversing the encryption process.
- **GCM Mode**: Encryption is performed in GCM mode for authenticated encryption with additional data (AEAD).

## Requirements:
- Python 3.x
- Tkinter
- Cryptography library (Install via `pip install cryptography`)

## Installation:

1. Clone this repository to your local machine
2. Install the necessary dependencies
3. Run the application

## Usage:

### Password Generator:
1. When you run the password generator script, you will be prompted to enter the desired length of the password. The generated password will meet the following criteria:
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

### File Encryption:
1. Select the file you want to encrypt by clicking the "Browse" button.
2. Enter a password that will be used to encrypt the file.
3. Click the "Encrypt" button. The encrypted file will be saved with a `_encriptado` suffix in the same directory as the original file.

### File Decryption:
1. Select the encrypted file you want to decrypt by clicking the "Browse" button.
2. Enter the password used to encrypt the file.
3. Click the "Decrypt" button. The decrypted file will be saved with a `_desencriptado` suffix.

## Example:
- Encrypt a file: `document.txt` becomes `document_encriptado.txt`
- Decrypt a file: `document_encriptado.txt` becomes `document_desencriptado.txt`

## Acknowledgments:
- Cryptography library for secure encryption and decryption.
- Tkinter for building the graphical user interface.



