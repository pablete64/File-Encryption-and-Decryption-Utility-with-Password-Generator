import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import base64

def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    # Derivar clave usando PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(password, input_file):
    base, ext = os.path.splitext(input_file)
    output_file = f"{base}_encriptado{ext}"
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    salt = os.urandom(16)  # Generar una sal aleatoria
    iv = os.urandom(12)    # Generar un IV aleatorio de 12 bytes (96 bits) para GCM
    
    key = derive_key(password, salt)  # Derivar la clave usando la sal y la contraseña

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    with open(output_file, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(tag)
        f.write(ciphertext)
    
    return output_file

def select_input_file():
    global input_file_entry
    input_file = filedialog.askopenfilename(title="Select File to Encrypt")
    if input_file:
        input_file_entry.delete(0, tk.END)
        input_file_entry.insert(tk.END, input_file)

def encrypt():
    input_file = input_file_entry.get()
    password = password_entry.get()
    if not password:
        result_label.config(text="Please enter a password.")
        return

    output_file = encrypt_file(password, input_file)
    result_label.config(text=f"File encrypted successfully and saved as:\n{output_file}")

# GUI setup
root = tk.Tk()
root.title("File Encryption")

input_file_label = tk.Label(root, text="Input File:")
input_file_label.grid(row=0, column=0, padx=5, pady=5)

input_file_entry = tk.Entry(root, width=50)
input_file_entry.grid(row=0, column=1, padx=5, pady=5)

input_file_button = tk.Button(root, text="Browse", command=select_input_file)
input_file_button.grid(row=0, column=2, padx=5, pady=5)

password_label = tk.Label(root, text="Password:")
password_label.grid(row=1, column=0, padx=5, pady=5)

password_entry = tk.Entry(root, show='*', width=50)
password_entry.grid(row=1, column=1, padx=5, pady=5)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=2, column=1, padx=5, pady=5)

result_label = tk.Label(root, text="")
result_label.grid(row=3, column=0, columnspan=3, padx=5, pady=5)

root.mainloop()
