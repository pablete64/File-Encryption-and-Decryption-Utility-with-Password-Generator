import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

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

def decrypt_file(password, input_file):
    with open(input_file, 'rb') as f:
        salt = f.read(16)  # Leer la sal
        iv = f.read(12)    # Leer el IV
        tag = f.read(16)   # Leer el tag
        ciphertext = f.read()

    key = derive_key(password, salt)  # Derivar la clave usando la sal y la contraseña

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data

def select_input_file():
    global input_file_entry
    input_file = filedialog.askopenfilename(title="Select File to Decrypt")
    if input_file:
        input_file_entry.delete(0, tk.END)
        input_file_entry.insert(tk.END, input_file)

def decrypt():
    input_file = input_file_entry.get()
    password = password_entry.get()
    if not password:
        result_label.config(text="Please enter a password.")
        return

    decrypted_data = decrypt_file(password, input_file)
    
    # Escribir los datos desencriptados en un nuevo archivo
    output_file = f"{os.path.splitext(input_file)[0]}_desencriptado{os.path.splitext(input_file)[1]}"
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    result_label.config(text=f"File decrypted successfully and saved as:\n{output_file}")

# GUI setup
root = tk.Tk()
root.title("File Decryption")

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

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=2, column=1, padx=5, pady=5)

result_label = tk.Label(root, text="")
result_label.grid(row=3, column=0, columnspan=3, padx=5, pady=5)

root.mainloop()
