import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64, os
from cryptography.fernet import Fernet
from PIL import Image, ImageTk
import re

# Generate AES key using Fernet
def generate_key():
    return Fernet.generate_key()

def validate_key_strength(key):
    if len(key) < 8:
        return "Weak"
    elif not re.search(r"[A-Z]", key) or not re.search(r"[0-9]", key):
        return "Medium"
    elif re.search(r"[A-Z]", key) and re.search(r"[0-9]", key) and re.search(r"[^A-Za-z0-9]", key):
        return "Strong"
    return "Medium"

def encrypt_image(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    enc_path = file_path + ".enc"
    with open(enc_path, "wb") as file:
        file.write(encrypted)
    return enc_path

def decrypt_image(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted = file.read()
    decrypted = fernet.decrypt(encrypted)
    dec_path = file_path.replace(".enc", "_decrypted.png")
    with open(dec_path, "wb") as file:
        file.write(decrypted)
    return dec_path

class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Encryptor")
        self.geometry("600x500")
        self.resizable(False, False)
        self.configure(bg="#2e2e2e")

        self.current_theme = "dark"
        self.style = ttk.Style(self)
        self.set_theme("dark")

        self.key = tk.StringVar()
        self.file_path = None

        self.create_widgets()

    def set_theme(self, mode):
        if mode == "dark":
            self.style.theme_use('clam')
            self.style.configure("TFrame", background="#2e2e2e")
            self.style.configure("TLabel", background="#2e2e2e", foreground="white")
            self.style.configure("TButton", background="#444", foreground="white")
            self.style.configure("TEntry", fieldbackground="#444", foreground="white")
        else:
            self.style.theme_use('clam')
            self.style.configure("TFrame", background="white")
            self.style.configure("TLabel", background="white", foreground="black")
            self.style.configure("TButton", background="#eee", foreground="black")
            self.style.configure("TEntry", fieldbackground="white", foreground="black")

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.set_theme(self.current_theme)

    def create_widgets(self):
        frm = ttk.Frame(self)
        frm.pack(pady=20, padx=20, fill="both", expand=True)

        ttk.Label(frm, text="Enter Encryption Key:").pack(anchor="w")
        entry = ttk.Entry(frm, textvariable=self.key, show="*")
        entry.pack(fill="x")

        self.strength_label = ttk.Label(frm, text="")
        self.strength_label.pack(anchor="w")

        entry.bind("<KeyRelease>", self.update_strength)

        ttk.Button(frm, text="Generate Key", command=self.set_generated_key).pack(pady=5)
        ttk.Button(frm, text="Choose Image", command=self.choose_file).pack(pady=5)
        ttk.Button(frm, text="Encrypt", command=self.encrypt).pack(pady=5)
        ttk.Button(frm, text="Decrypt", command=self.decrypt).pack(pady=5)

        ttk.Checkbutton(frm, text="Toggle Theme", command=self.toggle_theme).pack(pady=10)

        self.status_label = ttk.Label(frm, text="")
        self.status_label.pack(anchor="center")

    def update_strength(self, event=None):
        strength = validate_key_strength(self.key.get())
        self.strength_label.config(text=f"Key Strength: {strength}")

    def set_generated_key(self):
        gen_key = generate_key()
        self.key.set(gen_key.decode())
        self.update_strength()

    def choose_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg")])
        self.status_label.config(text=f"Selected: {os.path.basename(self.file_path)}")

    def encrypt(self):
        if not self.file_path or not self.key.get():
            messagebox.showerror("Error", "Please provide both image and key")
            return
        try:
            enc_path = encrypt_image(self.file_path, self.key.get().encode())
            messagebox.showinfo("Success", f"Encrypted as: {os.path.basename(enc_path)}")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt(self):
        if not self.file_path or not self.key.get():
            messagebox.showerror("Error", "Please provide both encrypted file and key")
            return
        try:
            dec_path = decrypt_image(self.file_path, self.key.get().encode())
            messagebox.showinfo("Success", f"Decrypted as: {os.path.basename(dec_path)}")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
