import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15


class FileEncryptor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Encryption/Decryption Application")
        self.geometry("400x350")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10)

        self.aes_frame = tk.Frame(self.notebook)
        self.rsa_frame = tk.Frame(self.notebook)

        self.notebook.add(self.aes_frame, text="AES Encryption")
        self.notebook.add(self.rsa_frame, text="RSA Encryption")

        self.create_aes_widgets()
        self.create_rsa_widgets()
        self.signature_frame = tk.Frame(self.notebook)
        self.notebook.add(self.signature_frame, text="Digital Signature")
        self.create_signature_widgets()

    def get_file_path(self):
        file_path = filedialog.askopenfilename()
        return file_path

    def create_aes_widgets(self):
        self.aes_key_label = tk.Label(self.aes_frame, text="AES Key:")
        self.aes_key_label.pack()

        self.aes_key_entry = tk.Entry(self.aes_frame)
        self.aes_key_entry.pack()

        self.aes_generate_key_button = tk.Button(self.aes_frame, text="Generate AES Key", command=self.generate_aes_key)
        self.aes_generate_key_button.pack()

        self.aes_file_button = tk.Button(self.aes_frame, text="Choose AES Key File", command=self.choose_aes_key_file)
        self.aes_file_button.pack()

        self.aes_encrypt_button = tk.Button(self.aes_frame, text="Encrypt File (AES)", command=self.encrypt_aes)
        self.aes_encrypt_button.pack()

        self.aes_decrypt_button = tk.Button(self.aes_frame, text="Decrypt File (AES)", command=self.decrypt_aes)
        self.aes_decrypt_button.pack()

    def generate_aes_key(self):
        key = get_random_bytes(16)
        self.aes_key_entry.delete(0, tk.END)
        self.aes_key_entry.insert(tk.END, key.hex())

        with open("aes_key.pem", "wb") as aes_file:
            aes_file.write(key)

    def choose_aes_key_file(self):
        file_path = filedialog.askopenfilename(filetypes=(("AES Key Files", "*.pem"), ("All Files", "*.*")))
        if file_path:
            with open(file_path, "rb") as aes_file:
                key = aes_file.read()
                self.aes_key_entry.delete(0, tk.END)
                self.aes_key_entry.insert(tk.END, key.hex())

    def encrypt_aes(self):
        key = self.aes_key_entry.get().encode('utf-8')
        file_path = self.get_file_path()
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                    cipher = AES.new(key, AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(data)
                    encrypted_file_path = "encrypted_aes_" + os.path.basename(file_path)
                    with open(encrypted_file_path, 'wb') as encrypted_file:
                        encrypted_file.write(cipher.nonce)
                        encrypted_file.write(tag)
                        encrypted_file.write(ciphertext)
                    messagebox.showinfo("Encryption",
                                        f"File encrypted successfully! Decrypted file saved as '{encrypted_file_path}'")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def decrypt_aes(self):
        key = self.aes_key_entry.get().encode('utf-8')
        file_path = self.get_file_path()
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    nonce = file.read(16)
                    tag = file.read(16)
                    ciphertext = file.read()
                    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                    data = cipher.decrypt_and_verify(ciphertext, tag)
                    decrypted_file_path = "decrypted_aes_" + os.path.basename(file_path)
                    with open(decrypted_file_path, 'wb') as decrypted_file:
                        decrypted_file.write(data)
                    messagebox.showinfo("Decryption",
                                        f"File decrypted successfully! Decrypted file saved as '{decrypted_file_path}'")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def create_rsa_widgets(self):
        self.rsa_public_key_label = tk.Label(self.rsa_frame, text="RSA Public Key:")
        self.rsa_public_key_label.pack()

        self.rsa_public_key_entry = tk.Entry(self.rsa_frame)
        self.rsa_public_key_entry.pack()

        self.rsa_private_key_label = tk.Label(self.rsa_frame, text="RSA Private Key:")
        self.rsa_private_key_label.pack()

        self.rsa_private_key_entry = tk.Entry(self.rsa_frame)
        self.rsa_private_key_entry.pack()

        self.rsa_generate_key_button = tk.Button(self.rsa_frame, text="Generate RSA Keys",
                                                 command=self.generate_rsa_keys)
        self.rsa_generate_key_button.pack()

        self.rsa_public_key_button = tk.Button(self.rsa_frame, text="Choose RSA Public Key File",
                                               command=self.choose_rsa_public_key_file)
        self.rsa_public_key_button.pack()

        self.rsa_private_key_button = tk.Button(self.rsa_frame, text="Choose RSA Private Key File",
                                                command=self.choose_rsa_private_key_file)
        self.rsa_private_key_button.pack()

        self.rsa_encrypt_button = tk.Button(self.rsa_frame, text="Encrypt File (RSA)", command=self.encrypt_rsa)
        self.rsa_encrypt_button.pack()

        self.rsa_decrypt_button = tk.Button(self.rsa_frame, text="Decrypt File (RSA)", command=self.decrypt_rsa)
        self.rsa_decrypt_button.pack()

    def generate_rsa_keys(self):
        key = RSA.generate(4096)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        self.rsa_private_key_entry.delete(0, tk.END)
        self.rsa_private_key_entry.insert(tk.END, private_key.decode('utf-8'))

        self.rsa_public_key_entry.delete(0, tk.END)
        self.rsa_public_key_entry.insert(tk.END, public_key.decode('utf-8'))

        with open("rsa_public.pem", "wb") as rsa_public_file:
            rsa_public_file.write(public_key)

        with open("rsa_private.pem", "wb") as rsa_secret_file:
            rsa_secret_file.write(private_key)

    def choose_rsa_public_key_file(self):
        file_path = filedialog.askopenfilename(filetypes=(("RSA Public Key Files", "*.pem"), ("All Files", "*.*")))
        if file_path:
            with open(file_path, "rb") as rsa_public_file:
                public_key = rsa_public_file.read()
                self.rsa_public_key_entry.delete(0, tk.END)
                self.rsa_public_key_entry.insert(tk.END, public_key.decode('utf-8'))

    def choose_rsa_private_key_file(self):
        file_path = filedialog.askopenfilename(filetypes=(("RSA Private Key Files", "*.pem"), ("All Files", "*.*")))
        if file_path:
            with open(file_path, "rb") as rsa_private_file:
                private_key = rsa_private_file.read()
                self.rsa_private_key_entry.delete(0, tk.END)
                self.rsa_private_key_entry.insert(tk.END, private_key.decode('utf-8'))

    def encrypt_rsa(self):
        public_key_string = self.rsa_public_key_entry.get()
        file_path = self.get_file_path()
        if file_path and public_key_string:
            try:
                public_key = RSA.import_key(public_key_string)
                with open(file_path, 'rb') as file:
                    data = file.read()
                    cipher_rsa = PKCS1_OAEP.new(public_key)
                    encrypted_data = cipher_rsa.encrypt(data)
                    encrypted_file_path = "encrypted_rsa_" + os.path.basename(file_path)
                    with open(encrypted_file_path, 'wb') as encrypted_file:
                        encrypted_file.write(encrypted_data)
                    messagebox.showinfo("Encryption",
                                        f"File encrypted successfully! Encrypted file saved as '{encrypted_file_path}'")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def decrypt_rsa(self):
        private_key_str = self.rsa_private_key_entry.get()
        file_path = self.get_file_path()
        if file_path and private_key_str:
            try:
                private_key = RSA.import_key(private_key_str)
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                    cipher_rsa = PKCS1_OAEP.new(private_key)
                    decrypted_data = cipher_rsa.decrypt(encrypted_data)
                    decrypted_file_path = "decrypted_rsa_" + os.path.basename(file_path)
                    with open(decrypted_file_path, 'wb') as decrypted_file:
                        decrypted_file.write(decrypted_data)
                    messagebox.showinfo("Decryption",
                                        f"File decrypted successfully! Decrypted file saved as '{decrypted_file_path}'")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showwarning("Decryption", "Please provide the RSA private key and select a file to decrypt.")

    def create_signature_widgets(self):
        self.signature_private_key_label = tk.Label(self.signature_frame, text="Private Key for Signing:")
        self.signature_private_key_label.pack()

        self.signature_private_key_entry = tk.Entry(self.signature_frame)
        self.signature_private_key_entry.pack()

        self.signature_private_key_button = tk.Button(self.signature_frame, text="Choose Private Key File",
                                                      command=self.choose_private_key_file)
        self.signature_private_key_button.pack()

        self.signature_sign_button = tk.Button(self.signature_frame, text="Sign File", command=self.sign_file)
        self.signature_sign_button.pack()

        self.signature_public_key_label = tk.Label(self.signature_frame, text="Public Key for Verification:")
        self.signature_public_key_label.pack()

        self.signature_public_key_entry = tk.Entry(self.signature_frame)
        self.signature_public_key_entry.pack()

        self.signature_public_key_button = tk.Button(self.signature_frame, text="Choose Public Key File",
                                                     command=self.choose_public_key_file)
        self.signature_public_key_button.pack()

        self.signature_verify_button = tk.Button(self.signature_frame, text="Verify Signature",
                                                 command=self.verify_signature)
        self.signature_verify_button.pack()

    def choose_private_key_file(self):
        file_path = filedialog.askopenfilename(filetypes=(("RSA Private Key Files", "*.pem"), ("All Files", "*.*")))
        if file_path:
            with open(file_path, "rb") as private_key_file:
                private_key = private_key_file.read()
                self.signature_private_key_entry.delete(0, tk.END)
                self.signature_private_key_entry.insert(tk.END, private_key.decode('utf-8'))

    def choose_public_key_file(self):
        file_path = filedialog.askopenfilename(filetypes=(("RSA Public Key Files", "*.pem"), ("All Files", "*.*")))
        if file_path:
            with open(file_path, "rb") as public_key_file:
                public_key = public_key_file.read()
                self.signature_public_key_entry.delete(0, tk.END)
                self.signature_public_key_entry.insert(tk.END, public_key.decode('utf-8'))

    def sign_file(self):
        private_key_str = self.signature_private_key_entry.get()
        file_path = self.get_file_path()
        if file_path and private_key_str:
            try:
                private_key = RSA.import_key(private_key_str)
                with open(file_path, 'rb') as file:
                    data = file.read()
                    hash_value = SHA512.new(data)
                    signature = pkcs1_15.new(private_key).sign(hash_value)
                    signature_file_path = os.path.basename(file_path) + ".signature"
                    with open(signature_file_path, 'wb') as signature_file:
                        signature_file.write(signature)
                    messagebox.showinfo("Digital Signature",
                                        f"File signed successfully! Signature saved as '{signature_file_path}'")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showwarning("Digital Signature", "Please provide the private key and select a file to sign.")

    def verify_signature(self):
        public_key_str = self.signature_public_key_entry.get()
        if public_key_str:
            try:
                public_key = RSA.import_key(public_key_str)

                signature_file_path = filedialog.askopenfilename(
                    filetypes=(("Signature Files", "*.signature"), ("All Files", "*.*")))

                if signature_file_path:
                    with open(signature_file_path, 'rb') as signature_file:
                        signature = signature_file.read()

                    file_to_verify_path = filedialog.askopenfilename()

                    if file_to_verify_path:
                        with open(file_to_verify_path, 'rb') as file:
                            data = file.read()
                            hash_value = SHA512.new(data)

                        verifier = pkcs1_15.new(public_key)
                        verifier.verify(hash_value, signature)

                        messagebox.showinfo("Digital Signature", "Signature verification successful!")
                        return
            except ValueError as e:
                messagebox.showerror("Digital Signature", f"Signature verification failed: {str(e)}")
                return
            except Exception as e:
                messagebox.showerror("Digital Signature", f"Error during signature verification: {str(e)}")
                return

        messagebox.showwarning("Digital Signature",
                               "Please provide the public key and select a valid signature file and file to verify.")


if __name__ == "__main__":
    app = FileEncryptor()
    app.mainloop()
