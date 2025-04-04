from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import pbkdf2_hmac
import os

# Create the main window
root = Tk()
root.title("Secure Image Encryptor")
root.geometry("400x300")

file_name = ""

def select_file():
    """ Opens file dialog to select an image. """
    global file_name
    # file = filedialog.askopenfile(mode='r', filetypes=[('JPG Files', '*.jpg')])
    file = filedialog.askopenfile(mode='r', filetypes=[('JPG Files', '*.jpg'), ('Encrypted Files', '*.enc'), ('All Files', '*.*')])

    if file:
        file_name = file.name
        file_label.config(text=f"Selected: {os.path.basename(file_name)}")

def derive_key(password: str, salt: bytes):
    """ Derives a strong key from the user password using PBKDF2. """
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

def encrypt_image():
    """ Encrypts the selected image using AES encryption. """
    global file_name
    if not file_name:
        messagebox.showerror("Error", "No file selected!")
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return

    try:
        with open(file_name, 'rb') as fi:
            image_data = fi.read()

        salt = get_random_bytes(16)  # Generate random salt
        key = derive_key(password, salt)  # Derive encryption key
        iv = get_random_bytes(16)  # Generate IV
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Padding to ensure image size is a multiple of 16 bytes
        pad_length = 16 - (len(image_data) % 16)
        image_data += bytes([pad_length]) * pad_length  # Append padding

        encrypted_data = cipher.encrypt(image_data)

        # Save encrypted file
        encrypted_file = file_name + ".enc"
        with open(encrypted_file, 'wb') as fo:
            fo.write(salt + iv + encrypted_data)  # Store salt and IV with encrypted data

        messagebox.showinfo("Success", f"Image encrypted successfully!\nSaved as: {os.path.basename(encrypted_file)}")
    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong: {str(e)}")

def decrypt_image():
    """ Decrypts an AES-encrypted image using the same password. """
    global file_name
    if not file_name or not file_name.endswith(".enc"):
        messagebox.showerror("Error", "Please select a valid encrypted (.enc) file!")
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return

    try:
        with open(file_name, 'rb') as fi:
            file_data = fi.read()

        salt = file_data[:16]  # Extract salt
        iv = file_data[16:32]  # Extract IV
        encrypted_data = file_data[32:]  # Encrypted image data

        key = derive_key(password, salt)  # Derive decryption key
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remove padding
        pad_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-pad_length]

        # Save decrypted file
        decrypted_file = file_name.replace(".enc", "_decrypted.jpg")
        with open(decrypted_file, 'wb') as fo:
            fo.write(decrypted_data)

        messagebox.showinfo("Success", f"Image decrypted successfully!\nSaved as: {os.path.basename(decrypted_file)}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# UI Elements
Label(root, text="Enter Password:").pack(pady=5)
password_entry = Entry(root, width=20, show="*")
password_entry.pack(pady=5)

file_label = Label(root, text="No file selected", fg="red")
file_label.pack()

Button(root, text="Select Image", command=select_file, bg="lightblue").pack(pady=5)
Button(root, text="Encrypt", command=encrypt_image, bg="lightgreen").pack(pady=5)
Button(root, text="Decrypt", command=decrypt_image, bg="orange").pack(pady=5)

root.mainloop()
