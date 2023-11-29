from tkinter import *
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import binascii

# Generate an 8-byte (64-bit) random key
key = get_random_bytes(8)

def on_enter(event):
    event.widget['background'] = '#5CB85C'  # Warna latar belakang saat kursor masuk
    event.widget['foreground'] = 'white'  # Warna teks saat kursor masuk

def on_leave(event):
    event.widget['background'] = '#4CAF50'  # Warna latar belakang saat kursor keluar
    event.widget['foreground'] = 'black'  # Warna teks saat kursor keluar

def encrypt_message():
    message = entry.get()
    
    # Pesan harus memiliki panjang kelipatan 8
    while len(message) % 8 != 0:
        message += ' '  # Padding pesan dengan spasi jika diperlukan
    
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted = cipher.encrypt(message.encode('utf-8'))
    
    # Konversi byte menjadi string hexadecimal
    encrypted_hex = binascii.hexlify(encrypted).decode('utf-8')
    
    encrypted_entry.delete(0, END)
    encrypted_entry.insert(0, encrypted_hex)

def decrypt_message():
    encrypted_hex = encrypted_entry.get()
    
    # Konversi string hexadecimal kembali ke byte
    encrypted = binascii.unhexlify(encrypted_hex.encode('utf-8'))
    
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)
    
    # Hapus spasi ekstra (padding) dan kemudian dekode
    decrypted = decrypted.rstrip(b' ')
    
    decrypted_entry.delete(0, END)
    decrypted_entry.insert(0, decrypted.decode('utf-8'))

def clear_entry():
    entry.delete(0, END)
    encrypted_entry.delete(0, END)
    decrypted_entry.delete(0, END)

# Membuat GUI
root = Tk()
root.title("Enkripsi & Deskripsi DES")
root.configure(bg="#f2f2f2")

frame = Frame(root, bg="#ffffff", padx=20, pady=20)
frame.pack(padx=20, pady=20, expand=True)

label = Label(frame, text="Masukkan pesan:", font=("Arial", 12), bg="#ffffff")
label.grid(row=0, column=0, sticky="w")

entry = Entry(frame, font=("Arial", 12))
entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

encrypt_button = Button(frame, text="Enkripsi 🔒", command=encrypt_message, font=("Arial", 12), bg="#4CAF50", fg="black")
encrypt_button.grid(row=1, column=0, pady=10, sticky="w")
encrypt_button.bind("<Enter>", on_enter)
encrypt_button.bind("<Leave>", on_leave)

decrypt_button = Button(frame, text="Deskripsi 🔓", command=decrypt_message, font=("Arial", 12), bg="#4CAF50", fg="black")
decrypt_button.grid(row=1, column=1, pady=10, sticky="w")
decrypt_button.bind("<Enter>", on_enter)
decrypt_button.bind("<Leave>", on_leave)

clear_button = Button(frame, text="Hapus 🗑️", command=clear_entry, font=("Arial", 12), bg="#FF0000", fg="white")
clear_button.grid(row=1, column=2, pady=10, sticky="w")
clear_button.bind("<Enter>", on_enter)
clear_button.bind("<Leave>", on_leave)

result_label = Label(frame, text="Hasil Enkripsi (Hex):", font=("Arial", 12), bg="#ffffff")
result_label.grid(row=2, column=0, sticky="w")

encrypted_entry = Entry(frame, font=("Arial", 12))
encrypted_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")


decrypted_label = Label(frame, text="Hasil Deskripsi:", font=("Arial", 12), bg="#ffffff")
decrypted_label.grid(row=3, column=0, sticky="w")

decrypted_entry = Entry(frame, font=("Arial", 12))
decrypted_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

root.mainloop()
