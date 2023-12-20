import tkinter as tk
import random

# Text Encryption & Decryption Functions
def text_to_bits(text):
    bits = ''.join(format(ord(char), '08b') for char in text)
    return bits

def bits_to_text(bits):
    text = ''.join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))
    return text

def bits_to_text_cipher(bits):
    custom_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    text = ''
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if chunk:
            index = int(chunk, 2) % len(custom_alphabet)
            text += custom_alphabet[index]
    return text

def generate_key(length):
    return ''.join(format(random.randint(0, 1), '01b') for _ in range(length))

def encrypt(plaintext, key):
    plaintext_bits = text_to_bits(plaintext)
    ciphertext_bits = ''.join(str(int(plain_bit) ^ int(key_bit)) for plain_bit, key_bit in zip(plaintext_bits, key))
    return ciphertext_bits

def decrypt(ciphertext_bits, key):
    decrypted_bits = ''.join(str(int(cipher_bit) ^ int(key_bit)) for cipher_bit, key_bit in zip(ciphertext_bits, key))
    decrypted_text = bits_to_text(decrypted_bits)
    return decrypted_text

# Binary (Bits) Encryption & Decryption Functions
def generate_random_key1(length1):
    return ''.join(random.choice("01") for _ in range(length1))

def encrypt1(plaintextbits1, keybits1):
    if len(plaintextbits1) != len(keybits1):
        return "Plaintext and key must have the same length."
    ciphertextbits1 = ""
    for i in range(len(plaintextbits1)):
        plaintext_bit1 = int(plaintextbits1[i])
        key_bit1 = int(keybits1[i])
        ciphertext_bit1 = plaintext_bit1 ^ key_bit1
        ciphertextbits1 += str(ciphertext_bit1)
    return ciphertextbits1

def decrypt1(ciphertextbits1, keybits1):
    if len(ciphertextbits1) != len(keybits1):
        return "Ciphertext and key must have the same length."
    decryptedbits1 = ""
    for i in range(len(ciphertextbits1)):
        ciphertext_bit1 = int(ciphertextbits1[i])
        key_bit1 = int(keybits1[i])
        plaintext_bit1 = ciphertext_bit1 ^ key_bit1
        decryptedbits1 += str(plaintext_bit1)
    return decryptedbits1

def is_binary1(text1):
    return all(bit in "01" for bit in text1)

# Creating a GUI window
root = tk.Tk()
root.title("Stream Cipher ")
root.geometry("400x570")
title_label = tk.Label(root, text="Stream Cipher", font=("Times New Roman", 20,'bold'))
title_label.pack(pady=15)

choice = tk.IntVar()
Font = ('Calibri', 14, 'bold')

# Text Form Encryption
def text_encryption():
    def clear_output():
        plaintext_text.set("")
        ciphertext_text1.set("")
        key_text1.set("")
        decrypted_text_text.set("")
        result_label_text.set("")

    def encrypt_text():
        plaintext = plaintext_text.get()
        key = generate_key(len(text_to_bits(plaintext)))
        ciphertext = encrypt(plaintext, key)
        ciphertext_text.set(bits_to_text(ciphertext))
        ciphertext_text1.set(bits_to_text_cipher(ciphertext))
        key_text.set(bits_to_text(key))
        key_text1.set(bits_to_text_cipher(key))
        result_label_text.set("Encryption completed")

    def decrypt_text():
        ciphertext = ciphertext_text.get()
        key = key_text.get()
        decrypted_text = decrypt(text_to_bits(ciphertext), text_to_bits(key))
        decrypted_text_text.set(decrypted_text)
        result_label_text.set("Decryption completed")

    frame = tk.Frame(root)
    frame.pack()

    plaintext_text = tk.StringVar()
    ciphertext_text = tk.StringVar()
    ciphertext_text1 = tk.StringVar()
    key_text = tk.StringVar()
    key_text1 = tk.StringVar()
    decrypted_text_text = tk.StringVar()
    result_label_text = tk.StringVar()

    enter_label = tk.Label(frame, text="Enter plaintext",font=('Arial', 10, 'bold'))
    enter_label.grid(row=0, column=0, columnspan=2)
    tk.Label(frame, text="Plaintext (Text):").grid(row=1, column=0)
    tk.Entry(frame, textvariable=plaintext_text).grid(row=1, column=1)
    tk.Label(frame, text="Ciphertext (Text):").grid(row=3, column=0)
    tk.Entry(frame, textvariable=ciphertext_text1).grid(row=3, column=1)
    tk.Label(frame, text="Key (Text):").grid(row=2, column=0)
    tk.Entry(frame, textvariable=key_text1).grid(row=2, column=1)
    tk.Label(frame, text="Decrypted Text (Text):").grid(row=4, column=0)
    tk.Entry(frame, textvariable=decrypted_text_text).grid(row=4, column=1)

    encrypt_button = tk.Button(frame, text="Encrypt (Text)", command=encrypt_text)
    encrypt_button.grid(row=5, column=0)
    decrypt_button = tk.Button(frame, text="Decrypt (Text)", command=decrypt_text)
    decrypt_button.grid(row=5, column=1)
    clear_button = tk.Button(frame, text="Clear", command=clear_output)
    clear_button.grid(row=6, column=0, columnspan=2)

    result_label = tk.Label(frame, textvariable=result_label_text)
    result_label.grid(row=7, column=0, columnspan=2)

# Binary (Bits) Form Encryption
def bits_encryption():
    def clear_output():
        plaintext_text1.set("")
        ciphertext_text1.set("")
        key_text1.set("")
        decrypted_text_text1.set("")

    def encrypt_callback1():
        plaintext1 = plaintext_text1.get()
        if not is_binary1(plaintext1):
            result_label.config(text="Plaintext must consist only of '0's and '1's.")
            return
        keybits1 = generate_random_key1(len(plaintext1))
        ciphertextbits1 = encrypt1(plaintext1, keybits1)
        ciphertext_text1.set(ciphertextbits1)
        key_text1.set(keybits1)
        result_label.config(text="Encryption completed")

    def decrypt_callback1():
        ciphertext1 = ciphertext_text1.get()
        key1 = key_text1.get()
        if not is_binary1(ciphertext1) or not is_binary1(key1):
            result_label.config(text="Ciphertext and key must consist only of '0's and '1's.")
            return
        decryptedbits1 = decrypt1(ciphertext1, key1)
        decrypted_text_text1.set(decryptedbits1)
        result_label.config(text="Decryption completed")

    frame = tk.Frame(root)
    frame.pack()

    plaintext_text1 = tk.StringVar()
    ciphertext_text1 = tk.StringVar()
    key_text1 = tk.StringVar()
    decrypted_text_text1 = tk.StringVar()

    enter_label = tk.Label(frame, text="Enter plaintext",font=('Arial', 10, 'bold'))
    enter_label.grid(row=0, column=0, columnspan=2)
    tk.Label(frame, text="Plaintext (Binary):").grid(row=1, column=0)
    tk.Entry(frame, textvariable=plaintext_text1).grid(row=1, column=1)
    tk.Label(frame, text="Ciphertext (Binary):").grid(row=3, column=0)
    tk.Entry(frame, textvariable=ciphertext_text1).grid(row=3, column=1)
    tk.Label(frame, text="Key (Binary):").grid(row=2, column=0)
    tk.Entry(frame, textvariable=key_text1).grid(row=2, column=1)
    tk.Label(frame, text="Decrypted Text (Binary):").grid(row=4, column=0)
    tk.Entry(frame, textvariable=decrypted_text_text1).grid(row=4, column=1)

    encrypt_button1 = tk.Button(frame, text="Encrypt (Binary)", command=encrypt_callback1)
    encrypt_button1.grid(row=5, column=0)
    decrypt_button1 = tk.Button(frame, text="Decrypt (Binary)", command=decrypt_callback1)
    decrypt_button1.grid(row=5, column=1)
    clear_button1 = tk.Button(frame, text="Clear", command=clear_output)
    clear_button1.grid(row=6, column=0, columnspan=2)

    result_label = tk.Label(frame, text="")
    result_label.grid(row=7, column=0, columnspan=2)

# Create buttons for switching between text and binary forms
textButton = tk.Button(root, text='Text Form', font=Font, command=text_encryption)
textButton.pack(pady=15)

bitsButton = tk.Button(root, text='Bits Form', font=Font, command=bits_encryption)
bitsButton.pack(pady=15)

root.mainloop()