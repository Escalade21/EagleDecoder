import tkinter as tk
from tkinter import messagebox
import base64
import numpy as np


# Şifre çözme fonksiyonları
def caesar_decrypt(ciphertext, shift):
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr(((ord(char) - ord('a') - shift_amount) % 26) + ord('a'))
            decrypted_text += new_char
        else:
            decrypted_text += char
    return decrypted_text


def vigenere_decrypt(ciphertext, key):
    decrypted_text = ""
    key_indices = [ord(k) - ord('a') for k in key]
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = key_indices[i % len(key)]
            decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            decrypted_text += decrypted_char
    return decrypted_text


def base64_decrypt(ciphertext):
    decrypted_text = base64.b64decode(ciphertext).decode('utf-8')
    return decrypted_text


def rot13_decrypt(ciphertext):
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            shift_amount = 13
            new_char = chr(((ord(char) - ord('a') + shift_amount) % 26) + ord('a'))
            decrypted_text += new_char
        else:
            decrypted_text += char
    return decrypted_text


def morse_decrypt(ciphertext):
    morse_code_dict = {
        '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
        '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
        '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
        '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
        '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
        '--..': 'z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
        '-----': '0', '--..--': ',', '.-.-.-': '.', '..--..': '?', '-.-.--': '!',
        '-....-': '-', '-..-.': '/', '.--.-.': '@', '-.--.': '(', '-.--.-': ')'
    }
    decrypted_text = ''.join(morse_code_dict[char] for char in ciphertext.split())
    return decrypted_text


def atbash_decrypt(ciphertext):
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            new_char = chr(ord('a') + (ord('z') - ord(char)))
            decrypted_text += new_char
        else:
            decrypted_text += char
    return decrypted_text


def affine_decrypt(ciphertext, a, b):
    decrypted_text = ""
    a_inv = pow(a, -1, 26)  # Inverse of a modulo 26
    for char in ciphertext:
        if char.isalpha():
            new_char = chr(((a_inv * (ord(char) - ord('a') - b)) % 26) + ord('a'))
            decrypted_text += new_char
        else:
            decrypted_text += char
    return decrypted_text


def bacon_decrypt(ciphertext):
    bacon_dict = {
        'AAAAA': 'a', 'AAAAB': 'b', 'AAABA': 'c', 'AAABB': 'd', 'AABAA': 'e',
        'AABAB': 'f', 'AABBA': 'g', 'AABBB': 'h', 'ABAAA': 'i', 'ABAAB': 'j',
        'ABABA': 'k', 'ABABB': 'l', 'ABBAA': 'm', 'ABBAB': 'n', 'ABBBA': 'o',
        'ABBBB': 'p', 'BAAAA': 'q', 'BAAAB': 'r', 'BAABA': 's', 'BAABB': 't',
        'BABAA': 'u', 'BABAB': 'v', 'BABBA': 'w', 'BABBB': 'x', 'BBAAA': 'y',
        'BBAAB': 'z'
    }
    decrypted_text = ''.join(bacon_dict[ciphertext[i:i + 5]] for i in range(0, len(ciphertext), 5))
    return decrypted_text


def hex_decrypt(ciphertext):
    decrypted_text = bytes.fromhex(ciphertext).decode('utf-8')
    return decrypted_text


def rail_fence_decrypt(ciphertext, key):
    rail = [['\n' for _ in range(len(ciphertext))] for _ in range(key)]
    dir_down = None
    row, col = 0, 0
    for i in range(len(ciphertext)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row = row + 1 if dir_down else row - 1
    index = 0
    for i in range(key):
        for j in range(len(ciphertext)):
            if rail[i][j] == '*' and index < len(ciphertext):
                rail[i][j] = ciphertext[index]
                index += 1
    result = []
    row, col = 0, 0
    for i in range(len(ciphertext)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        row = row + 1 if dir_down else row - 1
    return ''.join(result)


def columnar_trans_decrypt(ciphertext, key):
    key_indices = sorted(range(len(key)), key=lambda k: key[k])
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols
    grid = [''] * num_cols
    for i in range(num_cols):
        grid[key_indices[i]] = ciphertext[i * num_rows:(i + 1) * num_rows]
    decrypted_text = ''.join(''.join(row[i] for row in grid) for i in range(num_rows))
    return decrypted_text


def xor_decrypt(ciphertext, key):
    decrypted_text = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(ciphertext, key))
    return decrypted_text


def beaufort_decrypt(ciphertext, key):
    decrypted_text = ""
    key_indices = [ord(k) - ord('a') for k in key]
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = key_indices[i % len(key)]
            decrypted_char = chr((shift - (ord(char) - ord('a'))) % 26 + ord('a'))
            decrypted_text += decrypted_char
    return decrypted_text


def playfair_decrypt(ciphertext, key):
    key_square = [['' for _ in range(5)] for _ in range(5)]
    key = ''.join(sorted(set(key), key=key.index))  # Remove duplicates
    alphabet = "abcdefghiklmnopqrstuvwxyz"  # Note: 'j' is omitted in Playfair cipher
    key_index = 0
    used_chars = set()
    for char in key:
        if char not in used_chars:
            key_square[key_index // 5][key_index % 5] = char
            used_chars.add(char)
            key_index += 1
    for char in alphabet:
        if char not in used_chars:
            key_square[key_index // 5][key_index % 5] = char
            key_index += 1

    def find_position(char):
        for row in range(5):
            for col in range(5):
                if key_square[row][col] == char:
                    return row, col
        return None, None

    decrypted_text = ""
    i = 0
    while i < len(ciphertext):
        a, b = ciphertext[i], ciphertext[i + 1]
        row_a, col_a = find_position(a)
        row_b, col_b = find_position(b)
        if row_a == row_b:
            decrypted_text += key_square[row_a][(col_a - 1) % 5]
            decrypted_text += key_square[row_b][(col_b - 1) % 5]
        elif col_a == col_b:
            decrypted_text += key_square[(row_a - 1) % 5][col_a]
            decrypted_text += key_square[(row_b - 1) % 5][col_b]
        else:
            decrypted_text += key_square[row_a][col_b]
            decrypted_text += key_square[row_b][col_a]
        i += 2
    return decrypted_text


def autokey_decrypt(ciphertext, key):
    decrypted_text = ""
    key_indices = [ord(k) - ord('a') for k in key]
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = key_indices[i] if i < len(key) else ord(decrypted_text[i - len(key)]) - ord('a')
            decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            decrypted_text += decrypted_char
    return decrypted_text


def hill_decrypt(ciphertext, key_matrix):
    n = int(len(key_matrix) ** 0.5)
    key_matrix = np.array(key_matrix).reshape(n, n)
    det = int(round(np.linalg.det(key_matrix)))
    inv_det = pow(det, -1, 26)
    adjugate_matrix = np.array(
        [[key_matrix[(j + k) % n, (i + l) % n] for i in range(n)] for j, k, l in itertools.product(range(n), repeat=3)])
    adjugate_matrix = np.linalg.inv(key_matrix) * np.linalg.det(key_matrix)
    adjugate_matrix = np.round(adjugate_matrix).astype(int)
    adjugate_matrix = adjugate_matrix % 26
    inverse_matrix = (inv_det * adjugate_matrix) % 26
    ciphertext_matrix = np.array([ord(char) - ord('a') for char in ciphertext]).reshape(-1, n)
    decrypted_matrix = (ciphertext_matrix @ inverse_matrix) % 26
    decrypted_text = ''.join(chr(int(num) + ord('a')) for row in decrypted_matrix for num in row)
    return decrypted_text


def otp_decrypt(ciphertext, key):
    decrypted_text = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(ciphertext, key))
    return decrypted_text


# Şifreleme biçimi önerme fonksiyonu
def suggest_cipher_type(ciphertext):
    suggestions = []

    # Basit örneklemeler yapılarak öneriler oluşturuluyor
    if all(char in "01" for char in ciphertext):
        suggestions.append("Binary")
    if all(char in "0123456789abcdefABCDEF" for char in ciphertext):
        suggestions.append("Hex")
    if all(char in ".- " for char in ciphertext):
        suggestions.append("Morse Code")
    if all(char.isalpha() for char in ciphertext):
        suggestions.append("Caesar")
        suggestions.append("Vigenère")
        suggestions.append("ROT13")
        suggestions.append("Atbash")
        suggestions.append("Affine")
        suggestions.append("Bacon")
        suggestions.append("Rail Fence")
        suggestions.append("Columnar Transposition")
        suggestions.append("Beaufort")
        suggestions.append("Playfair")
        suggestions.append("Autokey")
        suggestions.append("Hill")
        suggestions.append("One-Time Pad")
    try:
        base64.b64decode(ciphertext).decode('utf-8')
        suggestions.append("Base64")
    except Exception:
        pass

    suggestions.append("XOR")

    if not suggestions:
        suggestions.append("Unsupported cipher type")

    return suggestions


def decrypt_message():
    ciphertext = entry_ciphertext.get()
    cipher_type = cipher_type_var.get()
    key = entry_key.get()
    decrypted_text = ""
    try:
        if cipher_type == "Caesar":
            shift = int(key) if key.isdigit() else 0
            decrypted_text = caesar_decrypt(ciphertext, shift)
        elif cipher_type == "Vigenère":
            decrypted_text = vigenere_decrypt(ciphertext, key)
        elif cipher_type == "Base64":
            decrypted_text = base64_decrypt(ciphertext)
        elif cipher_type == "ROT13":
            decrypted_text = rot13_decrypt(ciphertext)
        elif cipher_type == "Morse Code":
            decrypted_text = morse_decrypt(ciphertext)
        elif cipher_type == "Atbash":
            decrypted_text = atbash_decrypt(ciphertext)
        elif cipher_type == "Affine":
            a, b = map(int, key.split(","))
            decrypted_text = affine_decrypt(ciphertext, a, b)
        elif cipher_type == "Bacon":
            decrypted_text = bacon_decrypt(ciphertext)
        elif cipher_type == "Hex":
            decrypted_text = hex_decrypt(ciphertext)
        elif cipher_type == "Rail Fence":
            key = int(key) if key.isdigit() else 2
            decrypted_text = rail_fence_decrypt(ciphertext, key)
        elif cipher_type == "Columnar Transposition":
            decrypted_text = columnar_trans_decrypt(ciphertext, key)
        elif cipher_type == "XOR":
            decrypted_text = xor_decrypt(ciphertext, key)
        elif cipher_type == "Beaufort":
            decrypted_text = beaufort_decrypt(ciphertext, key)
        elif cipher_type == "Playfair":
            decrypted_text = playfair_decrypt(ciphertext, key)
        elif cipher_type == "Autokey":
            decrypted_text = autokey_decrypt(ciphertext, key)
        elif cipher_type == "Hill":
            key_matrix = list(map(int, key.split(',')))
            decrypted_text = hill_decrypt(ciphertext, key_matrix)
        elif cipher_type == "One-Time Pad":
            decrypted_text = otp_decrypt(ciphertext, key)
        else:
            decrypted_text = "Unsupported cipher type."
    except Exception as e:
        decrypted_text = f"Error: {str(e)}"
    messagebox.showinfo("Decrypted Text", decrypted_text)


def suggest_and_decrypt():
    ciphertext = entry_ciphertext.get()
    suggestions = suggest_cipher_type(ciphertext)
    suggested_cipher = suggestions[0]
    cipher_type_var.set(suggested_cipher)
    messagebox.showinfo("Suggested Cipher Type", f"Suggested Cipher Type: {suggested_cipher}")
    decrypt_message()


# GUI setup
root = tk.Tk()
root.title("CTF Cipher Decryptor")

label_ciphertext = tk.Label(root, text="Ciphertext:")
label_ciphertext.pack()

entry_ciphertext = tk.Entry(root, width=50)
entry_ciphertext.pack()

label_cipher_type = tk.Label(root, text="Cipher Type:")
label_cipher_type.pack()

cipher_type_var = tk.StringVar(value="Caesar")
cipher_type_menu = tk.OptionMenu(root, cipher_type_var, "Caesar", "Vigenère", "Base64", "ROT13", "Morse Code", "Atbash",
                                 "Affine", "Bacon", "Hex", "Rail Fence", "Columnar Transposition", "XOR", "Beaufort",
                                 "Playfair", "Autokey", "Hill", "One-Time Pad")
cipher_type_menu.pack()

label_key = tk.Label(root, text="Key:")
label_key.pack()

entry_key = tk.Entry(root, width=20)
entry_key.pack()

suggest_button = tk.Button(root, text="Suggest Cipher Type", command=suggest_and_decrypt)
suggest_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_message)
decrypt_button.pack()

label_footer = tk.Label(root, text="Yapanlar: Eagle Team", font=("Helvetica", 10, "italic"))
label_footer.pack(side=tk.BOTTOM, pady=10)

root.mainloop()
