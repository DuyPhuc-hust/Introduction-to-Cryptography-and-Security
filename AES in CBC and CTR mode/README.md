# AES CBC and CTR Decryption

This project demonstrates **AES decryption** using both **CBC (Cipher Block Chaining)** and **CTR (Counter)** modes in Python with the `pycryptodome` library.

---

## 📘 Overview

The script includes functions for:
- **PKCS#5 Unpadding**
- **CBC Mode Decryption**
- **CTR Mode Decryption**

It uses the AES algorithm with 128-bit keys and hex-encoded ciphertexts, following standard encryption formats where the first 16 bytes are used as the **IV** (for CBC) or **nonce** (for CTR).

---

## 🧩 Functions

### `pkcs5_unpad(data)`
Removes PKCS#5 padding from a decrypted plaintext.

### `cbc_decrypt(k, c)`
Performs AES-CBC decryption.
- `k`: hex-encoded AES key  
- `c`: hex-encoded ciphertext (includes IV at the beginning)

### `ctr_decrypt(k, c)`
Performs AES-CTR decryption.
- `k`: hex-encoded AES key  
- `c`: hex-encoded ciphertext (includes nonce at the beginning)

---

## ⚙️ How It Works

### CBC Mode
1. Extracts the first 16 bytes of ciphertext as the **IV**.
2. Decrypts the remaining ciphertext blocks using AES-CBC.
3. Removes PKCS#5 padding from the plaintext.

### CTR Mode
1. Extracts the first 16 bytes as the **nonce**.
2. Initializes a counter from that nonce.
3. Decrypts using AES-CTR mode without padding.

---

## ▶️ Running the Script

### 1. Install dependencies
```bash
pip install pycryptodome
```
### 2. Run the program
```bash
python3 aes_cbc_ctr.py
```
