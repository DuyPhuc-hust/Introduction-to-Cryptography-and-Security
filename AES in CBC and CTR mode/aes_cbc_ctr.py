from Crypto.Cipher import AES
from Crypto.Util import Counter

# PKCS5 Unpadding
def pkcs5_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# CBC Decryption 
def cbc_decrypt(k, c):
    key = bytes.fromhex(k)
    ciphertext = bytes.fromhex(c)
    iv = ciphertext[:AES.block_size]
    enc_msg = ciphertext[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(enc_msg)
    plaintext = pkcs5_unpad(plaintext_padded)
    return plaintext.decode('utf-8')

# CTR Decryption 
def ctr_decrypt(k, c):
    key = bytes.fromhex(k)
    ciphertext = bytes.fromhex(c)
    nonce = ciphertext[:AES.block_size]
    enc_msg = ciphertext[AES.block_size:]
    ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(enc_msg)
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    cbc_key_1 = "140b41b22a29beb4061bda66b6747e14"
    cbc_ctext_1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"

    cbc_key_2 = "140b41b22a29beb4061bda66b6747e14"
    cbc_ctext_2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

    ctr_key_1 = "36f18357be4dbd77f050515c73fcf9f2"
    ctr_ctext_1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"

    ctr_key_2 = "36f18357be4dbd77f050515c73fcf9f2"
    ctr_ctext_2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

    print(cbc_decrypt(cbc_key_1, cbc_ctext_1))
    print(cbc_decrypt(cbc_key_2, cbc_ctext_2))
    print(ctr_decrypt(ctr_key_1, ctr_ctext_1))
    print(ctr_decrypt(ctr_key_2, ctr_ctext_2))
