from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def des_encrypt_decrypt(text, key, mode, iv=None):
    data = pad(text.encode(), 8)

    if mode == DES.MODE_ECB:
        cipher = DES.new(key, mode)
    else:
        cipher = DES.new(key, mode, iv)

    encrypted = cipher.encrypt(data)

    if mode == DES.MODE_ECB:
        cipher_dec = DES.new(key, mode)
    else:
        cipher_dec = DES.new(key, mode, iv)

    decrypted = unpad(cipher_dec.decrypt(encrypted), 8)

    return encrypted, decrypted.decode()


# ====== Ввод данных ======
plaintext = input("Введите открытый текст: ")
key = b'8bytekey'          # 64-битовый ключ
iv = get_random_bytes(8)   # 64-битовый C0 (ПСЧ)

modes = {
    "ECB": DES.MODE_ECB,
    "CBC": DES.MODE_CBC,
    "CFB": DES.MODE_CFB,
    "OFB": DES.MODE_OFB
}

for name, mode in modes.items():
    enc, dec = des_encrypt_decrypt(plaintext, key, mode, iv)
    print(f"\nРежим {name}")
    print("Шифрограмма (hex):", enc.hex())
    print("Дешифрование:", dec)
