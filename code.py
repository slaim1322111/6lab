def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
          

def generate_round_keys(key, rounds=24):
    key_bytes = key.encode()
    round_keys = []

    for i in range(rounds):
        rk = bytes((key_bytes[j % len(key_bytes)] + i) % 256 for j in range(4))
        round_keys.append(rk)

    return round_keys


def feistel_function(right, round_key):
    return xor_bytes(right, round_key)


def feistel_encrypt_block(block, round_keys):
    left = block[:4]
    right = block[4:]

    for rk in round_keys:
        new_left = right
        f = feistel_function(right, rk)
        new_right = xor_bytes(left, f)
        left, right = new_left, new_right

    return left + right


def feistel_decrypt_block(block, round_keys):
    left = block[:4]
    right = block[4:]

    for rk in reversed(round_keys):
        new_right = left
        f = feistel_function(left, rk)
        new_left = xor_bytes(right, f)
        left, right = new_left, new_right

    return left + right


def pad_text(text):
    data = text.encode()
    while len(data) % 8 != 0:
        data += b' '
    return data


def encrypt(text, key):
    data = pad_text(text)
    round_keys = generate_round_keys(key)
    encrypted = b''

    for i in range(0, len(data), 8):
        encrypted += feistel_encrypt_block(data[i:i+8], round_keys)

    return encrypted


def decrypt(cipher, key):
    round_keys = generate_round_keys(key)
    decrypted = b''

    for i in range(0, len(cipher), 8):
        decrypted += feistel_decrypt_block(cipher[i:i+8], round_keys)

    return decrypted.decode().rstrip()



plaintext = input("Введите исходный текст: ")
key = input("Введите ключ: ")

ciphertext = encrypt(plaintext, key)
print("\nШифрограмма (hex):", ciphertext.hex())

decrypted_text = decrypt(ciphertext, key)
print("Дешифрованный текст:", decrypted_text)
