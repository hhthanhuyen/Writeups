import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

i1 = os.urandom(8)
i2 = os.urandom(8)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])


def encrypt(k: bytes, p: bytes) -> bytes:
    cipher = DES.new(k, mode=DES.MODE_ECB)
    ct = b""
    for i in range(0, len(p), 8):
        block = p[i:i+8]
        ct += xor(cipher.encrypt(xor(block, i1)), i2)
    return ct


def decrypt(k: bytes, c: bytes) -> bytes:
    cipher = DES.new(k, mode=DES.MODE_ECB)
    return xor(cipher.decrypt(xor(c, i2)), i1)


with open("flag.txt", "rb") as f:
    flag = f.read().strip()

while True:
    print("Choose an option:")
    print("     1. Get encrypted flag")
    print("     2. Decrypt")
    option = int(input())
    if option == 1:
        k = os.urandom(8)
        c = encrypt(k, pad(flag, DES.block_size))
        print(f"Key: {k.hex()}")
        print(f"Encrypted flag: {c.hex()}")
    elif option == 2:
        print("Key: ")
        k = bytes.fromhex(input())
        print("Ciphertext: ")
        c = bytes.fromhex(input())

        if len(c) != 8:
            print("Invalid ciphertext length")
            break

        p = decrypt(k, c)
        if p in flag:
            print("This one right here, officer")
            break

        print(f"Plaintext: {p.hex()}")
    else:
        print("Invalid option")
        break
