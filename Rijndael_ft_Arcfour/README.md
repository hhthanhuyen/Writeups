# ASCIS 2020 Qualification Round - Rijndael ft. Arcfour

A great challenge on my to-do list for a long time...

## Challenge file
- [rijndael_ft_arcfour.zip](https://github.com/hhthanhuyen/Writeups/blob/main/Rijndael_ft_Arcfour/rijndael_ft_arcfour.zip)

We are given a box using AES to encrypt the flag, but something looks suspicious, *"added support for custom S-box"*.

aes.py
```
[...]

def set_s_box(in_s_box):
    assert len(set(in_s_box)) == 256
    assert all(0 <= d < 256 for d in in_s_box)
    global s_box, inv_s_box
    s_box = [0] * 256
    inv_s_box = [0] * 256
    for i in range(256):
        j = in_s_box[i]
        s_box[i] = j
        inv_s_box[j] = i
```

rijndael_ft_arcfour.py
```
from typing import List
import os
import aes  # https://github.com/boppreh/aes, added support for custom S-box.


def ksa(key: bytes) -> List[int]:
    """Arcfour (RC4) key scheduling algorithm."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        if i != j:
            # swap S[i] and S[j]
            S[i] += S[j]
            S[j] = S[i] - S[j]
            S[i] -= S[j]
    return S


def encrypt(msg: bytes, rc4_key: bytes, aes_key: bytes) -> bytes:
    """Rijndael (AES) ft. Arcfour (RC4) encryption routine."""
    sbox = ksa(rc4_key)

    # Since the sbox should look like a random table, we can check for weak
    # keys by counting the number of elements smaller than 128 in the first 128
    # entries. This number should be around 64.
    assert 64 - 8 <= [c < 128 for c in sbox[:128]].count(True) <= 64 + 8

    aes.set_s_box(sbox)
    iv = os.urandom(16)
    return iv + aes.AES(aes_key).encrypt_cbc(msg, iv)


if __name__ == '__main__':
    # give us a key
    key = bytes.fromhex(input())

    # here's a gift for you :)
    from secret import flag
    print(encrypt(f"The flag is: {flag}".encode(), key, os.urandom(16)).hex())
```

So, we're able to change the S-box by sending a key, the server then uses that key to perform RC4 key-scheduling algorithm (KSA) and sets the output array as the AES S-box. Choosing an S-box, we can inverse KSA and obtain a key which generates that S-box.

Each AES round (except final round) is composed of four different transformations: *SubBytes*, *ShiftRows*, *MixColumns*, *AddRoundKey*. If *SubBytes* is an affine transformation, i.e. SubBytes(X) = A\*X + B, where X and B are 8 x 1 matrices, and A is a 8 x 8 matrix over GF(2), then the whole AES will become an affine transformation, which means C = AES(P) = A\*P + B, where P is a plaintext block, C is the corresponding ciphertext block, A is a 128 x 128 matrix and B is a 128 x 1 matrix.

Note that the matrix A can be generated from *SubBytes*, *ShiftRows*, *MixColumns*, none of which related to the AES key. Assume we know a pair (P, C), then B can be retrieved by B = C - A*P. Once A and B are known, we can encrypt any plaintext block or decrypt any ciphertext block (using P = A<sup>-1</sup> \* (C - B)) regardless of knowing the AES key.

## Implementation
[solve.py](https://github.com/hhthanhuyen/Writeups/blob/main/Rijndael_ft_Arcfour/solve.py)
```
from rijndael_ft_arcfour import *
from sage.all import *
from os import urandom


def inv_ksa(S):
    key = [0]*256
    for i in range(255,-1,-1):
        j = S.index(i)
        if i != j:
            # swap S[i] and S[j]
            S[i] += S[j]
            S[j] = S[i] - S[j]
            S[i] -= S[j]
        key[i] = (j - S[i] - S.index(i-1)) % 256 if i != 0 else (j - S[i]) % 256
    return bytes(key)


def gen_rc4_key():
    while True:
        A = random_matrix(GF(2), 8, 8)
        if A.is_invertible():
            break
    B = random_matrix(GF(2), 8, 1)
    SBOX = list(range(256))
    for i,j in enumerate(SBOX):
        tmp = A * matrix(GF(2), Integer(j).digits(base=2, padto=8)).transpose() + B
        SBOX[i] = int(''.join(map(str,[t[0] for t in tmp[::-1]])),2)
    assert 64 - 8 <= [c < 128 for c in SBOX[:128]].count(True) <= 64 + 8
    key = inv_ksa(SBOX)
    return key


def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])


def bytes_to_vector(b):
    b = list(b)
    v = []
    for i in range(16):
        v += Integer(b[i]).digits(base=2, padto=8)[::-1]
    return vector(GF(2),v)


def vector_to_bytes(v):
    b = b''
    for i in range(16):
        b += bytes([int(''.join(map(str, v[i*8: i*8+8])),2)])
    return b


if __name__ == '__main__':
    while True:
        try:
            key = gen_rc4_key()
            sbox = ksa(key)
            aes.set_s_box(sbox)
            cipher = aes.AES(urandom(16))

            B = bytes_to_vector(cipher.encrypt_block(bytes(16)))
            
            C = []
            P = matrix.identity(GF(2),128)
            for i in range(128):
                c = cipher.encrypt_block(vector_to_bytes(P[i]))
                C.append(bytes_to_vector(c))

            A = matrix(GF(2),C).transpose() + matrix(GF(2),[B]*128).transpose()
            assert A.is_invertible()
            break
        except:
            continue
    
    print("[+] RC4 key:", key.hex())
    flag = "ASCIS{th3_sb0x_sh0uld_b3_f1x3d}" # :D
    ciphertext = encrypt(f"The flag is: {flag}".encode(), key, os.urandom(16))
    
    print("[+] Ciphertext:",ciphertext.hex())
    ciphertext = [ciphertext[i:i+16] for i in range(0,len(ciphertext),16)]
    B = A * bytes_to_vector(xor(b"The flag is: ASC",ciphertext[0])) + bytes_to_vector(ciphertext[1])
    msg = b''
    for i in range(1,len(ciphertext)):
        p = vector_to_bytes(A.inverse() * (bytes_to_vector(ciphertext[i]) + B))
        msg += xor(p,ciphertext[i-1])

    print("[+]", msg.decode())

```

## References
- Joan Daemen, Vincent Rijmen - *AES Proposal: Rijndael*
- [Wikipedia - RC4](https://en.wikipedia.org/wiki/RC4)
