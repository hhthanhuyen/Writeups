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
