from typing import List
from Crypto.Util.number import getStrongPrime, bytes_to_long


p = getStrongPrime(512)
q = getStrongPrime(512)
N = p * q
e = 65537

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)


def crt(a: List[int], m: List[int]) -> int:
    """
    Chinese Remainder Theorem
    x \equiv a_0 (mod m_0)
    x \equiv a_1 (mod m_1)
    ...
    Assume that all m_i are pairwise coprime
    https://vi.wikipedia.org/wiki/%C4%90%E1%BB%8Bnh_l%C3%BD_s%E1%BB%91_d%C6%B0_Trung_Qu%E1%BB%91c
    """
    M = 1
    for mi in m:
        M *= mi

    x = 0
    for i in range(len(a)):
        a_i = a[i]
        m_i = m[i]

        M_i = M // m_i
        y_i = pow(M_i, -1, m_i)

        x = (x + a_i * M_i * y_i) % M
    return x


def encrypt(m: int) -> int:
    # Compute m^e mod N
    c = 1
    a = m
    k = e
    while k > 0:
        if k % 2 == 1:
            c = c * a % N
        a = a * a % N
        k = k // 2
    return c


def decrypt(c: int) -> int:
    """
    What's happening here?
    I compute:
        m_p = c^d mod p
        m_q = c^d mod q
    Then apply CRT to compute m

    Why?
    I heard that this approach is 4 times faster than the usual c^d mod N
    """

    # Compute c^d mod p
    m_p = 1
    a = c
    k = d
    while k > 0:
        if k % 2 == 1:
            m_p = m_p * a % p
        a = a * a % p
        k = k // 2

    # Compute c^d mod q
    m_q = 1
    a = c
    k = d
    while k > 0:
        if k % 2 == 1:
            m_q = m_p * a % q
        a = a * a % q
        k = k // 2

    return crt([m_p, m_q], [p, q])


with open("flag.txt", "rb") as f:
    flag = bytes_to_long(f.read().strip())

print(f"Public key: {N}")

logs_e = [flag]
logs_d = []
while True:
    print("Choose an option:")
    print("     1. Get encrypted flag")
    print("     2. Encrypt")
    print("     3. Decrypt")
    option = int(input())
    if option == 1:
        print(encrypt(flag))
        break
    elif option == 2:
        print("Plaintext: ")
        m = int(input())

        if m in logs_d:
            print("This one right here, officer.")
            break

        c = encrypt(m)
        print(f"Ciphertext: {c}")

        logs_e.append(c)
    elif option == 3:
        print("Ciphertext: ")
        c = int(input())

        if c in logs_e:
            print("This one right here, officer.")
            break

        m = decrypt(c)
        print(f"Plaintext: {m}")

        logs_d.append(m)
    else:
        print("Invalid option")
        break
