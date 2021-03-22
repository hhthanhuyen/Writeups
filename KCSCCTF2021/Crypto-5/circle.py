from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from os import urandom
from collections import namedtuple
from flag import FLAG

Point = namedtuple("Point", "x y")

p = 12614890870414228127779916638250802780539080481439818392282120457454118656637931353089369536761286238473711443616903578930867547881364141714404652594476247
G = Point(2806063492489459545247324657227342168942447420510651428295738429317448638882656448158355443494544670230790482108751812744127243162016136982116321879703, 
          10439495556207164880422605748876259086334305799649649122097186988382416428455443266630972486168701673177383620403133890197192716594737247426126158546851335)

assert (G.x**2 + G.y**2) % p == 1


def addition(P, Q):
    x = (P.x*Q.y + Q.x*P.y) % p
    y = (P.y*Q.y - P.x*Q.x) % p
    return Point(x,y)


def scalar_multiplication(n, P):
    Q = Point(0,1)
    while n:
        if n % 2 == 1:
            Q = addition(Q, P)
        P = addition(P, P)
        n = n // 2
    return Q


if __name__ == "__main__":
    d = int.from_bytes(urandom(32), "big")
    P = scalar_multiplication(d, G)
    print(f"{P.x}, {P.y}")
    
    try:
        x = int(input()) % p
        y = int(input()) % p
        assert (x**2 + y**2) % p == 1

        Q = addition(Point(x,y), P)
        blackList = [0, 1, p - 1]
        if (Q.x in blackList) or (Q.y in blackList):
            print("Heyyy !")

        else:
            secret = int.from_bytes(urandom(32), "big")
            K = scalar_multiplication(secret, Q)
            key = str(K.x) + str(K.y)
            key = sha256(key.encode()).digest()[:16]
            iv = urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            print(f"IV: {iv.hex()}")
            print(f"Ciphertext: {cipher.encrypt(pad(FLAG,16)).hex()}")

    except:
        print("Invalid input...")
