from Crypto.Util.number import getStrongPrime, inverse, bytes_to_long
from flag import FLAG
import random


# FLAG = b"KCSC{???????????????????????????????}"


p = getStrongPrime(N=1024, e=65537)
q = getStrongPrime(N=1024, e=65537)
n = p*q
e = 65537
d = inverse(e, (p-1)*(q-1))
encrypted_flag = pow(bytes_to_long(FLAG), e, n)
x = random.randint(8*len(FLAG), 1024)

print(n, e, encrypted_flag, x)


while True:
    try:
        c = int(input())
        m = pow(c,d,n)
        print((m >> x) & 1)
    
    except:
        break
