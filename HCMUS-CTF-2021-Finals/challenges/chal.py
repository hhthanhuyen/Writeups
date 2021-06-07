from Crypto.Util.number import isPrime, getPrime
import random
import math

p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p-1) * (q-1)

while True:
    e = random.randint(2,n-1)
    if math.gcd(e,phi) == 1:
        break

d = pow(e, -1, phi)

m = random.randint(2,n-1)
c = pow(m, e, n)

print(m, c)

p = int(input())
q = int(input())
d = int(input())

assert(p < q)
assert(512 <= p.bit_length())
assert(q.bit_length() < 1024)
assert(isPrime(p))
assert(isPrime(q))

n = p * q
assert(1 < d < n)

if m == pow(c, d, n):
    with open('/home/ctf/flag.txt','r') as f:
        print(f.read())