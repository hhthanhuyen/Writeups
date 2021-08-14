# back_to_basics

Shoutout to those people who think that base64 is proper encryption.

Author: epistemologist

**main.py**
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import mpz, to_binary
#from secret import flag, key

ALPHABET = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#")

def base_n_encode(bytes_in, base):
	return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()

def base_n_decode(bytes_in, base):
	bytes_out = to_binary(mpz(bytes_in, base=base))[:1:-1]
	return bytes_out

def encrypt(bytes_in, key):
	out = bytes_in
	for i in key:
            print(i)
            out = base_n_encode(out, ALPHABET.index(i))
	return out

def decrypt(bytes_in, key):
	out = bytes_in
	for i in key:
		out = base_n_decode(out, ALPHABET.index(i))
	return out

"""
flag_enc = encrypt(flag, key)
f = open("flag_enc", "wb")
f.write(flag_enc)
f.close()
"""
```

**flag_enc** (1610126 bytes)

Cho mô tả hàm `encrypt` và `decrypt` dựa trên `base_n_encode` và `base_n_decode`, base n trong đoạn [2, 62]. Khóa dùng để mã hóa/giải mã là các byte thuộc ALPHABET, len(ALPHABET) = 37.

Nhận thấy kích thước của bản mã không lớn (~1.5 MB) và khóa có thể brute force được, chỉ cần check phần decode chứa printable bytes.

sol.py
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import mpz, to_binary
import string

alphabet = string.printable.encode()
ALPHABET = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#")
data = open("flag_enc","rb").read().strip()

def base_n_encode(bytes_in, base):
    return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()

def base_n_decode(bytes_in, base):
    bytes_out = to_binary(mpz(bytes_in, base=base))[:1:-1]
    return bytes_out


while True:
    for b in range(2,len(ALPHABET)+1):
        try:
            _data = base_n_decode(data,b)
            if all(bytes([i]) in alphabet for i in set(list(_data))):
                data = _data
                break
        except:
            continue
    #print(data)
    if b'uiuctf' in data:
        break

print(data)

#uiuctf{r4DixAL}
```

# dhke_intro

Small numbers are bad in cryptography. This is why.

Author: whimsicott79@leftovers

**dhkectf_intro.py**

```python
import random
from Crypto.Cipher import AES

# generate key
gpList = [ [13, 19], [7, 17], [3, 31], [13, 19], [17, 23], [2, 29] ]
g, p = random.choice(gpList)
a = random.randint(1, p)
b = random.randint(1, p)
k = pow(g, a * b, p)
k = str(k)

# print("Diffie-Hellman key exchange outputs")
# print("Public key: ", g, p)
# print("Jotaro sends: ", aNum)
# print("Dio sends: ", bNum)
# print()

# pad key to 16 bytes (128bit)
key = ""
i = 0
padding = "uiuctf2021uiuctf2021"
while (16 - len(key) != len(k)):
    key = key + padding[i]
    i += 1
key = key + k
key = bytes(key, encoding='ascii')

with open('flag.txt', 'rb') as f:
    flag = f.read()

iv = bytes("kono DIO daaaaaa", encoding = 'ascii')
cipher = AES.new(key, AES.MODE_CFB, iv)
ciphertext = cipher.encrypt(flag)

print(ciphertext.hex())
```

**output.txt**
```
b31699d587f7daf8f6b23b30cfee0edca5d6a3594cd53e1646b9e72de6fc44fe7ad40f0ea6
```

Một bài basic về thuật toán trao đổi khóa Diffie-Hellman, `g` và `p` được chọn ngẫu nhiên, `p` lớn nhất là 29. Chọn 2 số `a`, `b`, khóa chung `k` là g^(ab) % p, lấy `k` tạo tiếp khóa dùng để mã hóa flag (AES - CFB mode). Do `k` không thể lớn hơn `p` được nên thử `k` đến khi giải mã ra đúng flag format.

sol.py
```python
from Crypto.Cipher import AES

for j in range(29):
    k = str(j)
    key = ""
    i = 0
    padding = "uiuctf2021uiuctf2021"
    while (16 - len(key) != len(k)):
        key = key + padding[i]
        i += 1
    key = key + k
    key = bytes(key, encoding='ascii')

    iv = bytes("kono DIO daaaaaa", encoding = 'ascii')
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = bytes.fromhex('b31699d587f7daf8f6b23b30cfee0edca5d6a3594cd53e1646b9e72de6fc44fe7ad40f0ea6')
    flag = cipher.decrypt(ciphertext)
    if b'uiuctf' in flag:
        print(flag)

#uiuctf{omae_ha_mou_shindeiru_b9e5f9}
```

# dhke_adventure

Za smoother warudo. **nc dhke-adventure.chal.uiuc.tf 1337**

author: whimsicott79@leftovers, arxenix

**dhke_adventure.py**
```python
from random import randint
from Crypto.Util.number import isPrime
from Crypto.Cipher import AES
from hashlib import sha256

print("I'm too lazy to find parameters for my DHKE, choose for me.")
print("Enter prime at least 1024 at most 2048 bits: ")
# get user's choice of p
p = input()
p = int(p)
# check prime valid
if p.bit_length() < 1024 or p.bit_length() > 2048 or not isPrime(p):
    exit("Invalid input.")
# prepare for key exchange
g = 2
a = randint(2,p-1)
b = randint(2,p-1)
# generate key
dio = pow(g,a,p)
jotaro = pow(g,b,p)
key = pow(dio,b,p)
key = sha256(str(key).encode()).digest()

with open('flag.txt', 'rb') as f:
    flag = f.read()

iv = b'uiuctf2021uiuctf'
cipher = AES.new(key, AES.MODE_CFB, iv)
ciphertext = cipher.encrypt(flag)

print("Dio sends: ", dio)
print("Jotaro sends: ", jotaro)
print("Ciphertext: ", ciphertext.hex())
```

Tiếp tục cũng là một bài về thuật toán trao đổi khóa Diffie-Hellman, nhưng số nguyên tố `p` do mình chọn, `p` có độ lớn từ 1024 bits đến 2048 bits. Như vậy `p` được chọn sao cho `p-1` là tích các số nguyên tố nhỏ, dễ dàng lấy logarit rời rạc (Pohlig-Hellman algorithm).

sol.py
```python
from pwn import remote
from sage.all import *
from Crypto.Cipher import AES
from hashlib import sha256

def gen_prime():
    while True:
        p = 2
        for i in range(65):
            p *= random_prime(2**20)
        if is_prime(p+1) and 1024 < p.nbits() < 2048:
            return p+1


r = remote('dhke-adventure.chal.uiuc.tf', 1337)
r.recvuntil("Enter prime at least 1024 at most 2048 bits: \n")
p = gen_prime()
print(p)
r.sendline(str(p))

r.recvuntil("Dio sends: ")
Dio = int(r.recvuntil("\n").strip())
r.recvuntil("Jotaro sends: ")
Jotaro = int(r.recvuntil("\n").strip())
r.recvuntil("Ciphertext: ")
ciphertext = bytes.fromhex(r.recvuntil("\n").strip().decode())

d_Dio = discrete_log(Mod(Dio,p),Mod(2,p))
key = pow(Jotaro, d_Dio, p)
key = sha256(str(key).encode()).digest()
iv = b'uiuctf2021uiuctf'
cipher = AES.new(key, AES.MODE_CFB, iv)
print(cipher.decrypt(ciphertext))

#uiuctf{give_me_chocolate_every_day_7b8b06}
```
