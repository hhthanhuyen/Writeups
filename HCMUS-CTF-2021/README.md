
# HCMUS-CTF 2021 Quals - Cryptography

### SanityCheck

> Welcome to HCMUS_-CTF 2021. We're Blackpinker.  
> author: pakkunandy  
> [encoded](challenges/encoded)

```
MQZGQ3K2PFBDMYTONB4USR3YNFQUGQTJLEZUU2CJI5UGUSKHPBUWCR2VM5RW26DZLJTW6S2WKZBGCU2FLF2FKRLEKRSTA4DZLAZDK3DDNQ4VAZKXGV3WKR2OGJMVQ2DZLJLDS4LDNZWHOWLOOB4VQMTENFMDGVTXMVWWQ3KYGNBG4YZRHB4U2RCJPBTFCPJ5
```

Mở đầu là một bài sanity check, flag được encode lần lượt bằng rot13, base64 và base32, decode theo thứ tự ngược lại là được flag.

```python
>>> import base64
>>> import codecs
>>> c = 'MQZGQ3K2PFBDMYTONB4USR3YNFQUGQTJLEZUU2CJI5UGUSKHPBUWCR2VM5RW26DZLJTW6S2WKZBGCU2FLF2FKRLEKRSTA4DZLAZDK3DDNQ4VAZKXGV3WKR2OGJMVQ2DZLJLDS4LDNZWHOWLOOB4VQMTENFMDGVTXMVWWQ3KYGNBG4YZRHB4U2RCJPBTFCPJ5'
>>> print(codecs.decode(base64.b64decode(base64.b32decode(c)).decode(), "rot13"))
just make you open up your eyes

HCMUS-CTF{We_are_Blackpinker_welcome_to_hcmus_ctf_2021}
```

***

### SingleByte

> Yup!!!! You know it!!! The very simple encryption technique that has the perfect secrecy.  
> author: pakkunandy  
> [ciphertext.txt](challenges/ciphertext.txt)

```
r4SJmJOanoOFhMqDmcqLyp2Lk8qFjMqZiZiLh4iGg4SNyo6LnovKmYXKnoKLnsqFhIaTyoufnoKFmIOQj47KmouYnoOPmcqJi4TKn4SOj5iZnouEjsqego/Kg4SMhZiHi56DhYTEyqOEyp6PiYKEg4mLhsqej5iHmcbKg57Kg5nKnoKPypqYhYmPmZnKhYzKiYWEnI+YnoOEjcqCn4eLhMeYj4uOi4iGj8qahouDhJ6Pkp7KnoXKg4SJhYeamI+Cj4SZg4iGj8qej5KexsqLhpmFyoGEhZ2EyouZyomDmoKPmJ6Pkp6iqae/ucepvqyRnY+1gYSFnbWegouetZOFn7WJi4S1joW1mYOHmoaPtbKluLXf3tnb2dvf3ouIiYyP396LjNiPiYuIlw==
```

Single-byte XOR cipher, mỗi ký tự của bản rõ được XOR với cùng một byte, tìm lại byte này bằng cách thử 256 khả năng.

```python
>>> from base64 import b64decode
>>> from pwn import xor
>>> f = open("ciphertext.txt","rb").read()
>>> f = b64decode(f)
>>> for i in range(256):
...     x = xor(f, bytes([i]*len(f)))
...     if b"HCMUS-CTF" in x:
...         print(x.decode())
... 
Encryption is a way of scrambling data so that only authorized parties can understand the information. In technical terms, it is the process of converting human-readable plaintext to incomprehensible text, also known as ciphertextHCMUS-CTF{we_know_that_you_can_do_simple_XOR_54313154abcfe54af2ecab}
```

***

### TheChosenOne

> The cryptography technique can be good, but the implementation is bad. Do you know the weakness of AES-ECB? (Inspired from some old stuff with a little bit easier =D )  
> https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation  
> nc 61.28.237.24 30300  
> author: pakkunandy  
> [server.py](challenges/server.py)

```python
[...]
plaintext = user_input + flag
padding_length = padding(plaintext)
plaintext = plaintext.ljust(padding_length, padding_character)

sys.stdout.write('The ciphertext:\n{}\n\n'.format((cipher.encrypt(plaintext)).encode('hex')))
```

Server cho phép nhập vào một chuỗi, sau đó trả về bản mã AES-ECB(pad(user_input || flag)), lưu ý mã khối ở chế độ ECB không an toàn, hai khối bản rõ giống nhau sẽ có hai khối bản mã giống nhau. Như vậy có thể tìm lại từng chữ của flag bằng cách so sánh hai khối, trong đó `?` là một byte dùng để brute force những chữ có thể của flag.

```
1234567890123456
aaaaaaaaaaaaaaa?  <- user_input = aaaaaaaaaaaaaaa?aaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaH

aaaaaaaaaaaaaaH?  <- user_input = aaaaaaaaaaaaaaH?aaaaaaaaaaaaaa
aaaaaaaaaaaaaaHC

aaaaaaaaaaaaaHC?  <- user_input = aaaaaaaaaaaaaHC?aaaaaaaaaaaaa
aaaaaaaaaaaaaHCM

[...]
```

```python
from pwn import remote, xor

r = remote("61.28.237.24", 30300)
r.recvuntil("Your input: ")
flag = ""

for i in range(15,-1,-1):
    for c in range(127,-1,-1):
        m = 'a'*i + flag + chr(c) + 'a'*i
        r.sendline(m)
        r.recvuntil("\n")
        ct = r.recvuntil("\n").strip().decode()
        ct = bytes.fromhex(ct)
        r.recvuntil("Your input: ")
        if ct[:16] == ct[16:32]:
            flag += chr(c)
            print("Flag:",flag)
            break

for i in range(15,-1,-1):
    for c in range(127,-1,-1):
        m = 'a'*i + flag + chr(c) + 'a'*i
        r.sendline(m)
        r.recvuntil("\n")
        ct = r.recvuntil("\n").strip().decode()
        ct = bytes.fromhex(ct)
        r.recvuntil("Your input: ")
        if ct[16:32] == ct[48:64]:
            flag += chr(c)
            print("Flag:",flag)
            break

# Flag: HCMUS-CTF{You_Can_4ttack_A3S!?!}
```

***

### CrackMe

> There is some way to crack the hash...  
> author: pakkunandy  
> [phase1.zip](challenges/phase1.zip)

Bài gồm 2 phase, phase 1 yêu cầu crack một password, phase 2 yêu cầu crack passphrase của một khóa RSA. Sau đó encode chuỗi bằng base64 để mở các file zip tương ứng.  
Tool: *john - John the Ripper password cracker*.  
Phase 1: playboy123  
Phase 2: felecity

Flag: HCMUS_CTF{cracking_for_fun}

***

### DESX

> DESX = DES10 > DES3 > DES. In other word, this is the superior encryption algorithm.  
> nc 61.28.237.24 30301  
> author: mugi  
> [desx.py](challenges/desx.py)

```python
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
```

Server cho phép 2 lựa chọn, `Get encrypted flag` và `Decrypt`. Trong đó flag được mã hóa bằng DES-ECB: **C<sub>i</sub> = E<sub>k</sub>(P<sub>i</sub> XOR i1) XOR i2**, với i1 và i2 là hai block cố định, không biết giá trị và server còn cho biết khóa `k` dùng để mã hóa. `Decrypt` chỉ được giải mã một block với khóa tự chọn, và được kiểm tra để tránh block được giải mã là flag.

Lưu ý DES có tính chất:  
&nbsp;&nbsp;&nbsp;&nbsp;![equation](https://latex.codecogs.com/svg.image?\overline{C}&space;=&space;E_{\overline{k}}(\overline{P})) 
&nbsp;&nbsp;&nbsp;&nbsp;![equation](https://latex.codecogs.com/svg.image?\overline{P}&space;=&space;D_{\overline{k}}(\overline{C}))

```python
from pwn import remote, xor

r = remote("61.28.237.24", 30301)
r.recv()
r.sendline("1")
key = bytes.fromhex(r.recvuntil("\n").strip().split()[-1].decode())
ct = bytes.fromhex(r.recvuntil("\n").strip().split()[-1].decode())
fake_key = xor(b'\xff'*8,key)

flag = b''
for i in range(0,len(ct),8):
    r.recv()
    r.sendline("2")
    r.recv()
    r.sendline(fake_key.hex())
    r.recv()
    fake_ct = xor(b'\xff',ct[i:i+8])
    r.sendline(fake_ct.hex())
    flag += xor(b'\xff'*8,bytes.fromhex(r.recvuntil("\n").strip().split()[-1].decode()))
    print(flag)

# Flag: HCMUS-CTF{https://en.wikipedia.org/wiki/Data_Encryption_Standard#Minor_cryptanalytic_properties}
```

***

### RSB

> RSB > RSA nc 61.28.237.24 30302  
> author: mugi  
> [rsb.py](challenges/rsb.py)

```python
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
```

Một bài về RSA-CRT Fault attack, ban đầu server gửi về giá trị của N, sau đó cho phép `Get encrypted flag`, `Encrypt` và `Decrypt`.  
Thử decrypt giá trị pow(2,65537,N) thì được kết quả khác 2...  
Z<sup>\*</sup><sub>N</sub> ≅ Z<sup>\*</sup><sub>p</sub> x Z<sup>\*</sup><sub>q</sub> , fault attack xảy ra khi có lỗi ở Z<sup>\*</sup><sub>p</sub> hoặc Z<sup>\*</sup><sub>q</sub> .

Với m < p và m < q:  
&nbsp;&nbsp;&nbsp;&nbsp;c<sup>d</sup> mod N = (c<sup>d</sup> mod p, c<sup>d</sup> mod q) = (c<sup>dp</sup> mod p, c<sup>dq</sup> mod q) = (m, m).  
&nbsp;&nbsp;&nbsp;&nbsp;Nếu c<sup>d</sup> ≡ m (mod p) mà c<sup>d</sup> ![equation](https://latex.codecogs.com/svg.image?\not\equiv) m (mod q), thì p | (c<sup>d</sup> - m), do đó GCD(N, c<sup>d</sup> - m) = p.

```python
from pwn import remote
from Crypto.Util.number import GCD, long_to_bytes

r = remote('61.28.237.24', 30302)
n = int(r.recvuntil("\n").strip().split()[-1])
print("n:",n)

r.recv()
r.sendline('3')
r.recv()
r.sendline(str(pow(2,65537,n)))
m = int(r.recvuntil("\n").strip().split()[-1])
print("m:",m)

r.recv()
r.sendline('1')
f = int(r.recvuntil("\n").strip())
print("Encrypted flag:",f)
p = GCD(m-2,n)
q = n//p
d = pow(65537,-1,(p-1)*(q-1))
print(long_to_bytes(pow(f,d,n)).decode())

#Flag: HCMUS-CTF{fault-attack}
```

***

### Permutation

> Playing around with permutation is fun. nc 61.28.237.24 30303  
> author: vuonghy2442  
> [permutation.py](challenges/permutation.py)

```python
from typing import List
import random

def get_permutation(n : int) -> List[int]:
    arr = list(range(n))
    random.shuffle(arr)
    return arr

def compose_permutation(p1 : List[int], p2 : List[int]):
    return [p1[x] for x in p2]

def permutation_power(p : List[int], n : int) -> List[int]:
    if n == 0:
        return list(range(len(p)))
    if n == 1:
        return p

    x = permutation_power(p, n // 2)
    x = compose_permutation(x, x)
    if n % 2 == 1:
        x = compose_permutation(x, p)
    return x


with open("flag.txt", "rb") as f:
    flag = int.from_bytes(f.read().strip(), byteorder='big')

perm = get_permutation(512)
print(perm)
print(permutation_power(perm, flag))
```

Bài cho một hoán vị của 512 phần tử, định nghĩa phép nhân vô hướng là n * Perm = Perm ∘ Perm ∘ ... ∘ Perm ∘ Perm (n lần).  
Cho biết hoán vị P, và hoán vị Q = flag * P, tìm lại flag. Vậy phải tính logarit rời rạc trên nhóm các hoán vị để tìm flag.

Mỗi hoán vị P có thể biểu diễn dưới dạng các chu trình rời nhau, tìm ord(P) bằng cách lấy LCM của độ dài các chu trình, do ord(P) không quá lớn nên có thể tìm được giá trị x sao cho Q = x * P với flag ≡ x (mod ord(P)).

Một vấn đề khác xảy ra, ord(P) rất nhỏ so với flag, tìm flag = k*ord(P) + x (với k là một số nguyên) không khả thi. Để mở rộng modulo thì tìm thêm nhiều phương trình flag ≡ x (mod ord(P)), đưa về bài toán giải hệ phương trình đồng dư. Lưu ý các ord(P) này thường không nguyên tố cùng nhau, không thể sử dụng Chinese remainder theorem được. Có một phương pháp khác để giải quyết vấn đề này, dựa trên [answer](https://math.stackexchange.com/questions/1644677/what-to-do-if-the-modulus-is-not-coprime-in-the-chinese-remainder-theorem) của @AC.

```python
from sage.all import *
from json import loads
from Crypto.Util.number import long_to_bytes
from sock import Sock


def compose_permutation(p1, p2):
    return [p1[x] for x in p2]

def permutation_power(p, n):
    if n == 0:
        return list(range(len(p)))
    if n == 1:
        return p
    
    x = permutation_power(p, n // 2)
    x = compose_permutation(x, x)
    if n % 2 == 1:
        x = compose_permutation(x, p)
    return x

def discrete_log(a, b, n):
    m = ceil(sqrt(n))
    l = []
    for j in range(m):
        l.append(permutation_power(a,j))
    inv_a = list(Permutation([x + 1 for x in a]).inverse())
    inv_a = [x - 1 for x in inv_a]
    inv_a_m = permutation_power(inv_a,m)
    y = b
    for i in range(m):
        if y in l:
            return i*m + l.index(y)
        y = compose_permutation(y, inv_a_m)


vals = []
mods = []
while True:
    r = Sock('61.28.237.24', 30303)
    g = loads(r.read_line().strip())
    y = loads(r.read_line().strip())
    r.close()

    _g = [i+1 for i in g]
    _g = list(Permutation(_g).to_cycles())
    lens = []
    for i in _g:
        lens.append(len(i))
    MOD = LCM(lens)

    if MOD < 100000000:
        #print(MOD)
        mods.append(MOD)
        vals.append(discrete_log(g,y,MOD))
        if len(mods) == 2:
            d,u,v = xgcd(mods[0],mods[1])
            l = (vals[0] - vals[1])//gcd(mods[0],mods[1])
            vals = [(vals[0] - mods[0]*u*l) % LCM(mods)]
            mods = [LCM(mods)]
            flag = long_to_bytes(vals[0])
            print(flag)
            if b'HCMUS-CTF' == flag[:9]:
                break

#Flag: HCMUS-CTF{discrete_log_is_easy_on_permutation_group}
```
