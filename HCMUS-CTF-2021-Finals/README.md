# HCMUS-CTF 2021 Finals - Cryptography

## Polynomial AES (58 pts)

`encrypt.py`
```python
from Crypto.Util.number import getPrime, getRandomRange, getRandomInteger
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

flag = open("flag.txt", "rb").read()


def sha256(s: bytes) -> bytes:
    h = SHA256.new()
    h.update(s)
    return h.digest()


def generate_key() -> bytes:
    d = getRandomRange(20, 30)
    p = getPrime(1024)
    q = []
    for _ in range(d + 1):
        q.append(getRandomInteger(100))

    def eval(x: int) -> int:
        ans = 0
        mul = 1
        for i in range(d + 1):
            ans = (ans + mul * q[i]) % p
            mul = (mul * x) % p
        return ans

    print(f"p = {p}")
    print(f"q = {q}")

    H = range(1, p)
    s = 0
    for h in H:
        s = (s + eval(h)) % p

    key = sha256(str(s).encode())
    return key


key = generate_key()
cipher = AES.new(key, mode=AES.MODE_ECB)
ct = cipher.encrypt(pad(flag, AES.block_size))

print(f"Encrypted flag: {ct.hex()}")
```
`output.txt`
```
p = 177623787080918790693312135936556122024020095001443303172107276987982440197490523418145835127889071265905054737784623738629013338784360558617366098465518180680782530663638215602960132688937540305263995580366073873308704407001927606741585489839642710147345583432505462036986076120792139184590814347216415564101
q = [801237753591354715102942191156, 626618719198500674209203323781, 990607682230559368102514378597, 300626649773649360709969851789, 874661725788013406358456728725, 611124797526692571169418404283, 696940952735206910076260768209, 202318491739756355785884585154, 217597478025466348191206328033, 238860189889236925504208320473, 257324672120956057034462883536, 160322512393915295700562029637, 607851219645061751393650249507, 843763343969620761723084660993, 664187143329183292841846729739, 1006116355393829943519743575276, 1032255895907602121421225800124, 760726117259231496345295071803, 374029363383881393553491416304, 510251190591403967192508766973, 418897119833960203375767935538, 454322945572252709096080212504, 442294223579983673964906923798, 974394018465930277236048171917, 615939424032648824469586728134]
Encrypted flag: 413016e1c544c23c3fddb759388ec267cd47980a57de5e3c5c6e6b5628eea5d5
```

Cho một đa thức *f* bậc *d* thuộc F<sub>p</sub>[x] với các hệ số như trong list `q`, khóa `key` dùng để mã hóa flag được tính bằng `s = f(1) + f(2) + f(3) + ... + f(p-1) (mod p)`, `key = sha256(str(s).encode())`.

```
p = 177623787080918790693312135936556122024020095001443303172107276987982440197490523418145835127889071265905054737784623738629013338784360558617366098465518180680782530663638215602960132688937540305263995580366073873308704407001927606741585489839642710147345583432505462036986076120792139184590814347216415564101
```

`p` có độ dài 1024 bit, loop từ 1 đến p-1 thì không biết đến khi nào mới xong...             
Có ![equation](https://latex.codecogs.com/svg.image?f(x)=q_{d}x^{d}&plus;q_{d-1}x^{d-1}&plus;q_{d-2}x^{d-2}&plus;...&plus;q_{1}x&plus;q_{0}&space;\thickspace&space;(mod\thickspace&space;p)).             
![equation](https://latex.codecogs.com/svg.image?s=f(1)&plus;f(2)&plus;f(3)&plus;...&plus;f(p-1)&space;\thickspace&space;(mod\thickspace&space;p)).                
![equation](https://latex.codecogs.com/svg.image?s=\sum_{i=0}^{d}q_{i}.\left&space;(&space;\sum_{k=1}^{p-1}k^{i}&space;\right&space;)&space;(mod\thickspace&space;p)).            
Đổi lại thì phải tính ![equation](https://latex.codecogs.com/svg.image?\sum_{k=1}^{p-1}k^{i},&space;i\in[0,d]) - [Faulhaber's formula](https://en.wikipedia.org/wiki/Faulhaber%27s_formula).

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from polysum import * # https://github.com/fcard/PolySum/blob/master/Python/polysum.py
from hashlib import sha256

p = 177623787080918790693312135936556122024020095001443303172107276987982440197490523418145835127889071265905054737784623738629013338784360558617366098465518180680782530663638215602960132688937540305263995580366073873308704407001927606741585489839642710147345583432505462036986076120792139184590814347216415564101
q = [801237753591354715102942191156, 626618719198500674209203323781, 990607682230559368102514378597, 300626649773649360709969851789, 874661725788013406358456728725, 611124797526692571169418404283, 696940952735206910076260768209, 202318491739756355785884585154, 217597478025466348191206328033, 238860189889236925504208320473, 257324672120956057034462883536, 160322512393915295700562029637, 607851219645061751393650249507, 843763343969620761723084660993, 664187143329183292841846729739, 1006116355393829943519743575276, 1032255895907602121421225800124, 760726117259231496345295071803, 374029363383881393553491416304, 510251190591403967192508766973, 418897119833960203375767935538, 454322945572252709096080212504, 442294223579983673964906923798, 974394018465930277236048171917, 615939424032648824469586728134]
s = 0
for i,j in enumerate(q):
    s += polysum(i,p-1)*j
    s = s % p

key = sha256(str(s).encode()).digest()
cipher = AES.new(key, mode=AES.MODE_ECB)
ct = bytes.fromhex('413016e1c544c23c3fddb759388ec267cd47980a57de5e3c5c6e6b5628eea5d5')
flag = unpad(cipher.decrypt(ct),16)
print(flag.decode())

# HCMUS-CTF{learn-algebra}
```

***

## DragonBall (95 pts)

Bài `DragonBall` nói về [ElGamal signature scheme](https://en.wikipedia.org/wiki/ElGamal_signature_scheme). Mình chưa chụp lại lúc làm bài, mà sơ qua thì server có 3 lựa chọn, `generate`, `verify` và `debug`.        
- `generate` để nhập username, sau đó server gen một chuỗi `USERNAME=username&LEVEL=Saiyan`, ký bằng Elgamal-SHA1, trả về một token có chứa `r` và `s`.
- `verify` để nhập token và xác thực user, nếu là `SuperSaiyan` thì trả về flag.
- Và `debug` cho biết tham số `g` và `p` được dùng.

Kiểm tra `g` và `p` không thấy có gì bất thường, mình nhập thử các username khác nhau thì biết được nonce `k` cố định rồi.

Như vậy có thể tìm lại `k` và private key `x`, đủ để tạo token thỏa yêu cầu `USERNAME=username&LEVEL=SuperSaiyan`.

```python
import base64
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha1

p = 129395855808705212728342121899564040533627536165407217623699982163034898985604990453612738681235265684964910273382421570674875235106037524148312004154122323500944367988234700927644310658336581857679208804861661335768169851589929150626616698506529354785376916490328643358410300092039405295348822918174724269387
g = 125119881720420900707670154269953309690838537679536446473408150363676013315875914220318853661265626997530402259420104771257078966641464155686445398996594055909718103795617751840611152747280651424068043671714408414771552296848509963265865300590662320297995606313265875459093865996548994154719802981360764938058

h1 = bytes_to_long(sha1(b'USERNAME=123&LEVEL=Saiyan').digest())
r1 = bytes_to_long(b'M\xc3\xbek\xf1\xe7\x02\xfaY\xd9D\xa1\xb8\x13\x86(ZB.\xce\x98"\xb4Z\x84f\xbb\xf4\x14\xcf1\xdf\x90Y\x81\xd1\x00\xa1D\x10\xc6jTp\xdc\xe9.\xdf\xcd\x89\xd1\x12A\xab\xf7\x7f_x\xfai\xf8\tP\xf6\xb6.g\xb0E\x1c\x8c\x8f\xdc\x15\x87\x0c-\x92\xe8@t\xa7\xef\xe6\xdav\xee\xdd\x03\xf7\xc2R\xb3\x15\xac\'\xfdH\\T\x95\x85W\'sVf\x17\x98>\x0c*\xe45\xfd\xe8E\xf94\x0f\xafIq1\t$<e')
s1 = bytes_to_long(b'Eg\x19x\xf3\x81\xcbu\xdb\x03L\xd6\xd1\xf0JZkE\xf4\x8c\xac\xa2\xb5\xcc\x1d\x96\x98\xb27a\xa1\x98\xbe\xf3vxTqZ\x9d\xe0\x03~\x8fg\xda\xe6\x18-\xd1\xe2!\x11\x9f\x87Bc\t\xff\xd3c\x0e\xaf\xe5;\xe43\'\x88\x05\xee\xf0\x8b\xa6\xe0f\xb3-C\xcf\x92\x89??\x9b\x1d\xcc\xc0}H\x96\xa1\xac[\x10^\xb6\x90\xa5\xa1X\xff,V\x8d\xfd}\xe3[\x17H\xd2_Bs\x1b}[|\xf9\x16@^\xdbJ&^\x9a')

h2 = bytes_to_long(sha1(b'USERNAME=ww&LEVEL=Saiyan').digest())
r2 = bytes_to_long(b'M\xc3\xbek\xf1\xe7\x02\xfaY\xd9D\xa1\xb8\x13\x86(ZB.\xce\x98"\xb4Z\x84f\xbb\xf4\x14\xcf1\xdf\x90Y\x81\xd1\x00\xa1D\x10\xc6jTp\xdc\xe9.\xdf\xcd\x89\xd1\x12A\xab\xf7\x7f_x\xfai\xf8\tP\xf6\xb6.g\xb0E\x1c\x8c\x8f\xdc\x15\x87\x0c-\x92\xe8@t\xa7\xef\xe6\xdav\xee\xdd\x03\xf7\xc2R\xb3\x15\xac\'\xfdH\\T\x95\x85W\'sVf\x17\x98>\x0c*\xe45\xfd\xe8E\xf94\x0f\xafIq1\t$<e')
s2 = bytes_to_long(b'D\xd1\xf6\xa8\xff|8\xfa\x85\xec\x96\x9b\xc8\xcdH[\xf7\xa0\xf9\xfdt\x07\xc9H\xff\xef\xeb.\xfd\xf0\xdbb\xab\x1aG\xb4B\xc3!\xe6\xbc\xbb]\xc8\t\x8cKej\x95\xcd\x84\xfe\x7fA\x8cVf\xbf\xa1\x11\nV\xed\x06b\xb8W\x1aXD%J\xe3\x1a\xb8\x9a!\x87\x15\xdfY\x1a\x11n{\xd5\rc\xf5C&4\xcc)\t%\xb6\x7f\xc1r\xf2\xaf\x9a\xc3\xc2\x9f9\xfd:,\x84\x13\x94\x89\xbfKS\xe7\x8f8=\xc0\x16\xa41>\x91')

h3 = bytes_to_long(sha1(b'USERNAME=1&LEVEL=Saiyan').digest())
r3 = bytes_to_long(b'M\xc3\xbek\xf1\xe7\x02\xfaY\xd9D\xa1\xb8\x13\x86(ZB.\xce\x98"\xb4Z\x84f\xbb\xf4\x14\xcf1\xdf\x90Y\x81\xd1\x00\xa1D\x10\xc6jTp\xdc\xe9.\xdf\xcd\x89\xd1\x12A\xab\xf7\x7f_x\xfai\xf8\tP\xf6\xb6.g\xb0E\x1c\x8c\x8f\xdc\x15\x87\x0c-\x92\xe8@t\xa7\xef\xe6\xdav\xee\xdd\x03\xf7\xc2R\xb3\x15\xac\'\xfdH\\T\x95\x85W\'sVf\x17\x98>\x0c*\xe45\xfd\xe8E\xf94\x0f\xafIq1\t$<e')
s3 = bytes_to_long(b'<\x0e0\xef\xfd\x1b\r!\xa9Wf\xee\xc9\xad\xa5\x9d\x17\xe8l\xfaP\xd2}\t\x8f.b\x80\xc9\xe3\x15^\x96\x12ASxm\x85\xa0\xc8\x8b8\xe2\x03\xb3$Su\x92p&\xee"\xa6\x80\xe2\xdc\xa5g\x9b+lS\x1ca\x0c\x88+z\xd3\xa9\xec\xf9\x8f>\x97\xcb\xdd\x86\xb3UE\xc3{\xc4Vt\xd4\xce\xba\xe9C\xa5\xc3\xfe\x85l\x86ew\xc1\xda\x97\xad\x87Q\x82\xea\xb1aO\n\x9d\xdf\xafTU\xb4\xea\xbf\x9e,\x05\xce\xfbO\x18')

h = bytes_to_long(sha1(b'USERNAME=123&LEVEL=SuperSaiyan').digest())

k = (h1 - h2) * pow(s1-s2,-1,p-1) % (p-1)
x = (h1 - k * s1)*pow(r1,-1,p-1) % (p-1)
assert s1 == ((h1 - x*r1)*pow(k,-1,p-1) %(p-1))
assert s2 == ((h2 - x*r2)*pow(k,-1,p-1) %(p-1))
assert s3 == ((h3 - x*r3)*pow(k,-1,p-1) %(p-1))

r = r1
s = (h - x*r)*pow(k,-1,p-1) % (p-1)
S = b'USERNAME=123&LEVEL=SuperSaiyan' + b'&r=' + long_to_bytes(r) + b'&s=' + long_to_bytes(s)

print(base64.b64encode(S))
```

Lúc `verify` nhập token `SuperSaiyan` là được flag.
```
VVNFUk5BTUU9MTIzJkxFVkVMPVN1cGVyU2FpeWFuJnI9TcO+a/HnAvpZ2UShuBOGKFpCLs6YIrRahGa79BTPMd+QWYHRAKFEEMZqVHDc6S7fzYnREkGr939fePpp+AlQ9rYuZ7BFHIyP3BWHDC2S6EB0p+/m2nbu3QP3wlKzFawn/UhcVJWFVydzVmYXmD4MKuQ1/ehF+TQPr0lxMQkkPGUmcz00i9EUt9d/ifwYU8pc8sxN/4O/O3kJD8+gBPYHAqSo5dKoMw7gI2S7GjkmJYg2MohUKYFK+Y+aV//wUdaBC5yVymcTGs3AM5mJqYOGXR+/9N3frdCGKwLNcaagdoepYUFKMxYfrD4u+BU67uTDuQoc+ol0bGNmtY6wfB/jNvZVEA==
```

***

## RSA PTA (100pts)

`chal.py`
```python
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
```

Challenge tạo hai số nguyên tố `p`, `q`, mã hóa một số ngẫu nhiên `m`, trả về `m` và bản mã `c`; yêu cầu nhập `p`, `q` và `d` sao cho `m == pow(c, d, n)` (với n=pq).

Như vậy mình cần tìm hai số nguyên tố sao cho việc tính logarit được dễ dàng một chút.

Sau khi tìm được *dp*, *dq* sao cho m ≡ c<sup>dp</sup> (mod p) và m ≡ c<sup>dq</sup> (mod q), tìm *d* bằng cách lấy d ≡ dp (mod p-1) và d ≡ dq (mod q-1).

```python
from sage.all import *
from pwn import remote

r = remote('61.28.237.24', 30304)
m,c = r.recvuntil("\n",drop=True).split()
m,c = int(m),int(c)
print(m,c)

def gen_prime():
    while True:
        p = 2
        r = randint(10,15)
        for i in range(55):
            p *= random_prime(2**r,False,2**(r-1))
        if is_prime(p+1):
            return p+1

primes = []
ds = []
while True:
    p = gen_prime()
    try:
        d = discrete_log(Mod(m,p),Mod(c,p))
        assert pow(Mod(c,p),d,p) == Mod(m,p) and p.nbits() > 511 and p.nbits() < 1024
        
        if len(primes) != 0:
            assert (ds[0] - d) % gcd(primes[0]-1,p-1) == 0
        primes.append(p)
        ds.append(d)
        if len(primes) == 2:
            break
    except:
        continue

_,u,v = xgcd(primes[0]-1,primes[1]-1)
l = (ds[0] - ds[1])//gcd(primes[0]-1,primes[1]-1)
d = (ds[0] - (primes[0]-1)*u*l) % LCM(primes[0]-1,primes[1]-1)
assert m == pow(c,d,primes[0]*primes[1])

p = min(primes)
q = max(primes)
print(p,q)

r.sendline(str(p))
r.sendline(str(q))
r.sendline(str(d))

print(r.recv())
```
