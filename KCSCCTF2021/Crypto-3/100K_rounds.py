from passlib.hash import pbkdf2_sha256
from flag import FLAG


while True:
    try:
        pw1 = bytes.fromhex(input("Password 1: "))
        pw2 = bytes.fromhex(input("Password 2: "))

        if pw1 != pw2:
            k1 = pbkdf2_sha256.hash(pw1, rounds=100000, salt=b'SaltAndSugar')
            k2 = pbkdf2_sha256.hash(pw2, rounds=100000, salt=b'SaltAndSugar')
            
            if k1 == k2 and b"KCSC" in pw1:
                idx = int.from_bytes(pw2[:2],"big")
                print(FLAG[idx: ])
                break
                
            else:
                print("Try again.")

        else:
            print("Password 1 should be different from Password 2.")

    except:
        break
