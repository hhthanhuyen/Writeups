from fastecdsa import curve, ecdsa, keys
from flag import FLAG
import json


m = "KCSC"

private_key, public_key = keys.gen_keypair(curve.P256)
print(public_key)


while True:
    try:
        usr_input = json.loads(input())
        
        if usr_input["option"] == "flip":
            index = usr_input["index"]
            flipped_key = private_key ^ (1 << index)
            r, s = ecdsa.sign(m, flipped_key)
            res = {"r": r, "s": s}
            print(json.dumps(res))
        
        if usr_input["option"] == "guess":
            if usr_input["private_key"] == private_key:
                res = {"message": FLAG}
                print(json.dumps(res))
                break
                
            else:
                res = {"message": "Try again."}
                print(json.dumps(res))
                
    except:
        break

