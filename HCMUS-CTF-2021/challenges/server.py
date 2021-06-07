#!/usr/bin/env python

from Crypto.Cipher import AES
from select import select
import sys

def padding(plaintext):

    plaintext_length = len(plaintext)
    padding_length = 0
    
    if plaintext_length % 32 != 0:
        padding_length = (plaintext_length // 32 + 1) * 32
    else:
        padding_length = 0
    return padding_length

def main():
    flag = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" # TODO 
    key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" # TODO
    
    padding_character = "D"
    
    assert (len(flag) == 32) and (len(key) == 32)
    cipher = AES.new(key, AES.MODE_ECB)

    banner = """
 _   _  ____ __  __ _   _ ____         ____ _____ _____
| | | |/ ___|  \/  | | | / ___|       / ___|_   _|  ___|
| |_| | |   | |\/| | | | \___ \ _____| |     | | | |_
|  _  | |___| |  | | |_| |___) |_____| |___  | | |  _|
|_| |_|\____|_|  |_|\___/|____/       \____| |_| |_|

"""
    sys.stdout.write(banner)
    sys.stdout.write("Welcome to AES-ECB Encryption Machine. \nPlease give us your plaintext, we'll give you its ciphertext!!!!")
    sys.stdout.write("\n=====================================\n")
    sys.stdout.flush()

    while True:
        try:
            sys.stdout.write('\nYour input: ')
            sys.stdout.flush()

            rlist, _, _ = select([sys.stdin], [], [])

            inp = ''
            if rlist:
                user_input = sys.stdin.readline().rstrip('\n')

            plaintext = user_input + flag
            padding_length = padding(plaintext)
            plaintext = plaintext.ljust(padding_length, padding_character)
            
            sys.stdout.write('The ciphertext:\n{}\n\n'.format((cipher.encrypt(plaintext)).encode('hex')))
        except KeyboardInterrupt:
            exit(0)   

if __name__ == '__main__':
    main()

