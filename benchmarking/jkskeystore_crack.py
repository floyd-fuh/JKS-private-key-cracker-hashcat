#!/usr/bin/env pypy
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

import sys
import os
import struct
import string
import itertools
from binascii import hexlify
import hashlib


def crack_password(encr, check):
    alphabet = string.digits #+ string.ascii_lowercase
    for passwd in next_brute_force_token(alphabet, minimum=6):
        sha = hashlib.sha1()
        sha.update(passwd)
        sha.update("Mighty Aphrodite")
        sha.update(encr)
        if check == sha.digest():
            return passwd
    print "Brute force unsucessful"

# Helper functions
def next_brute_force_token(alphabet, minimum=1, maximum=10):
    # This is the function that would need performance optimization, but that's not really the point here
    for i in range(minimum, maximum+1):
        for word in itertools.product(alphabet, repeat=i):
            yield '\x00' + '\x00'.join(word)

def bytes_to_chars(passwd):
    """Removing every second byte (zero bytes)"""
    return passwd[1::2]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <prepared file> \n" % sys.argv[0])
        sys.exit(-1)
        
    for i in range(1, len(sys.argv)):
        f = file(sys.argv[i], "r")
        #this will only process the first line
        values = f.readline().rstrip().split(":")[1].split("$")
        encr = values[4].decode("hex")
        check = values[5].decode("hex")
        f.close()
        password = crack_password(encr, check)
        #file("test12.EncryptedPrivateKeyInfo", "w").write(encrypted_private_key_info)
        password_clear = bytes_to_chars(password)
        print "Password:", repr(password_clear)
