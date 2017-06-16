#!/usr/bin/env pypy
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

#Attention: This script needs numpy installed in pypy. Usually something like this will do the trick:
#pypy -m pip install numpy

import sys
import os
import struct
import string
import itertools
from binascii import hexlify
import hashlib
import numpy

def xor(data, key):
    #print len(data), len(key)
    dt = numpy.dtype('B');
    return numpy.bitwise_xor(numpy.fromstring(key, dtype=dt), numpy.fromstring(data, dtype=dt)).tostring()

def get_keystream(keystream, keylength, passwd):
    for _ in range(0, (keylength // 20)+1):
        sha = hashlib.sha1()
        sha.update(passwd+keystream)
        keystream = sha.digest()
        yield keystream

def get_key(encr, keystream, keylength, passwd):
    #key = xor(keystreams[:len(encr)], encr)
    key = xor("".join(get_keystream(keystream, keylength, passwd))[:len(encr)], encr)
    return key

def crack_password(first_two, four_to_eight, encr, keystream, check, keylength):
    alphabet = string.digits #+ string.ascii_lowercase
    #Stage 1
    for passwd in next_brute_force_token(alphabet, minimum=6):
        #print repr(passwd)
        key = get_key(encr, keystream, keylength, passwd)
        sha = hashlib.sha1()
        #print "Stage last checksum: Input to sha.update:", passwd.encode("hex"), key.encode("hex")
        sha.update(passwd+key)
        if check == sha.digest():
            # print "checksum", check.encode("hex"), "matches", sha.digest().encode("hex")
            return passwd, key
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
        for line in f:
            values = line.rstrip().split(":")
            sig = values[0]
            alias = values[-1]
            checksum, iv, encr, first_two, four_to_eight = [x.decode("hex") for x in values[1:-1]]
            keylength = len(encr)
            password, key = crack_password(first_two, four_to_eight, encr, iv, checksum, keylength)
            #file("test12.EncryptedPrivateKeyInfo", "w").write(encrypted_private_key_info)
            password_clear = bytes_to_chars(password)
            #print "Alias of private key:", alias
            #print "Password in Java version:", repr(password)
            print "Password:", repr(password_clear)
            #print "Key:", key.encode("hex").upper()
            filename = sys.argv[i]+".der"
            o = file(filename, "w")
            o.write(key)
            o.close()
            #print "You can use the following command to convert "+filename+" to a normal Encrypted PEM file:"
            #print "openssl pkcs8 -in "+filename+" -topk8 -inform der"
        f.close()
