#!/usr/bin/env pypy
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

# Reads a private key entry from a Java Key Store that was prepared with JksPrivkPrepare.jar and decrypts it with the given password. The format this script reads is:
# $jksprivk$*checksum*iv*encrypted private key*1 byte DER proof (byte 0)*14 bytes DER proof (bytes 6 to 19)*private key alias (only metadata)

import sys
import os
import struct
import string
import itertools
from binascii import hexlify
import hashlib

def get_key(encr, keystream, keylength, passwd):
    """Stage 2: Do everything from the second round and decrypt the rest of the key with the password"""
    count = 0
    key = ""
    while count < keylength:
        sha = hashlib.sha1()
        sha.update(passwd+keystream)
        keystream = sha.digest()
        for i in range(0, len(keystream)):
            if not count < keylength:
                break
            key += chr(ord(keystream[i]) ^ ord(encr[count]))
            count += 1
    return key

def decrypt_with_password(passwd, first_two, four_to_eight, encr, keystream, check, keylength):
    key = get_key(encr, keystream, keylength, passwd)
    sha = hashlib.sha1()
    #print "Stage last checksum: Input to sha.update:", passwd.encode("hex"), key.encode("hex")
    sha.update(passwd+key)
    if check == sha.digest():
        # print "checksum", check.encode("hex"), "matches", sha.digest().encode("hex")
        return key
    else:
        print "Checksum mismatch with password", repr(passwd)
        #exit(1)
        return None

def bytes_to_chars(passwd):
    """Removing every second byte (zero bytes)"""
    return passwd[1::2]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <prepared file> <password> \n" % sys.argv[0])
        sys.exit(-1)
        
    for i in range(1, len(sys.argv))[::2]:
        f = file(sys.argv[i], "r")
        password = '\x00' + '\x00'.join(list(sys.argv[i+1]))
        for line in f:
            values = line.rstrip().split("*")
            sig = values[0]
            alias = values[-1]
            checksum, iv, encr, first_two, four_to_eight = [x.decode("hex") for x in values[1:-1]]
            keylength = len(encr)
            key = decrypt_with_password(password, first_two, four_to_eight, encr, iv, checksum, keylength)
            if key:
                filename = sys.argv[i]+"_"+alias+".der"
                o = file(filename, "w")
                o.write(key)
                o.close()
                print "You can use the following command to convert "+filename+" to a normal Encrypted PEM file:"
                print "openssl pkcs8 -in "+filename+" -topk8 -inform der"
        f.close()
