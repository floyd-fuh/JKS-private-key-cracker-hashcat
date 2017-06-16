#!/usr/bin/env pypy
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

# Reads a private key entry from a Java Key Store that was prepared with JksPrivkPrepare.jar and tries to crack the password. The format this script reads is:
# $jksprivk$*checksum*iv*encrypted private key*1 byte DER proof (byte 0)*14 bytes DER proof (bytes 6 to 19)*private key alias (only metadata)

import sys
import os
import struct
import string
import itertools
from binascii import hexlify
import hashlib

# Actually we can do the get_key function with or without numpy, numpy is faster.
# But as this method is only called once we found the password and in-practice all other
# candidates are rejected before, it doesn't really matter in practice for this implementation.
# So let's not bother users of this little POC (in practice you should use hashcat anyway)

# import numpy
#
# def xor(data, key):
#     #print len(data), len(key)
#     dt = numpy.dtype('B');
#     return numpy.bitwise_xor(numpy.fromstring(key, dtype=dt), numpy.fromstring(data, dtype=dt)).tostring()
#
# def get_keystream(keystream, keylength, passwd):
#     yield keystream
#     for _ in range(0, (keylength // 20)+1):
#         sha = hashlib.sha1()
#         sha.update(passwd+keystream)
#         keystream = sha.digest()
#         yield keystream
#
# def get_key(encr, keystream, keylength, passwd):
#     #key = xor(keystreams[:len(encr)], encr)
#     key = xor("".join(get_keystream(keystream, keylength, passwd))[:len(encr)], encr)
#     return key

#if you want to run without numpy:
def get_key(encr, keystream, keylength, passwd):
    """Stage 2: Do everything from the second round and decrypt the rest of the key with the password"""
    count = 0
    key = ""
    while count < keylength:
        for i in range(0, len(keystream)):
            if not count < keylength:
                break
            key += chr(ord(keystream[i]) ^ ord(encr[count]))
            count += 1
        sha = hashlib.sha1()
        #print "Stage 2: Input to sha.update:", passwd.encode("hex"), keystream.encode("hex")
        sha.update(passwd+keystream)
        keystream = sha.digest()
    return key

def get_candidates(alphabet, first, ending, keystream):
    """Stage 1: Only do the absolutely necessary calculations that show if the password might lead to a DER private key"""
    # see precalculate_is_candidate_values
    # The performance critical parts is everything from here:
    for p in next_brute_force_token(alphabet, minimum=6):
        # print repr(p)
        sha = hashlib.sha1()
        #print "Stage 1: Input to sha.update:", p.encode("hex"), keystream.encode("hex")
        sha.update(p+keystream)
        new_keystream = sha.digest()
        # print repr(new_keystream)
        # print repr(first), repr(ending)
        if new_keystream[0] == first and new_keystream[6:] == ending:
            yield p, new_keystream

def crack_password(first, ending, encr, keystream, check, keylength):
    alphabet = string.digits #+ string.ascii_lowercase
    #Stage 1
    for passwd, keystream in get_candidates(alphabet, first, ending, keystream):
        # Now that we know this is a good candidate that matches
        # 6 bytes of the format we look for, we can calculate if this
        # is really the correct one. If not, we just go on brute forcing.
        # In the currenty implementation this does not make any difference performance-wise
        # as in practice so far I never got a candidate that wasn't the correct password...
        #Stage 2
        #print "Got candidate which looks like DER encoded (when XORed with first, fourt_to_eight)", keystream.encode("hex")
        key = get_key(encr, keystream, keylength, passwd)
        sha = hashlib.sha1()
        # print "Stage last checksum: Input to sha.update:", passwd.encode("hex"), key.encode("hex")
        sha.update(passwd+key)
        if check == sha.digest():
            # print "checksum", check.encode("hex"), "matches", sha.digest().encode("hex")
            return passwd, key
        #else:
            #print "Checksum mismatch with password", repr(passwd)
            #print "Simply going on cracking..."
    print "Brute force unsucessful"
    exit()

# Helper functions
def next_brute_force_token(alphabet, minimum=1, maximum=10):
    #return ["\x001\x002\x003\x004\x005\x006"]
    #This is the function that would need performance optimization, but that's not really the point here
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
        for line in f:
            values = line.rstrip().split("*")
            sig = values[0]
            alias = values[-1]
            checksum, iv, encr, first, ending = [x.decode("hex") for x in values[1:-1]]
            keylength = len(encr)
            password, key = crack_password(first, ending, encr, iv, checksum, keylength)
            #file("test12.EncryptedPrivateKeyInfo", "w").write(encrypted_private_key_info)
            password_clear = bytes_to_chars(password)
            #print "Alias of private key:", alias
            #print "Password in pseudo UTF-16 Java version:", repr(password)
            print "Password:", repr(password_clear)
            #print "Key:", key.encode("hex").upper()
            #filename = sys.argv[i]+"_"+alias+".der"
            #o = file(filename, "w")
            #o.write(key)
            #o.close()
            #print "You can use the following command to convert "+filename+" to a normal Encrypted PEM file:"
            #print "openssl pkcs8 -in "+filename+" -topk8 -inform der"
        f.close()
