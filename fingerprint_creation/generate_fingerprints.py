#!/usr/bin/env pypy
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

# A pretty hacky way of generating all kind of key pairs in a JKS,
# then extract the private key entry of the JKS, decrypt it and
# check which bytes can be used as a fingerprint

# This script only have to be used, if you need to generate new fingerprints

import glob
import struct
import subprocess
import pprint
import tempfile
import os
import random
import string
import sys

MAGIC = 0xfeedfeed
VERSION_1 = 0x01
VERSION_2 = 0x02

def between_markers(content, start, end, with_markers=False):
    if start and end and start in content and end in content:
        if with_markers:
            start_index = content.index(start)
            end_index = content.index(end, start_index + len(start)) + len(end)
        else:
            start_index = content.index(start) + len(start)
            end_index = content.index(end, start_index)
        if end_index:
            return content[start_index:end_index]
    return None

def parse_certificate(certdata):
    # I think openssl on the command line is easier for users rather than installing a python library for openssl as well
    _, tmp_path = tempfile.mkstemp()
    f = file(tmp_path, "w")
    f.write(certdata)
    f.close()
    cmd = "openssl x509 -in %s -inform DER -noout -text" % tmp_path
    out = executeInShell(cmd)
    out = out.lower()
    keytype = ""
    if "public key algorithm: dsa" in out:
        keytype = "DSA"
    elif "public key algorithm: id-ec" in out:
        keytype = "EC"
        marker = "asn1 oid: "
        #it is actually curve, but we set the keysize here
        keysize = between_markers(out, marker, "\n")
        # print keysize
    elif "public key algorithm: rsa" in out:
        keytype = "RSA"
    else:
        sys.stderr.write("Error! Could not determine key type of certificate/public key in keystore (DSA, RSA, EC)")
        exit(1)
    if keytype == "RSA" or keytype == "DSA":
        cmd = "openssl x509 -in %s -inform DER -modulus" % tmp_path
        out = executeInShell(cmd)
        modulus = between_markers(out, "Modulus=", "\n")
        if len(modulus) % 2 == 1:
            modulus = "0"+modulus
        keysize = len(modulus.decode("hex")) * 8
        # print keysize
    os.remove(tmp_path)
    return keytype + "_" + str(keysize)
    

def get_certificate_characteristics(filename):
    try:
        fd = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("! %s: %s\n" % filename, str(e))
        return

    # read the entire file into data variable
    data = fd.read()
    fd.seek(0, os.SEEK_SET)

    # start actual processing
    buf = fd.read(4)
    xMagic = struct.unpack("> I", buf)[0]
    buf = fd.read(4)
    xVersion = struct.unpack("> I", buf)[0]

    if (xMagic != MAGIC or (xVersion != VERSION_1 and xVersion != VERSION_2)):
        sys.stderr.write("Invalid keystore format\n")
        return

    buf = fd.read(4)
    count = struct.unpack("> I", buf)[0]

    for i in range(0, count):
        buf = fd.read(4)
        tag = struct.unpack("> I", buf)[0]

        if (tag == 1):  # key entry
            # Read the alias
            p = ord(fd.read(1))
            length = ord(fd.read(1))
            alias = fd.read(length)
            assert(len(alias) == length)

            # Read the (entry creation) date
            buf = fd.read(8)
            assert(len(buf) == 8)

            # Read the key
            buf = fd.read(4)
            keysize = struct.unpack("> I", buf)[0]
            protectedPrivKey = fd.read(keysize)

            # read certificates
            buf = fd.read(4)
            numOfCerts = struct.unpack("> I", buf)[0]
            for j in range(0, numOfCerts):
                if xVersion == 2:
                    # read the certificate type
                    p = ord(fd.read(1))
                    assert(p == 1 or p == 0)
                    length = ord(fd.read(1))
                    buf = fd.read(length)

                # read certificate data
                buf = fd.read(4)
                certsize = struct.unpack("> I", buf)[0]
                certdata = fd.read(certsize)
                assert(len(certdata) == certsize)
                yield alias, protectedPrivKey, parse_certificate(certdata)

            # We can be sure now that numOfCerts of certs are read
        elif (tag == 2):  # trusted certificate entry
            # Read the alias
            p = fd.read(1)
            length = ord(fd.read(1))
            buf = fd.read(length)

            # Read the (entry creation) date
            buf = fd.read(8)

            # Read the trusted certificate
            if xVersion == 2:
                # read the certificate type
                p = fd.read(1)
                length = ord(fd.read(1))
                buf = fd.read(length)

            buf = fd.read(4)
            certsize = struct.unpack("> I", buf)[0]
            certdata = fd.read(certsize)
        else:
            sys.stderr.write("Unrecognized keystore entry")
            fd.close()

    # how much data have we processed
    # pos = fd.tell()
    # read hash
    # md = fd.read(20)
    # assert(len(md) == 20)
    # md is now the hash of the Java KeyStore. However, we don't care about that hash
    # as we are attacking individual Private Keys here.

def executeInShell(command):
    #print command
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    process.wait()
    #sys.stderr.write(stdout)
    return stdout #, stderr

der_mappings = {"RSA": ('0', '\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01')}

#sigalgs don't matter, because we are looking at the private key, which has nothing to do with the signing algorithm in the certificate
#sigalgs_rsa = [(512, "MD2withRSA"), (512, "MD5withRSA"), (512, "SHA1withRSA"), (512, "SHA256withRSA"), (617, "SHA384withRSA"), (745, "SHA512withRSA")]
#sigalgs_dsa = ["SHA1withDSA"]
#sigalgs_ec = ["SHA1withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"]

def randString():
    l = random.randint(6, 10)
    return "".join([random.choice(string.ascii_letters) for _ in range(0, l)])
    


def process_keystore(keystore, storepasswd, keypasswd):
    #print keystore
    keystore_path = "./"+keystore+".jks"
    for alias_from_file, encrypted_private_key_info, details in get_certificate_characteristics(keystore_path):
        # The der_mappings generation
        cmd = "java KeyPrinter %s %s %s %s" % (storepasswd, keystore_path, alias_from_file, keypasswd)
        out = executeInShell(cmd).rstrip().decode("hex")
        # if details.startswith("RSA"):
        #     fingerprint = out[0:2] + out[4:20]
        # elif details.startswith("DSA"):
        #     fingerprint = out[0] + out[4:20]
        # elif details.startswith("EC"):
        #     fingerprint = out[0] + out[2:5] + out[6:20]
        #So basically what they have in common is:
        
        fingerprint = (out[0], out[6:20])
        assert(len(fingerprint) != 0)
        if fingerprint == der_mappings["RSA"] and details.startswith("RSA"):
            pass
        else:
            if not details in der_mappings:
                der_mappings[details] = set()
            der_mappings[details].add(fingerprint)


def print_mappings():
    pprint.pprint(der_mappings)
    for key in der_mappings:
        der_mappings[key] = list(der_mappings[key])[0]
    print "Filtered:"
    pprint.pprint(der_mappings)

rsa_keysize = 512

while True:
    storepasswd = randString()
    keypasswd = randString()
    cn = randString()    
    gen_alias = randString()
    
    # RSA - can be pretty much arbitrary
    #minimum, sigalg = random.choice(sigalgs_rsa)
    #while minimum > rsa_keysize:
    #    minimum, sigalg = random.choice(sigalgs_rsa)
    keysize = str(rsa_keysize)
    rsa_keysize += 8
    keystore = "RSA_"+str(keysize)
    try:
        os.remove("./"+keystore+".jks")
    except OSError:
        pass
    cmd = "keytool -genkey -dname 'CN="+cn+", OU="+cn+", O="+cn+", L="+cn+", S="+cn+", C=CH' -noprompt -alias "+gen_alias+" -keysize "+keysize+" -keyalg RSA -keystore "+keystore+".jks -storepass "+storepasswd+ " -keypass "+keypasswd #+ " -sigalg "+sigalg
    executeInShell(cmd)
    process_keystore(keystore, storepasswd, keypasswd)
    
    # DSA
    keysize = random.choice(["512", "1024"])
    #sigalg = random.choice(sigalgs_dsa)
    keystore = "DSA_"+str(keysize)
    try:
        os.remove("./"+keystore+".jks")
    except OSError:
        pass
    cmd = "keytool -genkey -dname 'CN="+cn+", OU="+cn+", O="+cn+", L="+cn+", S="+cn+", C=CH' -noprompt -alias "+gen_alias+" -keysize "+keysize+" -keyalg DSA -keystore "+keystore+".jks -storepass "+storepasswd+ " -keypass "+keypasswd #+ " -sigalg "+sigalg
    executeInShell(cmd)
    process_keystore(keystore, storepasswd, keypasswd)
    
    # EC - these are all that work in my version of keytool
    keysize = random.choice(["256", "283", "359", "384", "409", "431", "521"]) #[str(x) for x in range(256, 571)]:
    #sigalg = random.choice(sigalgs_ec)
    keystore = "EC_"+str(keysize)
    try:
        os.remove("./"+keystore+".jks")
    except OSError:
        pass
    cmd = "keytool -genkey -dname 'CN="+cn+", OU="+cn+", O="+cn+", L="+cn+", S="+cn+", C=CH' -noprompt -alias "+gen_alias+" -keysize "+keysize+" -keyalg EC -keystore "+keystore+".jks -storepass "+storepasswd+ " -keypass "+keypasswd #+ " -sigalg "+sigalg
    executeInShell(cmd)
    process_keystore(keystore, storepasswd, keypasswd)
    
    pprint.pprint(der_mappings)
    print rsa_keysize
    