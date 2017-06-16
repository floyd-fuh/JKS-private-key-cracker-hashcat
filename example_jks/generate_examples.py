#!/usr/bin/env pypy
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

import os
def executeInShell(command):
    import subprocess
    process = subprocess.Popen(command, shell=True)
    process.wait()


for passw in ["123456", "1234567", "12345678", "123456789", "1234567890"]:
    # RSA - can be pretty much arbitrary
    for keysize in ["512", "777", "1024", "2048", "4096", "8192"]:
        executeInShell("keytool -genkey -dname 'CN=test, OU=test, O=test, L=test, S=test, C=CH' -noprompt -alias "+passw+" -keysize "+keysize+" -keyalg RSA -keystore rsa_"+keysize+"_"+passw+".jks -storepass "+passw+ " -keypass "+passw)
    # DSA - so far only these two sizes worked for me
    for keysize in ["512", "1024"]:
        executeInShell("keytool -genkey -dname 'CN=test, OU=test, O=test, L=test, S=test, C=CH' -noprompt -alias "+passw+" -keysize "+keysize+" -keyalg DSA -keystore dsa_"+keysize+"_"+passw+".jks -storepass "+passw + " -keypass "+passw)
    # EC - these are all that work in my version of keytool
    for curve in ["256", "283", "359", "384", "409", "431", "521"]: #[str(x) for x in range(256, 571)]:
        executeInShell("keytool -genkey -dname 'CN=test, OU=test, O=test, L=test, S=test, C=CH' -noprompt -alias "+passw+" -keysize "+curve+" -keyalg EC -keystore ec_"+curve+"_"+passw+".jks -storepass "+passw + " -keypass "+passw)

#Now one example KeyStore that has two keys in it...
executeInShell("keytool -genkey -dname 'CN=test, OU=test, O=test, L=test, S=test, C=CH' -noprompt -alias first -keysize 2048 -keyalg RSA -keystore twokeys_123456.jks -storepass 123456 -keypass 123456")
executeInShell("keytool -genkey -dname 'CN=test, OU=test, O=test, L=test, S=test, C=CH' -noprompt -alias second -keysize 4096 -keyalg RSA -keystore second.jks -storepass 123456 -keypass 222222")
executeInShell("keytool -importkeystore -srckeystore second.jks -destkeystore twokeys_123456.jks -srcstorepass 123456 -deststorepass 123456 -srckeypass 222222 -srcalias second")
os.remove("second.jks")
