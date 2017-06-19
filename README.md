# JKS private key cracker - Nail in the JKS coffin

The Java Key Store (JKS) is the Java way of storing one or several cryptographic private and public keys for asymmetric cryptography in a file. While there are various key store formats, Java and Android still default to the JKS file format. JKS is one of the file formats for Java key stores, but JKS is confusingly used as the acronym for the general Java key store API as well. This project includes information regarding the security mechanisms of the JKS file format and how the password protection of the private key can be cracked. Due the unusual design of JKS the developed implementation can ignore the key store password and crack the private key password directly. Because it ignores the key store password, this implementation can attack every JKS configuration, which is not the case with most other tools. By exploiting a weakness of the Password Based Encryption scheme for the private key in JKS, passwords can be cracked very efficiently. Until now, no public tool was available exploiting this weakness. This technique was implemented in hashcat to amplify the efficiency of the algorithm with higher cracking speeds on GPUs.

To get the theory part, please refer to the POC||GTFO article "15:12 Nail in the Java Key Store Coffin" in issue 0x15 included in this repository (pocorgtfo15.pdf) or available on various mirros like this beautiful one: https://unpack.debug.su/pocorgtfo/

Before you ask: JCEKS or BKS or any other Key Store format is not supported (yet).

# How you should crack JKS files

The answer is build your own cracking hardware for it ;) . But let's be a little more practical, so the answer is using your GPU:

```
    _____:  _____________         _____:  v3.6.0     ____________
   _\    |__\______    _/_______ _\    |_____ _______\______    /__ ______
   |     _     |  __   \   ____/____   _     |   ___/____  __    |_______/
   |     |     |  \    _\____      /   |     |   \      /  \     |     |
   |_____|     |______/     /     /____|     |_________/_________:     |
         |_____:-aTZ!/___________/     |_____:                 /_______:
 
* BLAKE2 * BLOCKCHAIN2 * DPAPI * CHACHA20 * JAVA KEYSTORE * ETHEREUM WALLET *
```

All you need to do is run the following command:

```
java -jar JksPrivkPrepare.jar your_JKS_file.jks > hash.txt
```

If your hash.txt ends up being empty, there is either no private key in the JKS file or you specified a non-JKS file.

Then feed the hash.txt file to hashcat (version 3.6.0 and above), for example like this:

```
$ ./hashcat -m 15500 -a 3 -1 '?u|' -w 3 hash.txt ?1?1?1?1?1?1?1?1?1
hashcat (v3.6.0) starting...

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 1080, 2026/8107 MB allocatable, 20MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Applicable optimizers:
* Zero-Byte
* Precompute-Init
* Not-Iterated
* Appended-Salt
* Single-Hash
* Single-Salt
* Brute-Force

Watchdog: Temperature abort trigger set to 90c
Watchdog: Temperature retain trigger set to 75c

$jksprivk$*D1BC102EF5FE5F1A7ED6A63431767DD4E1569670...8*test:POC||GTFO
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Type........: JKS Java Key Store Private Keys (SHA1)
Hash.Target......: $jksprivk$*D1BC102EF5FE5F1A7ED6A63431767DD4E1569670...8*test
Time.Started.....: Tue May 30 17:41:58 2017 (8 mins, 25 secs)
Time.Estimated...: Tue May 30 17:50:23 2017 (0 secs)
Guess.Mask.......: ?1?1?1?1?1?1?1?1?1 [9]
Guess.Charset....: -1 ?u|, -2 Undefined, -3 Undefined, -4 Undefined 
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:  7946.6 MH/s (39.48ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 4014116700160/7625597484987 (52.64%)
Rejected.........: 0/4014116700160 (0.00%)
Restore.Point....: 5505024000/10460353203 (52.63%)
Candidates.#1....: NNVGFSRFO -> Z|ZFVDUFO
HWMon.Dev.#1.....: Temp: 75c Fan: 89% Util:100% Core:1936MHz Mem:4513MHz Bus:1

Started: Tue May 30 17:41:56 2017
Stopped: Tue May 30 17:50:24 2017
```

So from this repository you basically only need the JksPrivkPrepare.jar to run a cracking session.

# Other things in this repository

* test_run.sh: A little test script that you should be able to run after a couple of minutes to see this project in action. It includes comments on how to setup the dependencies for this project.
* benchmarking: tests that show why you should use this technique and not others. Please read the "Nail in the JKS coffin" article.
* example_jks: generate example JKS files
* fingerprint_creation: Every plaintext private key in PKCS#8 has it's own "fingerprint" that we expect when we guess the correct password. These fingerprints are necessary to make sure we are able to detect when we guessed the correct password. Please read the "Nail in the JKS coffin" article. This folder has the code to generate these fingerprints, it's a little bit hacky but I don't expect that it will be necessary to add any other fingerprints ever.
* JksPrivkPrepare: The source code of how the JKS files are read and the hash calculated we need to give to hashcat.
* jksprivk_crack.py: A proof of concept implementation that can be used instead of hashcat. Obviously this is much slower than hashcat, but it can outperform John the Ripper (JtR) in certain cases. Please read the "Nail in the JKS coffin" article.
* jksprivk_decrypt.py: A little helper script that can be used to extract a private key once the password was correctly guessed.
* run_example_jks.sh: A script that runs JksPrivkPrepare.jar and jksprivk_crack.py on all example JKS files in the example_jks folder. Make sure you run the generate_examples.py in example_jks script before.

# Related work and further links

A big shout to Casey Marshall who wrote the JKS.java class, which is used in a modified version in this project:

```
/* JKS.java -- implementation of the "JKS" key store.
   Copyright (C) 2003  Casey Marshall <rsdio@metastatic.org>

Permission to use, copy, modify, distribute, and sell this software and
its documentation for any purpose is hereby granted without fee,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation.  No representations are made about the
suitability of this software for any purpose.  It is provided "as is"
without express or implied warranty.

This program was derived by reverse-engineering Sun's own
implementation, using only the public API that is available in the 1.4.1
JDK.  Hence nothing in this program is, or is derived from, anything
copyrighted by Sun Microsystems.  While the "Binary Evaluation License
Agreement" that the JDK is licensed under contains blanket statements
that forbid reverse-engineering (among other things), it is my position
that US copyright law does not and cannot forbid reverse-engineering of
software to produce a compatible implementation.  There are, in fact,
numerous clauses in copyright law that specifically allow
reverse-engineering, and therefore I believe it is outside of Sun's
power to enforce restrictions on reverse-engineering of their software,
and it is irresponsible for them to claim they can.  */
```

Various more information which are mentioned in the article as well:

* JKS is going to be replace as the default type in Java 9 http://openjdk.java.net/jeps/229
* https://gist.github.com/zach-klippenstein/4631307 
* http://www.openwall.com/lists/john-users/2015/06/07/3
* https://github.com/bes/KeystoreBrute
* https://github.com/jeffers102/KeystoreCracker
* https://github.com/volure/keystoreBrute
* https://gist.github.com/robinp/2143870 
* https://www.darknet.org.uk/2015/06/patator-multi-threaded-service-url-brute-forcing-tool/
* https://github.com/rsertelon/android-keystore-recovery
* https://github.com/MaxCamillo/android-keystore-password-recover
* https://cryptosense.com/mighty-aphrodite-dark-secrets-of-the-java-keystore/
* https://hashcat.net/events/p12/js-sha1exp_169.pdf
* https://github.com/hashcat/hashcat

Neighborly greetings go out to atom, vollkorn, cem, doegox, corkami, xonox and rexploit for supporting this research in one form or another!