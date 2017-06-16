#!/bin/bash
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

#Example dependencies for Debian based Linux included (but is usually tested on OSX)
#pypy to run POC, JRE to run hash preparation script (and is assumed will install Java's keytool into your $PATH)
#sudo apt-get install pypy openjdk-8-jre

#If you don't have Java 8, but can install Java 7 (also Java 6 should work):
#sudo apt-get install openjdk-7-jre openjdk-7-jdk 
#If you are on Java 8 you don't need to do this:
#cd JksPrivkPrepare
#./JksPrivkPrepare_compile.sh
#cd ..

#This could produce errors if not all elliptic curves are available, just ignore
cd ./example_jks
pypy ./generate_examples.py
cd ..

echo "Cracking the password of the store with two keys"
java -jar JksPrivkPrepare.jar ./two_keys_one_keystore/rsa.jks > ./two_keys_one_keystore/rsa_prepared.hashes
pypy ./jksprivk_crack.py ./two_keys_one_keystore/rsa_prepared.hashes

echo "Cracking the password of example keys"
./run_example_jks.sh

#If you want to run the benchmarks, you need some more dependencies...

#you need John the Ripper, which needs libssl-dev
#sudo apt-get install libssl-dev
#cd /opt/
#wget http://www.openwall.com/john/j/john-1.8.0-jumbo-1.tar.gz
#tar xvf john-1.8.0-jumbo-1.tar.gz
#cd ./john-1.8.0-jumbo-1/src
#./configure
#make

#You also need numpy in pypy, for that you need Python.h of pypy-dev and git for cloning
#Try the following first (it will fail if your pypy is too old):
#sudo apt-get install pypy-dev git
#git clone https://bitbucket.org/pypy/numpy.git
#cd numpy
#pypy setup.py install
#cd ..
#which would all be fine, but the problem is that most Debian-based systems have horribly outdated PyPy in the repository
#In that case, make sure you install a recent version of PyPy... eg. compile it http://pypy.org/download.html#translate

#Now you can run the benchmark. But ATTENTION: the wordlist it creates is nearly 5GB. 
#I simply couldn't convince John the Ripper to count from 000000 upwards without optimisations.
#cd benchmarking
#pypy ./generate_wordlist.py
#Then you can edit test_run.sh if you like. As the performance differs a lot, 
#you don't want to give too long passwords to most of them as you would wait forever.
#In the default configuration it compares JtR to the Python crack implementation with 
#password lengths 8 and incrementing
#./test_run.sh
