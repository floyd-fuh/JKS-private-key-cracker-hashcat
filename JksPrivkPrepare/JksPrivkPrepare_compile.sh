#!/bin/bash
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

#Should work with Java 6 and above...
javac JksPrivkPrepare.java
jar cfe JksPrivkPrepare.jar JksPrivkPrepare *.class 
rm *.class
mv JksPrivkPrepare.jar ..
