#!/usr/bin/env pypy
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

import itertools
def next_brute_force_token(alphabet, minimum=1, maximum=10):
    for i in range(minimum, maximum+1):
        for word in itertools.product(alphabet, repeat=i):
            yield ''.join(word)
a = file("wordlist.txt", "w")
for i in next_brute_force_token("0123456789", 6, 8):
    a.write(i+"\n")
a.close()
