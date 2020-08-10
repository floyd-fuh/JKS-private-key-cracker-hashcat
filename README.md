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

Then feed the hash.txt file to hashcat (version 3.6.0 and above, but if you want to be on the safe side and also make sure you can crack very long passwords please use at least version 4 of hashcat!), for example like this:

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

# From John The Ripper format to the hashcat format

This information is only important to CTF players or hash cracking competition players. In real life you should have access to the JKS file and just use JksPrivkPrepare.jar. However, when you get an artifical challenge, you sometimes only get the "John the Ripper" hash format from `keystore2john.py`. I'll explain how you can get from the "John" format to the original JKS file (yes, the entire file is in the john hash format). Let's look at an example:

```
$ python2 keystore2john.py JKS-private-key-cracker-hashcat/example_jks/androidstudio_default_123456.jks 
androidstudio_default_123456.jks:$keystore$0$2033$feedfeed00000002000000010000000100076d79616c6961730000015c4ee06a4700000500308204fc300e060a2b060104012a021101010500048204e84e2fffc6379d0fb4a70a86dd0d0d7e08fad4422a99cf6280ce973cc53c0864e90cf94d889e03a8fbf76520e60cfad58059704850946691f089df5324c5226b86f4f3ef0a48d5d347adfb7917e41a3fd3baf3d4f777443444c605b4cc176788511ccc7534dd07a9d9da8e4dff6b3eeb17b7e17b821b9d834e936658c0db85d9bd295d36f4c62df72b4c1bcd0555110a3807a7b371caf4ff22afb781e858cf19f4519aa03efe92f6534c7dbdd8849f937deb9be54adc86b2f143e7707aba55c4d8a0809db2fa60d88b18949f89126c4e27a26a365290f2dcc6884d5e4c55ce2a404ea49d00135d09643b958c2de3ad20717bcdb396378bddd7d3001bfd38e28b365402fdff855c0b1cad20ddaf58c574ceff2b25b2a38d9a2b099136a766fef0aeca613791f2691ec7e4d2ff2d085db93a123585686802d7ccc1235788d96e693921cf136146952a8da51f4fbf15d840c40ee2131350393ea2533aa0c42a1d91154e85d495cdc9c326c8f3d8579ef0363f98b2bdcb95b0c586b692f4f3c4ebd3b49bebbccb20bc104c272d02fbad14c82b3069838a19d7432ee72870443b45cfe9848d4c059da24a40f3a18c1efe718a79f329a139bba29d545b67e8b675409bca08786c1b427ffd8bd45b1487314477edd54da3f774f6d4bf964a4984ba8c26212111a8e1894da7e8088ac48e3143e72b9b8982a6c0cd18a7878fe980f892bf47bb0c9d7ebcb391ea158ac0a87bff6f0ab83ff024e32b8e332b8f7f38854c0ab8c1c76f1bd5553bedbee8b96e7141a0409c6b93c5f4ae028f2441f938634470b70b724dd996bdf0f397283039871bbf931017fc7dd5f9735f66e0d5245e743cccf4ae026f1243844c413455da6c75fd16e3bd01446cca40e504901cdbec29c2be8908d0d6624a0efa480cfb350ee7deb06772010ef8d81903b0e66fb838a1c260161ac8b022f41e730b346731c414e3ea39bc6cd3090ad9705b9bb1e6f0d29321d240215b885bc57204c7110ea241e9b11fc639ddd500e5b6085d2ad1c18b2165f8c66303809c50059a6258f7a392476a1c8f6f519f7954377631e45d16d716eabaac1eccf675ad8f0b30bd1058d922e3d3f55bb3a4070101d1e0ae24ced549c6a704e001342544f2e0f173e9aed88037ff50091f268f3b4747d8028695f2932cd0cb0163442c5e667b0fb2415bdcc706194c0f24a6946a7e5eed353c3ddcc7df0806d5c4feeaf0790dbedbb3570ac41e7f48a9ab1da79e659416c3deed4ddf862e966eaea76399ae6e05692f954dff071c94d3defef00f9bf02c032e85ff13a2d9d46a9526dc3f8d68bb2e5d5f03b51fd564f0ccc83734776b40b6caac0f839c4f1bf963414df6eff87156d7450f4d74ea875f38e61e58b3d5ae58a72fb4bc316bb13f9466df799e6b464b58e23c587c5ce87bd242019aa9f6a96c59d3947d6dbd1f90def23a08c89786858c1df270d690293eb890709718227d543aaf44bda3985b805d560fbafb0ebedd122198e4f5fdba83b37471a9ad08ab4c5e4668e702e0fd3d4f30084a1cf4925e7e02c1d9355a461f2ae87e65c91765bf9cbea70517eb84294e94300c2899b4e04e8733905826a624bf01300b4422449e8a7dfd04b54cdf1f54fa1f25a32ff0907d7d7acedc7f46e81e33d1e1dfecaf71d902f3d5420980ab6e01046b4f29ca676de4a56354866a9e67cf77faa72cbb4eca95e76750f0bd982e35e7b7c072cd5d3ee8a692ebb5d6223de62a14435dff6ed7e9e9240c9c03d464afb91711000000010005582e353039000002bd308202b9308201a1a0030201020204420d78f7300d06092a864886f70d01010b0500300d310b3009060355040613025a48301e170d3137303532383131343534395a170d3432303532323131343534395a300d310b3009060355040613025a4830820122300d06092a864886f70d01010105000382010f003082010a02820101008dc6fd3c50eccc03659b7e1c1b253e6886629545fc0dd8107c237a255a25b52e3cb2f469f1f13f6d968ea1c67bbac2151141070c80e422b181c20ff61d7143d38ad7a5164201435dd8f963790db9385b9300761ead2aa44e79fdc52e5e632c3c57ecd6fc2513828ff5e2d8cec04c667ec735c341d723e367e8021e4f4226deb3ea03d8309e199d6a46ad93adc2c3f8ac4de8a8eb107e41b73ec9d2b84464dfb6c4e46cef6faeefd04f68a96ffe5cdb5db737909ce003d556b9900f12c38222ab167a7602e3cb4a9558ef45fc35ed7ccd9cd88307a0c21fbf61ecf0981afb0d9bdef527838c35e7b52e9b00c30eeae125f83d0f6606835687a025fe41e732678b0203010001a321301f301d0603551d0e04160414ba491ec3b1d084e7016d696fb07f8dbba31a2be8300d06092a864886f70d01010b050003820101008a56f06e8d77e5168a133f30f498170cdffff57d1c48352cde26b372c3e592d59654211e51c7506f55d94045642b0b319aaa6de41c63342735e02db8523ff2e02f97f3fe6dc521fb57fb6c7c22164b8af51b2f25e1bd0eab181cb68c54ada44e0f4ceb60599579805a477358b8b5487a65befd1a5c3953b1dbd81e9d7d3c5a07b03351e18dd24a1706bd9c625b3d2329245e21f3d2702153dae821f7c4a645e506643e18cdd11d9b8c31eb7c4669940551ee93b13e31e755ccbb37402302afa9a7b68c9965d6dfb22b9ef3b959fcf931cebfcddcf4874738f47294812bbcad8f1128ec9a2861a4569f849307f31999ddb3931e811a5d708b3e2202e370b188a5$44f13fd07f8bd5fb219aac5578081d72cfc89272$1$1280$308204fc300e060a2b060104012a021101010500048204e84e2fffc6379d0fb4a70a86dd0d0d7e08fad4422a99cf6280ce973cc53c0864e90cf94d889e03a8fbf76520e60cfad58059704850946691f089df5324c5226b86f4f3ef0a48d5d347adfb7917e41a3fd3baf3d4f777443444c605b4cc176788511ccc7534dd07a9d9da8e4dff6b3eeb17b7e17b821b9d834e936658c0db85d9bd295d36f4c62df72b4c1bcd0555110a3807a7b371caf4ff22afb781e858cf19f4519aa03efe92f6534c7dbdd8849f937deb9be54adc86b2f143e7707aba55c4d8a0809db2fa60d88b18949f89126c4e27a26a365290f2dcc6884d5e4c55ce2a404ea49d00135d09643b958c2de3ad20717bcdb396378bddd7d3001bfd38e28b365402fdff855c0b1cad20ddaf58c574ceff2b25b2a38d9a2b099136a766fef0aeca613791f2691ec7e4d2ff2d085db93a123585686802d7ccc1235788d96e693921cf136146952a8da51f4fbf15d840c40ee2131350393ea2533aa0c42a1d91154e85d495cdc9c326c8f3d8579ef0363f98b2bdcb95b0c586b692f4f3c4ebd3b49bebbccb20bc104c272d02fbad14c82b3069838a19d7432ee72870443b45cfe9848d4c059da24a40f3a18c1efe718a79f329a139bba29d545b67e8b675409bca08786c1b427ffd8bd45b1487314477edd54da3f774f6d4bf964a4984ba8c26212111a8e1894da7e8088ac48e3143e72b9b8982a6c0cd18a7878fe980f892bf47bb0c9d7ebcb391ea158ac0a87bff6f0ab83ff024e32b8e332b8f7f38854c0ab8c1c76f1bd5553bedbee8b96e7141a0409c6b93c5f4ae028f2441f938634470b70b724dd996bdf0f397283039871bbf931017fc7dd5f9735f66e0d5245e743cccf4ae026f1243844c413455da6c75fd16e3bd01446cca40e504901cdbec29c2be8908d0d6624a0efa480cfb350ee7deb06772010ef8d81903b0e66fb838a1c260161ac8b022f41e730b346731c414e3ea39bc6cd3090ad9705b9bb1e6f0d29321d240215b885bc57204c7110ea241e9b11fc639ddd500e5b6085d2ad1c18b2165f8c66303809c50059a6258f7a392476a1c8f6f519f7954377631e45d16d716eabaac1eccf675ad8f0b30bd1058d922e3d3f55bb3a4070101d1e0ae24ced549c6a704e001342544f2e0f173e9aed88037ff50091f268f3b4747d8028695f2932cd0cb0163442c5e667b0fb2415bdcc706194c0f24a6946a7e5eed353c3ddcc7df0806d5c4feeaf0790dbedbb3570ac41e7f48a9ab1da79e659416c3deed4ddf862e966eaea76399ae6e05692f954dff071c94d3defef00f9bf02c032e85ff13a2d9d46a9526dc3f8d68bb2e5d5f03b51fd564f0ccc83734776b40b6caac0f839c4f1bf963414df6eff87156d7450f4d74ea875f38e61e58b3d5ae58a72fb4bc316bb13f9466df799e6b464b58e23c587c5ce87bd242019aa9f6a96c59d3947d6dbd1f90def23a08c89786858c1df270d690293eb890709718227d543aaf44bda3985b805d560fbafb0ebedd122198e4f5fdba83b37471a9ad08ab4c5e4668e702e0fd3d4f30084a1cf4925e7e02c1d9355a461f2ae87e65c91765bf9cbea70517eb84294e94300c2899b4e04e8733905826a624bf01300b4422449e8a7dfd04b54cdf1f54fa1f25a32ff0907d7d7acedc7f46e81e33d1e1dfecaf71d902f3d5420980ab6e01046b4f29ca676de4a56354866a9e67cf77faa72cbb4eca95e76750f0bd982e35e7b7c072cd5d3ee8a692ebb5d6223de62a14435dff6ed7e9e9240c9c03d464afb91711:::::JKS-private-key-cracker-hashcat/example_jks/androidstudio_default_123456.jks
```

You will need to extract the part starting with "feedfeed" and the next part (`44f13fd07f8bd5fb219aac5578081d72cfc89272`) from the john format, append them to each other (in this order), hex decode it and store it into a file. So for the above example:

```
$ python2
>>> f = file("original_jks_file.jks","wb")
>>> a = "feedfeed00000002000000010000000100076d79616c6961730000015c4ee06a4700000500308204fc300e060a2b060104012a021101010500048204e84e2fffc6379d0fb4a70a86dd0d0d7e08fad4422a99cf6280ce973cc53c0864e90cf94d889e03a8fbf76520e60cfad58059704850946691f089df5324c5226b86f4f3ef0a48d5d347adfb7917e41a3fd3baf3d4f777443444c605b4cc176788511ccc7534dd07a9d9da8e4dff6b3eeb17b7e17b821b9d834e936658c0db85d9bd295d36f4c62df72b4c1bcd0555110a3807a7b371caf4ff22afb781e858cf19f4519aa03efe92f6534c7dbdd8849f937deb9be54adc86b2f143e7707aba55c4d8a0809db2fa60d88b18949f89126c4e27a26a365290f2dcc6884d5e4c55ce2a404ea49d00135d09643b958c2de3ad20717bcdb396378bddd7d3001bfd38e28b365402fdff855c0b1cad20ddaf58c574ceff2b25b2a38d9a2b099136a766fef0aeca613791f2691ec7e4d2ff2d085db93a123585686802d7ccc1235788d96e693921cf136146952a8da51f4fbf15d840c40ee2131350393ea2533aa0c42a1d91154e85d495cdc9c326c8f3d8579ef0363f98b2bdcb95b0c586b692f4f3c4ebd3b49bebbccb20bc104c272d02fbad14c82b3069838a19d7432ee72870443b45cfe9848d4c059da24a40f3a18c1efe718a79f329a139bba29d545b67e8b675409bca08786c1b427ffd8bd45b1487314477edd54da3f774f6d4bf964a4984ba8c26212111a8e1894da7e8088ac48e3143e72b9b8982a6c0cd18a7878fe980f892bf47bb0c9d7ebcb391ea158ac0a87bff6f0ab83ff024e32b8e332b8f7f38854c0ab8c1c76f1bd5553bedbee8b96e7141a0409c6b93c5f4ae028f2441f938634470b70b724dd996bdf0f397283039871bbf931017fc7dd5f9735f66e0d5245e743cccf4ae026f1243844c413455da6c75fd16e3bd01446cca40e504901cdbec29c2be8908d0d6624a0efa480cfb350ee7deb06772010ef8d81903b0e66fb838a1c260161ac8b022f41e730b346731c414e3ea39bc6cd3090ad9705b9bb1e6f0d29321d240215b885bc57204c7110ea241e9b11fc639ddd500e5b6085d2ad1c18b2165f8c66303809c50059a6258f7a392476a1c8f6f519f7954377631e45d16d716eabaac1eccf675ad8f0b30bd1058d922e3d3f55bb3a4070101d1e0ae24ced549c6a704e001342544f2e0f173e9aed88037ff50091f268f3b4747d8028695f2932cd0cb0163442c5e667b0fb2415bdcc706194c0f24a6946a7e5eed353c3ddcc7df0806d5c4feeaf0790dbedbb3570ac41e7f48a9ab1da79e659416c3deed4ddf862e966eaea76399ae6e05692f954dff071c94d3defef00f9bf02c032e85ff13a2d9d46a9526dc3f8d68bb2e5d5f03b51fd564f0ccc83734776b40b6caac0f839c4f1bf963414df6eff87156d7450f4d74ea875f38e61e58b3d5ae58a72fb4bc316bb13f9466df799e6b464b58e23c587c5ce87bd242019aa9f6a96c59d3947d6dbd1f90def23a08c89786858c1df270d690293eb890709718227d543aaf44bda3985b805d560fbafb0ebedd122198e4f5fdba83b37471a9ad08ab4c5e4668e702e0fd3d4f30084a1cf4925e7e02c1d9355a461f2ae87e65c91765bf9cbea70517eb84294e94300c2899b4e04e8733905826a624bf01300b4422449e8a7dfd04b54cdf1f54fa1f25a32ff0907d7d7acedc7f46e81e33d1e1dfecaf71d902f3d5420980ab6e01046b4f29ca676de4a56354866a9e67cf77faa72cbb4eca95e76750f0bd982e35e7b7c072cd5d3ee8a692ebb5d6223de62a14435dff6ed7e9e9240c9c03d464afb91711000000010005582e353039000002bd308202b9308201a1a0030201020204420d78f7300d06092a864886f70d01010b0500300d310b3009060355040613025a48301e170d3137303532383131343534395a170d3432303532323131343534395a300d310b3009060355040613025a4830820122300d06092a864886f70d01010105000382010f003082010a02820101008dc6fd3c50eccc03659b7e1c1b253e6886629545fc0dd8107c237a255a25b52e3cb2f469f1f13f6d968ea1c67bbac2151141070c80e422b181c20ff61d7143d38ad7a5164201435dd8f963790db9385b9300761ead2aa44e79fdc52e5e632c3c57ecd6fc2513828ff5e2d8cec04c667ec735c341d723e367e8021e4f4226deb3ea03d8309e199d6a46ad93adc2c3f8ac4de8a8eb107e41b73ec9d2b84464dfb6c4e46cef6faeefd04f68a96ffe5cdb5db737909ce003d556b9900f12c38222ab167a7602e3cb4a9558ef45fc35ed7ccd9cd88307a0c21fbf61ecf0981afb0d9bdef527838c35e7b52e9b00c30eeae125f83d0f6606835687a025fe41e732678b0203010001a321301f301d0603551d0e04160414ba491ec3b1d084e7016d696fb07f8dbba31a2be8300d06092a864886f70d01010b050003820101008a56f06e8d77e5168a133f30f498170cdffff57d1c48352cde26b372c3e592d59654211e51c7506f55d94045642b0b319aaa6de41c63342735e02db8523ff2e02f97f3fe6dc521fb57fb6c7c22164b8af51b2f25e1bd0eab181cb68c54ada44e0f4ceb60599579805a477358b8b5487a65befd1a5c3953b1dbd81e9d7d3c5a07b03351e18dd24a1706bd9c625b3d2329245e21f3d2702153dae821f7c4a645e506643e18cdd11d9b8c31eb7c4669940551ee93b13e31e755ccbb37402302afa9a7b68c9965d6dfb22b9ef3b959fcf931cebfcddcf4874738f47294812bbcad8f1128ec9a2861a4569f849307f31999ddb3931e811a5d708b3e2202e370b188a5"
>>> b = "44f13fd07f8bd5fb219aac5578081d72cfc89272"
>>> c = a + b
>>> f.write(c.decode("hex"))
>>> f.close()
```

Now you can use JksPrivkPrepare.jar on that original_jks_file.jks you just created, just like you would on any JKS file:

```
$ java -jar JksPrivkPrepare.jar original_jks_file.jks 
Alias: myalias, algorithm: RSA, keysize or field size: 2048
$jksprivk$*E62A14435DFF6ED7E9E9240C9C03D464AFB91711*4E2FFFC6379D0FB4A70A86DD0D0D7E08FAD4422A*99CF6280CE973CC53C0864E90CF94D889E03A8FBF76520E60CFAD58059704850946691F089DF5324C5226B86F4F3EF0A48D5D347ADFB7917E41A3FD3BAF3D4F777443444C605B4CC176788511CCC7534DD07A9D9DA8E4DFF6B3EEB17B7E17B821B9D834E936658C0DB85D9BD295D36F4C62DF72B4C1BCD0555110A3807A7B371CAF4FF22AFB781E858CF19F4519AA03EFE92F6534C7DBDD8849F937DEB9BE54ADC86B2F143E7707ABA55C4D8A0809DB2FA60D88B18949F89126C4E27A26A365290F2DCC6884D5E4C55CE2A404EA49D00135D09643B958C2DE3AD20717BCDB396378BDDD7D3001BFD38E28B365402FDFF855C0B1CAD20DDAF58C574CEFF2B25B2A38D9A2B099136A766FEF0AECA613791F2691EC7E4D2FF2D085DB93A123585686802D7CCC1235788D96E693921CF136146952A8DA51F4FBF15D840C40EE2131350393EA2533AA0C42A1D91154E85D495CDC9C326C8F3D8579EF0363F98B2BDCB95B0C586B692F4F3C4EBD3B49BEBBCCB20BC104C272D02FBAD14C82B3069838A19D7432EE72870443B45CFE9848D4C059DA24A40F3A18C1EFE718A79F329A139BBA29D545B67E8B675409BCA08786C1B427FFD8BD45B1487314477EDD54DA3F774F6D4BF964A4984BA8C26212111A8E1894DA7E8088AC48E3143E72B9B8982A6C0CD18A7878FE980F892BF47BB0C9D7EBCB391EA158AC0A87BFF6F0AB83FF024E32B8E332B8F7F38854C0AB8C1C76F1BD5553BEDBEE8B96E7141A0409C6B93C5F4AE028F2441F938634470B70B724DD996BDF0F397283039871BBF931017FC7DD5F9735F66E0D5245E743CCCF4AE026F1243844C413455DA6C75FD16E3BD01446CCA40E504901CDBEC29C2BE8908D0D6624A0EFA480CFB350EE7DEB06772010EF8D81903B0E66FB838A1C260161AC8B022F41E730B346731C414E3EA39BC6CD3090AD9705B9BB1E6F0D29321D240215B885BC57204C7110EA241E9B11FC639DDD500E5B6085D2AD1C18B2165F8C66303809C50059A6258F7A392476A1C8F6F519F7954377631E45D16D716EABAAC1ECCF675AD8F0B30BD1058D922E3D3F55BB3A4070101D1E0AE24CED549C6A704E001342544F2E0F173E9AED88037FF50091F268F3B4747D8028695F2932CD0CB0163442C5E667B0FB2415BDCC706194C0F24A6946A7E5EED353C3DDCC7DF0806D5C4FEEAF0790DBEDBB3570AC41E7F48A9AB1DA79E659416C3DEED4DDF862E966EAEA76399AE6E05692F954DFF071C94D3DEFEF00F9BF02C032E85FF13A2D9D46A9526DC3F8D68BB2E5D5F03B51FD564F0CCC83734776B40B6CAAC0F839C4F1BF963414DF6EFF87156D7450F4D74EA875F38E61E58B3D5AE58A72FB4BC316BB13F9466DF799E6B464B58E23C587C5CE87BD242019AA9F6A96C59D3947D6DBD1F90DEF23A08C89786858C1DF270D690293EB890709718227D543AAF44BDA3985B805D560FBAFB0EBEDD122198E4F5FDBA83B37471A9AD08AB4C5E4668E702E0FD3D4F30084A1CF4925E7E02C1D9355A461F2AE87E65C91765BF9CBEA70517EB84294E94300C2899B4E04E8733905826A624BF01300B4422449E8A7DFD04B54CDF1F54FA1F25A32FF0907D7D7ACEDC7F46E81E33D1E1DFECAF71D902F3D5420980AB6E01046B4F29CA676DE4A56354866A9E67CF77FAA72CBB4ECA95E76750F0BD982E35E7B7C072CD5D3EE8A692EBB5D6223D*A9*3CF5310E6DC38AB1CB7F9302A9FA*myalias
```

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
