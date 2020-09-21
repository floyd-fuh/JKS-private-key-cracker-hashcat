package floydfuh.jksprivkprepare;

import java.io.*;

import java.security.*;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.*;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.SecretKeySpec;

public class JksPrivkPrepare {

    //New technique, works for all RSA, DSA, EC keys we have in mappings
    static HashMap<String, byte[][]> mappings = new HashMap<String, byte[][]>() {
        {
            //Basically we are looking for "fingerprints" in the cleartext version, such as on the first picture on
            //https://www.cem.me/20150104-cert-binaries-2.html

            //The main part of the fingerprint is actually the OID of the ASN.1 encoding, eg. 2a864886f70d010101 for RSA.
            //I considered "searching" only for the OID, but the reasons I decided against it:
            //1. I haven't seen a programatically generated JKS file that is valid in Java and doesn't match the fingerprints we have
            //2. Performance would be bad, as "searching" is more work than simply matching at certain offsets
            //3. Performance would be bad because the fingerprint would be shorter, therefore it gets more likely
            //   that a wrong password leads to a correct fingerprint, which would mean hashcat would need to implement
            //   stage 2 (decrypting the entire private key) as well to check if the correct password was found. That's
            //   currently not implemented as it is so unlikely (1:2^120) that it doesn't happen in practice and
            //   therefore simplifies the cracking algorithm.
            //All bytes that are always identical for the first 20 bytes of decrypted private keys
            //In other words, all bytes that seem to be static in the format for each cleartext private key type
            //Bytes 1 to 5 seem to vary for every key that is generated
            //The mapping is:
            //   keytype,        byte 0,                        byte 6 to 19
            put("DSA_512", new byte[][]{hexToBytes("30"), hexToBytes("3081a806072a8648ce3804013081")});
            put("DSA_1024", new byte[][]{hexToBytes("30"), hexToBytes("003082012c06072a8648ce380401")});
            //The next two lines are very rare cases, but happened when we created several hundred DSA keys...
            //This means eg. you actually get a 504 bit key instead of a 512. Fingerprint is the same.
            put("DSA_504", new byte[][]{hexToBytes("30"), hexToBytes("3081a806072a8648ce3804013081")});
            put("DSA_1016", new byte[][]{hexToBytes("30"), hexToBytes("003082012c06072a8648ce380401")});
            //default mapping if we have a DSA key of a different length:
            put("DSA", new byte[][]{hexToBytes("30"), hexToBytes("003082012c06072a8648ce380401")});

            put("RSA_512", new byte[][]{hexToBytes("30"), hexToBytes("00300d06092a864886f70d010101")});
            put("RSA_784", new byte[][]{hexToBytes("30"), hexToBytes("00300d06092a864886f70d010101")});
            put("RSA_1024", new byte[][]{hexToBytes("30"), hexToBytes("00300d06092a864886f70d010101")});
            put("RSA_2048", new byte[][]{hexToBytes("30"), hexToBytes("00300d06092a864886f70d010101")});
            put("RSA_4096", new byte[][]{hexToBytes("30"), hexToBytes("00300d06092a864886f70d010101")});
            put("RSA_8192", new byte[][]{hexToBytes("30"), hexToBytes("00300d06092a864886f70d010101")});
            //default mapping if we have a RSA key of a different length:
            put("RSA", new byte[][]{hexToBytes("30"), hexToBytes("00300d06092a864886f70d010101")});

            put("EC_256", new byte[][]{hexToBytes("30"), hexToBytes("1306072a8648ce3d020106082a86")});
            put("EC_359", new byte[][]{hexToBytes("30"), hexToBytes("1306072a8648ce3d020106082a86")});
            put("EC_431", new byte[][]{hexToBytes("30"), hexToBytes("1306072a8648ce3d020106082a86")});

            put("EC_283", new byte[][]{hexToBytes("30"), hexToBytes("1006072a8648ce3d020106052b81")});
            put("EC_384", new byte[][]{hexToBytes("30"), hexToBytes("1006072a8648ce3d020106052b81")});
            put("EC_409", new byte[][]{hexToBytes("30"), hexToBytes("1006072a8648ce3d020106052b81")});
            put("EC_521", new byte[][]{hexToBytes("30"), hexToBytes("1006072a8648ce3d020106052b81")});
            //default mapping if we have a EC key with a different curve:
            put("EC", new byte[][]{hexToBytes("30"), hexToBytes("1006072a8648ce3d020106052b81")});
            //Would be a possible choice here too... in the end the default is guesswork
            //put("EC",            new byte[][]{hexToBytes("30"), hexToBytes("1306072a8648ce3d020106082a86")});

        }
    };
    static int[] fingerprint_indexes_first = {0,};
    static int[] fingerprint_indexes_second = {6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};

    //Old technique, only worked for all RSA keys and DSA_1024
    //It had the same mapping for all keys and we used bytes 0, 1 and 4 to 7
    /*
    static HashMap<String, byte[]> mappings = new HashMap<String, byte[]>(){{
        put("default",           {hexToBytes("3082"), hexToBytes("02010030"});
    }};
    static int[] fingerprint_indexes_first = {0, 1};
    static int[] fingerprint_indexes_second = {4, 5, 6, 7};
     */
    public static void main(String[] args) throws FileNotFoundException, CertificateException, NoSuchAlgorithmException {
        if (args.length < 1) {
            System.err.println("Usage: java JksPrivkPrepare keystore_file");
            System.exit(1);
        }

        String keystoreFilename = args[0];

        InputStream in = new FileInputStream(keystoreFilename);
        //KeyStore store = KeyStore.getInstance("JKS");
        //store.load(in, "");

        JKS j = new JKS();

        try {
            try {
                j.engineLoad(in, "we could not care less about the keystore password :)".toCharArray());
            } catch (Exception e) {
                System.err.println("The file you specified does not seem to be a valid JKS file format. Are you sure it is not one of the other Key Store formats?");
                System.err.println("Exception was:");
                e.printStackTrace(System.err);
            }
            in.close();
            Enumeration aliases = j.engineAliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                byte[] key_object = (byte[]) j.privateKeys.get(alias);
                //System.err.println(bytesToHex(key_object));
                EncryptedPrivateKeyInfo epki = null;
                try {
                    epki = new EncryptedPrivateKeyInfo(key_object);
                } catch (Exception e) {
                    System.err.println("Alias " + alias + " seems to have no private key associated.");
                    continue;
                }
                //We have the encrypted Prviate Key now:
                byte[] full_key = epki.getEncryptedData();
                //System.err.println(bytesToHex(encr));
                byte[] iv = Arrays.copyOfRange(full_key, 0, 20); //First 20 bytes are IV
                byte[] checksum = Arrays.copyOfRange(full_key, full_key.length - 20, full_key.length); //Last 20 bytes are checksum
                byte[] encr = Arrays.copyOfRange(full_key, 20, full_key.length - 20); //The rest is the actual key
                //System.err.println("Length of private key in DER format: "+encr.length);

                //Let's see what kind of certificate chain is associated with the key:
                Certificate[] chain = (Certificate[]) j.certChains.get(alias);
                //TODO: So if we have a certificate chained associated with the private key
                //is it really always the first element that is the public key of that private key?
                //As we don't have the content of the private key before we crack this is kind of hard to correlate
                //Maybe just use the one that hasn't got the CA/Intermediate flag set?
                //At least the JKS class implementation below seem to indicate it is like this, see function engineGetKey
                Certificate cert = chain[0];
                PublicKey pubkey = cert.getPublicKey();
                String keyAlgorithm = pubkey.getAlgorithm();
                String keysizeOrCurve = "";
                if (keyAlgorithm.equals("RSA")) {
                    RSAPublicKey rsapubkey = (RSAPublicKey) pubkey;
                    keysizeOrCurve = String.valueOf(rsapubkey.getModulus().bitLength());
                } else if (keyAlgorithm.equals("DSA")) {
                    DSAPublicKey dsapubkey = (DSAPublicKey) pubkey;
                    int len;
                    if (dsapubkey.getParams() != null) {
                        len = dsapubkey.getParams().getP().bitLength();
                    } else {
                        // This is actually not very accurate...
                        // although we usually don't reach this else clause anyway
                        len = dsapubkey.getY().bitLength();
                        for (int i = 128; i < 10000; i = i * 2) {
                            if (i - 20 < len && len < i + 20) {
                                len = i;
                                break;
                            }
                        }
                    }
                    keysizeOrCurve = String.valueOf(len);
                } else if (keyAlgorithm.equals("EC")) {
                    ECPublicKey ecpubkey = (ECPublicKey) pubkey;
                    keysizeOrCurve = String.valueOf(ecpubkey.getParams().getCurve().getField().getFieldSize());
                    //keysizeOrCurve = ecpubkey.getW().toString();
                    //keysizeOrCurve = String.valueOf(ecpubkey.getParams().getOrder().bitLength());
                } else {
                    System.err.println("The public key is not in RSA, DSA or EC format, but " + keyAlgorithm + ".");
                    System.err.println("This is not supported, the default provider doesn't have this format.");
                    System.exit(1);
                }
                System.err.println("Alias: " + alias + ", algorithm: " + keyAlgorithm + ", keysize or field size: " + keysizeOrCurve);
                byte[][] originalFingerprint = choseFingerprint(keyAlgorithm, keysizeOrCurve);
                byte[] encrFirst20Bytes = Arrays.copyOfRange(encr, 0, 20);
                byte[][] xorFingerprint = precalculateXorStep(encrFirst20Bytes, originalFingerprint);
                String crackHash = "$jksprivk$*" + bytesToHex(checksum) + "*" + bytesToHex(iv) + "*" + bytesToHex(encr)
                        + "*" + bytesToHex(xorFingerprint[0]) + "*" + bytesToHex(xorFingerprint[1]) + "*" + alias;
                System.out.println(crackHash);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static byte[][] choseFingerprint(String keyAlgorithm, String keysizeOrCurve) {
        byte[][] fingerprint;
        if (mappings.containsKey(keyAlgorithm + "_" + keysizeOrCurve)) {
            fingerprint = mappings.get(keyAlgorithm + "_" + keysizeOrCurve);
            //System.err.println("Found fingerprint for "+keyAlgorithm+"_"+keysizeOrCurve);
        } else {
            if (keyAlgorithm.equals("RSA")) {
                //Actually we even created every single key from 512 to 10'000 bits and it's always the same fingerprint...
                /*
                System.err.println("WARNING: The key type " + keyAlgorithm+"_"+keysizeOrCurve + " is untested.");
                System.err.println("WARNING: This should usually not be a problem for RSA, as all keysizes");
                System.err.println("WARNING: observed had the same DER fingerprint.");
                 */
                fingerprint = mappings.get(keyAlgorithm);
            } else {
                System.err.println("WARNING: The key type " + keyAlgorithm + "_" + keysizeOrCurve + " is untested.");
                System.err.println("WARNING: We are going to try to make a best bet choice how this could work.");
                System.err.println("WARNING: If you are able to make a new fingerprint for this type (eg. create example keystore");
                System.err.println("WARNING: Add the fingerprint of the decrypted private key to the mappings variable.");
                fingerprint = mappings.get(keyAlgorithm);
            }
        }

        return fingerprint;
    }

    public static byte[][] precalculateXorStep(byte[] iv, byte[][] fingerprint) {
        byte[] first = new byte[fingerprint[0].length];
        int k = 0;
        for (int i : fingerprint_indexes_first) {
            first[k] = (byte) (fingerprint[0][k] ^ iv[i]);
            k++;
        }

        k = 0;
        byte[] second = new byte[fingerprint[1].length];
        for (int i : fingerprint_indexes_second) {
            second[k] = (byte) (fingerprint[1][k] ^ iv[i]);
            k++;
        }
        byte[][] new_fingerprint = {first, second};
        return new_fingerprint;
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}

// End of floyds "own" code. What comes now is a modified version of Casey Marshall's
// brilliant and transparent JKS.java class
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
/**
 * This is an implementation of Sun's proprietary key store algorithm, called
 * "JKS" for "Java Key Store". This implementation was created entirely through
 * reverse-engineering.
 *
 * <p>
 * The format of JKS files is, from the start of the file:
 *
 * <ol>
 * <li>Magic bytes. This is a four-byte integer, in big-endian byte order, equal
 * to <code>0xFEEDFEED</code>.</li>
 * <li>The version number (probably), as a four-byte integer (all multibyte
 * integral types are in big-endian byte order). The current version number (in
 * modern distributions of the JDK) is 2.</li>
 * <li>The number of entrires in this keystore, as a four-byte integer. Call
 * this value <i>n</i></li>
 * <li>Then, <i>n</i> times:
 * <ol>
 * <li>The entry type, a four-byte int. The value 1 denotes a private key entry,
 * and 2 denotes a trusted certificate.</li>
 * <li>The entry's alias, formatted as strings such as those written by <a
 *  href="http://java.sun.com/j2se/1.4.1/docs/api/java/io/DataOutput.html#writeUTF(java.lang.String)">DataOutput.writeUTF(String)</a>.</li>
 * <li>An eight-byte integer, representing the entry's creation date, in
 * milliseconds since the epoch.
 *
 * <p>
 * Then, if the entry is a private key entry:
 * <ol>
 * <li>The size of the encoded key as a four-byte int, then that number of
 * bytes. The encoded key is the DER encoded bytes of the
 * <a
 *   href="http://java.sun.com/j2se/1.4.1/docs/api/javax/crypto/EncryptedPrivateKeyInfo.html">EncryptedPrivateKeyInfo</a>
 * structure (the encryption algorithm is discussed later).</li>
 * <li>A four-byte integer, followed by that many encoded certificates, encoded
 * as described in the trusted certificates section.</li>
 * </ol>
 *
 * <p>
 * Otherwise, the entry is a trusted certificate, which is encoded as the name
 * of the encoding algorithm (e.g. X.509), encoded the same way as alias names.
 * Then, a four-byte integer representing the size of the encoded certificate,
 * then that many bytes representing the encoded certificate (e.g. the DER bytes
 * in the case of X.509).
 * </li>
 * </ol>
 * </li>
 * <li>Then, the signature.</li>
 * </ol>
 * </ol>
 * </li>
 * </ol>
 *
 * <p>
 * (See <a href="genkey.java">this file</a> for some idea of how I was able to
 * figure out these algorithms)</p>
 *
 * <p>
 * Decrypting the key works as follows:
 *
 * <ol>
 * <li>The key length is the length of the ciphertext minus 40. The encrypted
 * key, <code>ekey</code>, is the middle bytes of the ciphertext.</li>
 * <li>Take the first 20 bytes of the encrypted key as a seed value,
 * <code>K[0]</code>.</li>
 * <li>Compute <code>K[1] ... K[n]</code>, where <code>|K[i]| = 20</code>,
 * <code>n = ceil(|ekey| / 20)</code>, and
 * <code>K[i] = SHA-1(UTF-16BE(password) + K[i-1])</code>.</li>
 * <li><code>key = ekey ^ (K[1] + ... + K[n])</code>.</li>
 * <li>The last 20 bytes are the checksum, computed as <code>H =
 * SHA-1(UTF-16BE(password) + key)</code>. If this value does not match the last
 * 20 bytes of the ciphertext, output <code>FAIL</code>. Otherwise, output
 * <code>key</code>.</li>
 * </ol>
 *
 * <p>
 * The signature is defined as <code>SHA-1(UTF-16BE(password) +
 * US_ASCII("Mighty Aphrodite") + encoded_keystore)</code> (yup, Sun engineers
 * are just that clever).
 *
 * <p>
 * (Above, SHA-1 denotes the secure hash algorithm, UTF-16BE the big-endian byte
 * representation of a UTF-16 string, and US_ASCII the ASCII byte representation
 * of the string.)
 *
 * <p>
 * The source code of this class should be available in the file <a
 * href="http://metastatic.org/source/JKS.java">JKS.java</a>.
 *
 * @author Casey Marshall (rsdio@metastatic.org)
 */
class JKS extends KeyStoreSpi {

    // Constants and fields.
    // ------------------------------------------------------------------------
    /**
     * Ah, Sun. So goddamned clever with those magic bytes.
     */
    private static final int MAGIC = 0xFEEDFEED;

    private static final int PRIVATE_KEY = 1;
    private static final int TRUSTED_CERT = 2;

    private final Vector aliases;
    private final HashMap trustedCerts;
    public final HashMap privateKeys;
    public final HashMap certChains;
    private final HashMap dates;

    // Constructor.
    // ------------------------------------------------------------------------
    public JKS() {
        super();
        aliases = new Vector();
        trustedCerts = new HashMap();
        privateKeys = new HashMap();
        certChains = new HashMap();
        dates = new HashMap();

    }

    // Instance methods.
    // ------------------------------------------------------------------------
    public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {
        if (!privateKeys.containsKey(alias)) {
            return null;
        }
        byte[] key = decryptKey((byte[]) privateKeys.get(alias),
                charsToBytes(password));
        Certificate[] chain = engineGetCertificateChain(alias);
        if (chain.length > 0) {
            try {
                // Private and public keys MUST have the same algorithm.
                KeyFactory fact = KeyFactory.getInstance(
                        chain[0].getPublicKey().getAlgorithm());
                return fact.generatePrivate(new PKCS8EncodedKeySpec(key));
            } catch (InvalidKeySpecException x) {
                throw new UnrecoverableKeyException(x.getMessage());
            }
        } else {
            return new SecretKeySpec(key, alias);
        }
    }

    public Certificate[] engineGetCertificateChain(String alias) {
        return (Certificate[]) certChains.get(alias);
    }

    public Certificate engineGetCertificate(String alias) {
        return (Certificate) trustedCerts.get(alias);
    }

    public Date engineGetCreationDate(String alias) {
        return (Date) dates.get(alias);
    }

    // XXX implement writing methods.
    public void engineSetKeyEntry(String alias, Key key, char[] passwd, Certificate[] certChain)
            throws KeyStoreException {
        if (trustedCerts.containsKey(alias)) {
            throw new KeyStoreException("\"" + alias + " is a trusted certificate entry");
        }
        privateKeys.put(alias, encryptKey(key, charsToBytes(passwd)));
        if (certChain != null) {
            certChains.put(alias, certChain);
        } else {
            certChains.put(alias, new Certificate[0]);
        }
        if (!aliases.contains(alias)) {
            dates.put(alias, new Date());
            aliases.add(alias);
        }
    }

    public void engineSetKeyEntry(String alias, byte[] encodedKey, Certificate[] certChain)
            throws KeyStoreException {
        if (trustedCerts.containsKey(alias)) {
            throw new KeyStoreException("\"" + alias + "\" is a trusted certificate entry");
        }
        try {
            new EncryptedPrivateKeyInfo(encodedKey);
        } catch (IOException ioe) {
            throw new KeyStoreException("encoded key is not an EncryptedPrivateKeyInfo");
        }
        privateKeys.put(alias, encodedKey);
        if (certChain != null) {
            certChains.put(alias, certChain);
        } else {
            certChains.put(alias, new Certificate[0]);
        }
        if (!aliases.contains(alias)) {
            dates.put(alias, new Date());
            aliases.add(alias);
        }
    }

    public void engineSetCertificateEntry(String alias, Certificate cert)
            throws KeyStoreException {
        if (privateKeys.containsKey(alias)) {
            throw new KeyStoreException("\"" + alias + "\" is a private key entry");
        }
        if (cert == null) {
            throw new NullPointerException();
        }
        trustedCerts.put(alias, cert);
        if (!aliases.contains(alias)) {
            dates.put(alias, new Date());
            aliases.add(alias);
        }
    }

    public void engineDeleteEntry(String alias) throws KeyStoreException {
        aliases.remove(alias);
    }

    public Enumeration engineAliases() {
        return aliases.elements();
    }

    public boolean engineContainsAlias(String alias) {
        return aliases.contains(alias);
    }

    public int engineSize() {
        return aliases.size();
    }

    public boolean engineIsKeyEntry(String alias) {
        return privateKeys.containsKey(alias);
    }

    public boolean engineIsCertificateEntry(String alias) {
        return trustedCerts.containsKey(alias);
    }

    public String engineGetCertificateAlias(Certificate cert) {
        for (Iterator keys = trustedCerts.keySet().iterator(); keys.hasNext();) {
            String alias = (String) keys.next();
            if (cert.equals(trustedCerts.get(alias))) {
                return alias;
            }
        }
        return null;
    }

    public void engineStore(OutputStream out, char[] passwd)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(charsToBytes(passwd));
        md.update("Mighty Aphrodite".getBytes("UTF-8"));
        DataOutputStream dout = new DataOutputStream(new DigestOutputStream(out, md));
        dout.writeInt(MAGIC);
        dout.writeInt(2);
        dout.writeInt(aliases.size());
        for (Enumeration e = aliases.elements(); e.hasMoreElements();) {
            String alias = (String) e.nextElement();
            if (trustedCerts.containsKey(alias)) {
                dout.writeInt(TRUSTED_CERT);
                dout.writeUTF(alias);
                dout.writeLong(((Date) dates.get(alias)).getTime());
                writeCert(dout, (Certificate) trustedCerts.get(alias));
            } else {
                dout.writeInt(PRIVATE_KEY);
                dout.writeUTF(alias);
                dout.writeLong(((Date) dates.get(alias)).getTime());
                byte[] key = (byte[]) privateKeys.get(alias);
                dout.writeInt(key.length);
                dout.write(key);
                Certificate[] chain = (Certificate[]) certChains.get(alias);
                dout.writeInt(chain.length);
                for (int i = 0; i < chain.length; i++) {
                    writeCert(dout, chain[i]);
                }
            }
        }
        byte[] digest = md.digest();
        dout.write(digest);
    }

    public void engineLoad(InputStream in, char[] passwd)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(charsToBytes(passwd));
        md.update("Mighty Aphrodite".getBytes("UTF-8")); // HAR HAR
        aliases.clear();
        trustedCerts.clear();
        privateKeys.clear();
        certChains.clear();
        dates.clear();
        DataInputStream din = new DataInputStream(new DigestInputStream(in, md));
        if (din.readInt() != MAGIC) {
            throw new IOException("not a JavaKeyStore");
        }
        din.readInt();  // version no.
        final int n = din.readInt();
        aliases.ensureCapacity(n);
        if (n < 0) {
            throw new IOException("negative entry count");
        }
        for (int i = 0; i < n; i++) {
            int type = din.readInt();
            String alias = din.readUTF();
            aliases.add(alias);
            dates.put(alias, new Date(din.readLong()));
            switch (type) {
                case PRIVATE_KEY:
                    int len = din.readInt();
                    byte[] encoded = new byte[len];
                    din.read(encoded);
                    privateKeys.put(alias, encoded);
                    int count = din.readInt();
                    Certificate[] chain = new Certificate[count];
                    for (int j = 0; j < count; j++) {
                        chain[j] = readCert(din);
                    }
                    certChains.put(alias, chain);
                    break;

                case TRUSTED_CERT:
                    trustedCerts.put(alias, readCert(din));
                    break;

                default:
                    throw new IOException("malformed key store");
            }
        }

        byte[] hash = new byte[20];
        din.read(hash);
        if (MessageDigest.isEqual(hash, md.digest())) {
            throw new IOException("signature not verified");
        }
    }

    // Own methods.
    // ------------------------------------------------------------------------
    private static Certificate readCert(DataInputStream in)
            throws IOException, CertificateException, NoSuchAlgorithmException {
        String type = in.readUTF();
        int len = in.readInt();
        byte[] encoded = new byte[len];
        in.read(encoded);
        CertificateFactory factory = CertificateFactory.getInstance(type);
        return factory.generateCertificate(new ByteArrayInputStream(encoded));
    }

    private static void writeCert(DataOutputStream dout, Certificate cert)
            throws IOException, CertificateException {
        dout.writeUTF(cert.getType());
        byte[] b = cert.getEncoded();
        dout.writeInt(b.length);
        dout.write(b);
    }
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] decryptKey(byte[] encryptedPKI, byte[] passwd)
            throws UnrecoverableKeyException {
        try {
            EncryptedPrivateKeyInfo epki
                    = new EncryptedPrivateKeyInfo(encryptedPKI);
            byte[] encr = epki.getEncryptedData();

            //System.out.println("epki.getEncryptedData()");
            //System.out.println(bytesToHex(encr));
            byte[] keystream = new byte[20];
            System.arraycopy(encr, 0, keystream, 0, 20);
            byte[] check = new byte[20];
            System.arraycopy(encr, encr.length - 20, check, 0, 20);
            byte[] key = new byte[encr.length - 40];
            MessageDigest sha = MessageDigest.getInstance("SHA1");
            int count = 0;
            while (count < key.length) {
                sha.reset();
                sha.update(passwd);
                sha.update(keystream);
                sha.digest(keystream, 0, keystream.length);
                for (int i = 0; i < keystream.length && count < key.length; i++) {
                    key[count] = (byte) (keystream[i] ^ encr[count + 20]);
                    count++;
                }
            }
            sha.reset();
            sha.update(passwd);
            sha.update(key);
            if (!MessageDigest.isEqual(check, sha.digest())) {
                throw new UnrecoverableKeyException("checksum mismatch");
            }
            return key;
        } catch (Exception x) {
            throw new UnrecoverableKeyException(x.getMessage());
        }
    }

    private static byte[] encryptKey(Key key, byte[] passwd)
            throws KeyStoreException {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA1");
            SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
            byte[] k = key.getEncoded();
            byte[] encrypted = new byte[k.length + 40];
            byte[] keystream = rand.getSeed(20);
            System.arraycopy(keystream, 0, encrypted, 0, 20);
            int count = 0;
            while (count < k.length) {
                sha.reset();
                sha.update(passwd);
                sha.update(keystream);
                sha.digest(keystream, 0, keystream.length);
                for (int i = 0; i < keystream.length && count < k.length; i++) {
                    encrypted[count + 20] = (byte) (keystream[i] ^ k[count]);
                    count++;
                }
            }
            sha.reset();
            sha.update(passwd);
            sha.update(k);
            sha.digest(encrypted, encrypted.length - 20, 20);
            // 1.3.6.1.4.1.42.2.17.1.1 is Sun's private OID for this
            // encryption algorithm.
            return new EncryptedPrivateKeyInfo("1.3.6.1.4.1.42.2.17.1.1",
                    encrypted).getEncoded();
        } catch (Exception x) {
            throw new KeyStoreException(x.getMessage());
        }
    }

    private static byte[] charsToBytes(char[] passwd) {
        byte[] buf = new byte[passwd.length * 2];
        for (int i = 0, j = 0; i < passwd.length; i++) {
            buf[j++] = (byte) (passwd[i] >>> 8);
            buf[j++] = (byte) passwd[i];
        }
        return buf;
    }
}
