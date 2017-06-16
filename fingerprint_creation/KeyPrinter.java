import java.io.*;
import java.security.*;
import java.security.cert.Certificate;

// modified version from https://stackoverflow.com/questions/4907622/keytool-see-the-public-and-private-keys

public class KeyPrinter {

    /**
     * to be invoked with these parameters:
     * 
     * [0]:  keystore-password
     * [1]:  filename
     * [2]:  alias
     * [3]:  entry-Password (if necessary)
     */
    public static void main(String[] params)
        throws IOException, GeneralSecurityException
    {
        char[] storePass = params[0].toCharArray();
        String fileName = params[1];
        String alias = params[2];
        KeyStore.ProtectionParameter entryPass;
        if(params.length > 3) {
            entryPass=new KeyStore.PasswordProtection(params[3].toCharArray());
        } else {
            entryPass = null;
        }

        KeyStore store = KeyStore.getInstance("JKS");
        InputStream input = new FileInputStream(fileName);
        store.load(input, storePass);

        KeyStore.Entry entry = store.getEntry(alias, entryPass);
        //System.out.println(entry);
        
        //System.out.println("Private Key:");
        KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        PrivateKey privKey = privKeyEntry.getPrivateKey();
        byte[] keybytes = privKey.getEncoded();
        System.out.println(fileName + ": " + bytesToHex(keybytes));

    }
    
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
