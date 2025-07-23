package security;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;


public class HashUtil {

    // Hash file content using SHA-256
    public static byte[] hashFile(String filePath) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        FileInputStream fis = new FileInputStream(filePath);
        byte[] buffer = new byte[4096];
        int bytesRead;

        while ((bytesRead = fis.read(buffer)) != -1) {
            digest.update(buffer, 0, bytesRead);
        }
        fis.close();
        return digest.digest();
    }

    // Hash any byte array
    public static byte[] hashBytes(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    // Hash a string
    public static byte[] hashString(String data) throws Exception {
        return hashBytes(data.getBytes(StandardCharsets.UTF_8));
    }

    // Sign hash using private key
    public static byte[] signHash(byte[] hash, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        return signature.sign();
    }

    //  Verify hash signature using public key
    public static boolean verifySignature(byte[] hash, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(hash);
        return signature.verify(signatureBytes);
    }


}
