package security;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class HashUtil {

    // 1. Hash file content using SHA-256
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

    // 2. Hash any byte array (e.g., file + metadata)
    public static byte[] hashBytes(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    // 3. Hash a string (e.g., metadata JSON)
    public static byte[] hashString(String data) throws Exception {
        return hashBytes(data.getBytes(StandardCharsets.UTF_8));
    }

    // 4. Sign hash using private key
    public static byte[] signHash(byte[] hash, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        return signature.sign();
    }

    // 5. Verify hash signature using public key
    public static boolean verifySignature(byte[] hash, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(hash);
        return signature.verify(signatureBytes);
    }

    // 6. Encode bytes as hex (optional)
    public static String byteToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // 7. Base64 encode
    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    // 8. Base64 decode
    public static byte[] base64Decode(String base64Data) {
        return Base64.getDecoder().decode(base64Data);
    }
}
