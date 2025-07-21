package security;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class RSAUtil {

    private static final String RSA_ALGORITHM = "RSA";

    // ===================== Key Generation =====================
    public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    // ===================== Save Keys to Files =====================
    public static void savePublicKey(PublicKey publicKey, String filePath) throws IOException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(x509EncodedKeySpec.getEncoded());
        }
    }

    public static void savePrivateKey(PrivateKey privateKey, String filePath) throws IOException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(pkcs8EncodedKeySpec.getEncoded());
        }
    }

    // ===================== Load Keys from Files =====================
    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = readFile(filePath);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = readFile(filePath);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    private static byte[] readFile(String path) throws IOException {
        return java.nio.file.Files.readAllBytes(new File(path).toPath());
    }

    // ===================== Encryption / Decryption =====================


    // Encrypt AES key with RSA Public Key
    public static byte[] encryptWithRSAKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    // Decrypt AES key with RSA Private Key
    public static SecretKey decryptWithRSAKey(byte[] encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedAESKey);
        return new SecretKeySpec(decryptedKeyBytes, "AES");
    }


//    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        return cipher.doFinal(data);
//    }

//    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        return cipher.doFinal(encryptedData);
//    }
//
//    // ===================== Sign / Verify =====================
//    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
//        Signature signature = Signature.getInstance("SHA256withRSA");
//        signature.initSign(privateKey);
//        signature.update(data);
//        return signature.sign();
//    }
//
//    public static boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
//        Signature signature = Signature.getInstance("SHA256withRSA");
//        signature.initVerify(publicKey);
//        signature.update(data);
//        return signature.verify(signatureBytes);
//    }
//
//    // ===================== Utility (Base64 for display/debug) =====================
//    public static String toBase64(byte[] data) {
//        return Base64.getEncoder().encodeToString(data);
//    }
//
//    public static byte[] fromBase64(String base64) {
//        return Base64.getDecoder().decode(base64);
//    }
}
