package security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;


public class AESUtil {

    private static final String AES_ALGO = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16; // 128 bits

    // Generate a new AES SecretKey
    public static SecretKey generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, new SecureRandom());
        return keyGen.generateKey();
    }

    // Save SecretKey to file
    public static void saveKeyToFile(SecretKey key, String filePath) throws IOException {
        byte[] encoded = key.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(encoded);
        }
    }

    // Load SecretKey from file
    public static SecretKey loadKeyFromFile(String filePath) throws IOException {
        byte[] encoded = new byte[(int) new File(filePath).length()];
        try (FileInputStream fis = new FileInputStream(filePath)) {
            fis.read(encoded);
        }
        return new SecretKeySpec(encoded, "AES");
    }


    public static File encryptFile(File inputFile, SecretKey secretKey) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        // Prepend IV to ciphertext
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv);
        outputStream.write(encryptedBytes);

        File encryptedFile = new File(inputFile.getParent(), "enc_" + inputFile.getName());
        Files.write(encryptedFile.toPath(), outputStream.toByteArray());

        return encryptedFile;
    }

    public static File decryptFile(String encryptedFilePath, SecretKey secretKey) throws Exception {
        byte[] fileContent = Files.readAllBytes(new File(encryptedFilePath).toPath());

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(fileContent, 0, iv, 0, IV_SIZE);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] cipherBytes = new byte[fileContent.length - IV_SIZE];
        System.arraycopy(fileContent, IV_SIZE, cipherBytes, 0, cipherBytes.length);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decrypted = cipher.doFinal(cipherBytes);

        File decryptedFile = new File(encryptedFilePath + "_dec");
        Files.write(decryptedFile.toPath(), decrypted);
        return decryptedFile;
    }

}
