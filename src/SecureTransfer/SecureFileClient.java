package SecureTransfer;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.time.Instant;
import java.util.UUID;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class SecureFileClient {
    public static void main(String[] args) throws Exception {
        // Load client keystore (private key + cert)
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("client.jks"), "secureftp".toCharArray());

        // Load client truststore (trusts server)
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("clientTruststore.jks"), "secureftp".toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, "secureftp".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket("localhost", 8443);
        System.out.println("🔐 Connected securely to server with mTLS");

        // Prepare file
        File file = new File("file_to_send.txt");
        byte[] fileBytes = Files.readAllBytes(file.toPath());

        // Hash original file
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(fileBytes);

        // Sign hash with RSA private key
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("client", "secureftp".toCharArray());
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        byte[] digitalSignature = signature.sign();

        // Generate AES key for file encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt file
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedFile = aesCipher.doFinal(fileBytes);

        // Metadata for replay protection
        String timestamp = Instant.now().toString();
        String nonce = UUID.randomUUID().toString();

        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // Send AES key bytes
        byte[] aesKeyBytes = aesKey.getEncoded();
        out.writeInt(aesKeyBytes.length);
        out.write(aesKeyBytes);

        // Send metadata
        out.writeUTF(file.getName());
        out.writeUTF(timestamp);
        out.writeUTF(nonce);

        // Send hash and signature
        out.writeInt(hash.length);
        out.write(hash);

        out.writeInt(digitalSignature.length);
        out.write(digitalSignature);

        // Send encrypted file
        out.writeLong(encryptedFile.length);
        out.write(encryptedFile);

        out.flush();
        socket.close();
        System.out.println("📤 File encrypted, signed, and sent securely.");
    }
}
