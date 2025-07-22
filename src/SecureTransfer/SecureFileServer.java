package SecureTransfer;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.HashSet;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class SecureFileServer {
    private static final HashSet<String> usedNonces = new HashSet<>();

    public static void main(String[] args) throws Exception {
        // Load server's keystore (private key + cert)
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("server.jks"), "secureftp".toCharArray());

        // Load truststore (trusted client certs)
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("serverTruststore.jks"), "secureftp".toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, "secureftp".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLServerSocket serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(8443);
        serverSocket.setNeedClientAuth(true);

        System.out.println("🔐 Server ready with mTLS on port 8443");

        while (true) {
            try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                System.out.println("✅ Client authenticated");

                DataInputStream in = new DataInputStream(socket.getInputStream());

                // Read AES key
                byte[] keyBytes = new byte[in.readInt()];
                in.readFully(keyBytes);
                SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

                // Metadata
                String fileName = in.readUTF();
                String timestamp = in.readUTF();
                String nonce = in.readUTF();

                // Replay protection
                Instant time = Instant.parse(timestamp);
                if (Instant.now().minusSeconds(300).isAfter(time) || usedNonces.contains(nonce)) {
                    System.out.println("⛔ Replay attack suspected. Connection rejected.");
                    continue;
                }
                usedNonces.add(nonce);

                // Read hash
                byte[] hash = new byte[in.readInt()];
                in.readFully(hash);

                // Read signature
                byte[] signatureBytes = new byte[in.readInt()];
                in.readFully(signatureBytes);

                // Read encrypted file
                long encFileLen = in.readLong();
                byte[] encryptedData = new byte[(int) encFileLen];
                in.readFully(encryptedData);

                // Get client's public key from truststore
                Certificate clientCert = trustStore.getCertificate("client");
                PublicKey clientPublicKey = clientCert.getPublicKey();

                // Verify signature on hash
                Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(clientPublicKey);
                verifier.update(hash);
                if (!verifier.verify(signatureBytes)) {
                    System.out.println("❌ Invalid signature. Rejecting file.");
                    continue;
                }

                // Decrypt file
                Cipher aesCipher = Cipher.getInstance("AES");
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
                byte[] decrypted = aesCipher.doFinal(encryptedData);

                // Verify hash matches decrypted file
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] recalculatedHash = digest.digest(decrypted);
                if (!MessageDigest.isEqual(hash, recalculatedHash)) {
                    System.out.println("❌ Hash mismatch! Possible tampering detected.");
                    continue;
                }

                // Save file
                try (FileOutputStream fos = new FileOutputStream("received_" + fileName)) {
                    fos.write(decrypted);
                }

                System.out.println("✅ Successfully received and verified file: " + fileName);
            } catch (Exception e) {
                System.err.println("⚠️ Error handling client connection: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
}
