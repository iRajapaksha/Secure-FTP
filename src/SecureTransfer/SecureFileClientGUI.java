package SecureTransfer;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.time.Instant;
import java.util.UUID;

public class SecureFileClientGUI extends JFrame {
    private JTextArea logArea = new JTextArea(10, 40);
    private JButton selectFileBtn = new JButton("Select File");
    private JButton sendBtn = new JButton("Send File");
    private JFileChooser fileChooser = new JFileChooser();
    private File selectedFile;

    public SecureFileClientGUI() {
        super("Secure File Transfer Client");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel topPanel = new JPanel();
        topPanel.add(selectFileBtn);
        topPanel.add(sendBtn);
        sendBtn.setEnabled(false);

        add(topPanel, BorderLayout.NORTH);
        add(new JScrollPane(logArea), BorderLayout.CENTER);

        selectFileBtn.addActionListener(e -> {
            int result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                selectedFile = fileChooser.getSelectedFile();
                log("Selected file: " + selectedFile.getName());
                sendBtn.setEnabled(true);
            }
        });

        sendBtn.addActionListener(e -> {
            sendBtn.setEnabled(false);
            new Thread(() -> {
                try {
                    sendFile(selectedFile);
                    log("✅ File sent successfully.");
                } catch (Exception ex) {
                    log("❌ Error: " + ex.getMessage());
                    ex.printStackTrace();
                } finally {
                    SwingUtilities.invokeLater(() -> sendBtn.setEnabled(true));
                }
            }).start();
        });

        pack();
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void log(String msg) {
        SwingUtilities.invokeLater(() -> logArea.append(msg + "\n"));
    }

    private void sendFile(File file) throws Exception {
        // Load client keystore & truststore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("client.jks"), "secureftp".toCharArray());

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("clientTruststore.jks"), "secureftp".toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, "secureftp".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket("localhost", 8443)) {
            log("🔐 Connected to server with mTLS");

            byte[] fileBytes = Files.readAllBytes(file.toPath());

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(fileBytes);

            PrivateKey privateKey = (PrivateKey) keyStore.getKey("client", "secureftp".toCharArray());
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(hash);
            byte[] digitalSignature = signature.sign();

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey aesKey = keyGen.generateKey();

            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedFile = aesCipher.doFinal(fileBytes);

            String timestamp = Instant.now().toString();
            String nonce = UUID.randomUUID().toString();

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            byte[] aesKeyBytes = aesKey.getEncoded();
            out.writeInt(aesKeyBytes.length);
            out.write(aesKeyBytes);

            out.writeUTF(file.getName());
            out.writeUTF(timestamp);
            out.writeUTF(nonce);

            out.writeInt(hash.length);
            out.write(hash);

            out.writeInt(digitalSignature.length);
            out.write(digitalSignature);

            out.writeLong(encryptedFile.length);
            out.write(encryptedFile);

            out.flush();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SecureFileClientGUI::new);
    }
}
