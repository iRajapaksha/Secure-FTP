package SecureTransfer;
import javax.net.ssl.*;
        import javax.swing.*;
        import java.awt.*;
        import java.io.*;
        import java.security.*;
        import java.security.cert.Certificate;
        import java.time.Instant;
        import java.util.HashSet;
        import javax.crypto.*;
        import javax.crypto.spec.SecretKeySpec;

public class SecureFileServerGUI extends JFrame {
    private JTextArea logArea = new JTextArea(15, 50);
    private JButton startBtn = new JButton("Start Server");
    private JButton stopBtn = new JButton("Stop Server");
    private SSLServerSocket serverSocket;
    private Thread serverThread;
    private volatile boolean running = false;
    private final HashSet<String> usedNonces = new HashSet<>();

    public SecureFileServerGUI() {
        super("Secure File Transfer Server");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel topPanel = new JPanel();
        topPanel.add(startBtn);
        topPanel.add(stopBtn);
        stopBtn.setEnabled(false);

        add(topPanel, BorderLayout.NORTH);
        add(new JScrollPane(logArea), BorderLayout.CENTER);

        startBtn.addActionListener(e -> startServer());
        stopBtn.addActionListener(e -> stopServer());

        pack();
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void log(String msg) {
        SwingUtilities.invokeLater(() -> logArea.append(msg + "\n"));
    }

    private void startServer() {
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        running = true;

        serverThread = new Thread(() -> {
            try {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream("server.jks"), "secureftp".toCharArray());

                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(new FileInputStream("serverTruststore.jks"), "secureftp".toCharArray());

                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(keyStore, "secureftp".toCharArray());

                TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                tmf.init(trustStore);

                SSLContext context = SSLContext.getInstance("TLS");
                context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

                serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(8443);
                serverSocket.setNeedClientAuth(true);

                log("🔐 Server started on port 8443");

                while (running) {
                    try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                        log("✅ Client connected and authenticated");

                        DataInputStream in = new DataInputStream(socket.getInputStream());

                        byte[] keyBytes = new byte[in.readInt()];
                        in.readFully(keyBytes);
                        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

                        String fileName = in.readUTF();
                        String timestamp = in.readUTF();
                        String nonce = in.readUTF();

                        Instant time = Instant.parse(timestamp);
                        if (Instant.now().minusSeconds(300).isAfter(time) || usedNonces.contains(nonce)) {
                            log("⛔ Replay attack suspected. Ignoring file.");
                            continue;
                        }
                        usedNonces.add(nonce);

                        byte[] hash = new byte[in.readInt()];
                        in.readFully(hash);

                        byte[] signatureBytes = new byte[in.readInt()];
                        in.readFully(signatureBytes);

                        long encFileLen = in.readLong();
                        byte[] encryptedData = new byte[(int) encFileLen];
                        in.readFully(encryptedData);

                        Certificate clientCert = trustStore.getCertificate("client");
                        PublicKey clientPublicKey = clientCert.getPublicKey();

                        Signature verifier = Signature.getInstance("SHA256withRSA");
                        verifier.initVerify(clientPublicKey);
                        verifier.update(hash);
                        if (!verifier.verify(signatureBytes)) {
                            log("❌ Invalid signature. Rejecting file.");
                            continue;
                        }

                        Cipher aesCipher = Cipher.getInstance("AES");
                        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
                        byte[] decrypted = aesCipher.doFinal(encryptedData);

                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        byte[] recalculatedHash = digest.digest(decrypted);
                        if (!MessageDigest.isEqual(hash, recalculatedHash)) {
                            log("❌ Hash mismatch! Possible tampering.");
                            continue;
                        }

                        try (FileOutputStream fos = new FileOutputStream("received_" + fileName)) {
                            fos.write(decrypted);
                        }

                        log("✅ Received and verified file: " + fileName);
                    } catch (Exception ex) {
                        log("⚠️ Error handling client: " + ex.getMessage());
                        ex.printStackTrace();
                    }
                }
            } catch (Exception e) {
                log("❌ Server error: " + e.getMessage());
                e.printStackTrace();
            } finally {
                stopServer();
            }
        });
        serverThread.start();
    }

    private void stopServer() {
        running = false;
        stopBtn.setEnabled(false);
        startBtn.setEnabled(true);
        try {
            if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close();
            log("🛑 Server stopped.");
        } catch (IOException e) {
            log("❌ Error closing server socket: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SecureFileServerGUI::new);
    }
}

