package sender;

import Util.Payload;
import Util.PayloadUtil;
import com.google.gson.Gson;
import security.AESUtil;
import security.RSAUtil;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;



public class SenderApp extends JFrame {

    private JTextField filePathField;
    private JButton browseButton;
    private JButton generateAESKeyButton;
    private JButton generateRSAKeyPairButton;
    private JButton uploadPublicKeyButton;
    private JButton encryptButton;
    private JLabel statusLabel;

    private JButton connectButton;
    private JLabel connectionStatus;

    private PublicKey receiverPublicKey;

    private PublicKey senderPublicKey;
    private PrivateKey senderPrivateKey;
    private SecretKey aesKey;

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private JButton sendButton;
    private File payloadFile;
    private File inputFile;

    public SenderApp() {
        setTitle("Secure File Sender");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 400);
        setLocationRelativeTo(null);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        //Server connection
        connectButton = new JButton("Connect");
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        add(connectButton, gbc);

        connectionStatus = new JLabel("Waiting for a connection");
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        add(connectionStatus,gbc);


        // File selection
        JLabel fileLabel = new JLabel("Selected File:");
        gbc.gridx = 0;
        gbc.gridy = 1;
        add(fileLabel, gbc);

        filePathField = new JTextField();
        filePathField.setEditable(false);
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        add(filePathField, gbc);

        browseButton = new JButton("Browse");
        gbc.gridx = 3;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        add(browseButton, gbc);

        // Generate AES Key
        generateAESKeyButton = new JButton("Generate AES Key");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 4;
        add(generateAESKeyButton, gbc);

        // Generate RSA Key Pair
        generateRSAKeyPairButton = new JButton("Generate RSA Key Pair");
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 4;
        add(generateRSAKeyPairButton, gbc);

        // Upload Receiver's Public Key
        uploadPublicKeyButton = new JButton("Upload Receiver's Public Key");
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 4;
        add(uploadPublicKeyButton, gbc);

        // Encrypt and Generate Payload
        encryptButton = new JButton("Encrypt and Generate Payload");
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 4;
        add(encryptButton, gbc);

        // Send button
        sendButton = new JButton("Send Encrypted File");
        sendButton.setEnabled(false); // Only enabled after encryption
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 4;
        add(sendButton, gbc);


        // Status label
        statusLabel = new JLabel("Status: Waiting for input...");
        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.gridwidth = 4;
        add(statusLabel, gbc);

        setupListeners();
        setVisible(true);
    }

    private void setupListeners() {

        connectButton.addActionListener(e -> {
            new Thread(() -> {
                try {
                    serverSocket = new ServerSocket(9999); // Choose a port (e.g., 6000)
                    connectionStatus.setText("Waiting for client...");
                    clientSocket = serverSocket.accept(); // Blocking call
                    connectionStatus.setText("Connected to " + clientSocket.getInetAddress());
                } catch (IOException ex) {
                    ex.printStackTrace();
                    connectionStatus.setText("Connection failed");
                }
            }).start();
        });

        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Select file to encrypt");
            int result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                inputFile = fileChooser.getSelectedFile();
                filePathField.setText(inputFile.getAbsolutePath());
                statusLabel.setText("Status: File selected");
            }
        });

        generateAESKeyButton.addActionListener(e -> {
            try {
                // 1. Generate AES Key
                aesKey = AESUtil.generateAESKey(128); // You can use 256 if needed
                System.out.println("AES Key: " + aesKey);
                statusLabel.setText("Status: AES key generated successfully");

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error generating AES key.");
                JOptionPane.showMessageDialog(this,
                        "Failed to generate AES key:\n" + ex.getMessage(),
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        generateRSAKeyPairButton.addActionListener(e -> {
            try {
                KeyPair keyPair = RSAUtil.generateRSAKeyPair(2048);
                senderPrivateKey = keyPair.getPrivate();
                senderPublicKey = keyPair.getPublic();
                System.out.println("Sender public key: "+ senderPublicKey);
                statusLabel.setText("Status: RSA key pair generated.");
            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error generating RSA key pair.");
                JOptionPane.showMessageDialog(this,
                        "Failed to generate RSA key pair:\n" + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        uploadPublicKeyButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Select Receiver's Public Key");

            int userSelection = fileChooser.showOpenDialog(null);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File keyFile = fileChooser.getSelectedFile();
                try {
                    // Read key file
                    byte[] keyBytes = new FileInputStream(keyFile).readAllBytes();

                    // If the key is in PEM format, strip headers and decode Base64
                    String keyString = new String(keyBytes);
                    if (keyString.contains("BEGIN PUBLIC KEY")) {
                        keyString = keyString.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                                .replaceAll("-----END PUBLIC KEY-----", "")
                                .replaceAll("\\s", ""); // remove whitespace
                        keyBytes = Base64.getDecoder().decode(keyString);
                    }

                    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    receiverPublicKey = keyFactory.generatePublic(spec);
                    System.out.println("Receiver public key: " + receiverPublicKey);
                    statusLabel.setText("Status: Receiver's public key uploaded successfully.");
                } catch (Exception ex) {
                    statusLabel.setText("Error: Unable to load public key.");
                    ex.printStackTrace();
                }
            }
        });

        encryptButton.addActionListener(e -> {
            try {
                if (aesKey == null || receiverPublicKey == null || senderPrivateKey == null || filePathField.getText().isEmpty()) {
                    statusLabel.setText("Error: Missing input(s)");
                    JOptionPane.showMessageDialog(this, "Please ensure AES key, public/private keys and file are selected.");
                    return;
                }

                System.out.println("Input file path: "+ inputFile.getAbsolutePath());
                Payload payload = PayloadUtil.encryptPayload(inputFile, aesKey, receiverPublicKey, senderPrivateKey,senderPublicKey);

                // Save payload JSON
                Gson gson = new Gson();
                String payloadJson = gson.toJson(payload);
                System.out.println("Encrypted payload: " +payloadJson);
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save Payload JSON File");
                int userSelection = fileChooser.showSaveDialog(this);
                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File savedPayloadFile = fileChooser.getSelectedFile();
                    payloadFile = savedPayloadFile;
                    Files.writeString(savedPayloadFile.toPath(), payloadJson);
                    sendButton.setEnabled(true); // Enable send
                    statusLabel.setText("Status: Payload saved successfully.");
                    JOptionPane.showMessageDialog(this, "Payload saved:\n" + savedPayloadFile.getAbsolutePath(), "Success", JOptionPane.INFORMATION_MESSAGE);
                }

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error generating payload.");
                JOptionPane.showMessageDialog(this, "Payload generation failed:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        sendButton.addActionListener(e -> {
            if (clientSocket == null || clientSocket.isClosed()) {
                statusLabel.setText("Client is not connected.");
                JOptionPane.showMessageDialog(this, "No client connected to send the file.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (payloadFile == null || !payloadFile.exists()) {
                statusLabel.setText("Payload file not found.");
                JOptionPane.showMessageDialog(this, "Encrypted payload file not found.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
                byte[] fileBytes = Files.readAllBytes(payloadFile.toPath());
                System.out.println(" Output Stream is : " + payloadFile.getAbsolutePath());
                dos.writeUTF(payloadFile.getName());
                dos.writeLong(fileBytes.length);
                dos.write(fileBytes);
                dos.flush();

                statusLabel.setText("Encrypted file sent to client.");
                JOptionPane.showMessageDialog(this, "Encrypted file sent successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                ex.printStackTrace();
                statusLabel.setText("Error sending file.");
                JOptionPane.showMessageDialog(this, "Failed to send file:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SenderApp::new);
    }
}
