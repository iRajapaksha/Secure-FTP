package sender;

import Util.Payload;
import Util.PayloadUtil;
import com.google.gson.Gson;
import security.AESUtil;
import security.RSAUtil;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
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

    private PublicKey receiverPublicKey;

    private PublicKey senderPublicKey;
    private PrivateKey senderPrivateKey;
    private SecretKey aesKey;


    public SenderApp() {
        setTitle("Secure File Sender");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 300);
        setLocationRelativeTo(null);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // File selection
        JLabel fileLabel = new JLabel("Selected File:");
        gbc.gridx = 0;
        gbc.gridy = 0;
        add(fileLabel, gbc);

        filePathField = new JTextField();
        filePathField.setEditable(false);
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        add(filePathField, gbc);

        browseButton = new JButton("Browse");
        gbc.gridx = 3;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        add(browseButton, gbc);

        // Generate AES Key
        generateAESKeyButton = new JButton("Generate AES Key");
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        add(generateAESKeyButton, gbc);

        // Generate RSA Key Pair
        generateRSAKeyPairButton = new JButton("Generate RSA Key Pair");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 4;
        add(generateRSAKeyPairButton, gbc);

        // Upload Receiver's Public Key
        uploadPublicKeyButton = new JButton("Upload Receiver's Public Key");
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 4;
        add(uploadPublicKeyButton, gbc);

        // Encrypt and Generate Payload
        encryptButton = new JButton("Encrypt and Generate Payload");
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 4;
        add(encryptButton, gbc);

        // Status label
        statusLabel = new JLabel("Status: Waiting for input...");
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 4;
        add(statusLabel, gbc);

        setupListeners();
        setVisible(true);
    }

    private void setupListeners() {
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                filePathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
                statusLabel.setText("Status: File selected");
            }
        });

        generateAESKeyButton.addActionListener(e -> {
            try {
                // 1. Generate AES Key
                aesKey = AESUtil.generateAESKey(128); // You can use 256 if needed
                System.out.println("AES Key: " + aesKey);
                // 2. Let user choose where to save the key
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save AES Key");
                int userSelection = fileChooser.showSaveDialog(this);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File keyFile = fileChooser.getSelectedFile();
                    AESUtil.saveKeyToFile(aesKey, keyFile.getAbsolutePath());
                    statusLabel.setText("Status: AES Key saved at " + keyFile.getName());
                    JOptionPane.showMessageDialog(this,
                            "AES key saved successfully:\n" + keyFile.getAbsolutePath(),
                            "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                } else {
                    statusLabel.setText("Status: AES key generation canceled.");
                }

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
                System.out.println("Sender private key: "+ senderPrivateKey);

                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Select folder to save RSA Keys");
                fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                int userSelection = fileChooser.showSaveDialog(this);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File directory = fileChooser.getSelectedFile();
                    String publicKeyPath = directory.getAbsolutePath() + File.separator + "sender_public.key";
                    String privateKeyPath = directory.getAbsolutePath() + File.separator + "sender_private.key";

                    RSAUtil.savePublicKey(senderPublicKey, publicKeyPath);
                    RSAUtil.savePrivateKey(senderPrivateKey, privateKeyPath);

                    statusLabel.setText("RSA key pair saved.");
                    JOptionPane.showMessageDialog(this,
                            "RSA key pair generated successfully:\n" + publicKeyPath + "\n" + privateKeyPath,
                            "Success", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    statusLabel.setText("RSA key generation canceled.");
                }

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
            fileChooser.setDialogTitle("Select Receiver's Public Key (.pem or .der)");

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

                File inputFile = new File(filePathField.getText());
                System.out.println("Input file path: "+ inputFile.getAbsolutePath());
                Payload payload = PayloadUtil.encryptPayload(inputFile, aesKey, receiverPublicKey, senderPrivateKey);

                // Save payload JSON
                Gson gson = new Gson();
                String payloadJson = gson.toJson(payload);
                System.out.println("Encrypted payload: " +payloadJson);
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save Payload JSON File");
                int userSelection = fileChooser.showSaveDialog(this);
                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File saveFile = fileChooser.getSelectedFile();
                    Files.writeString(saveFile.toPath(), payloadJson);
                    statusLabel.setText("Status: Payload saved successfully.");
                    JOptionPane.showMessageDialog(this, "Payload saved:\n" + saveFile.getAbsolutePath(), "Success", JOptionPane.INFORMATION_MESSAGE);
                }

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error generating payload.");
                JOptionPane.showMessageDialog(this, "Payload generation failed:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SenderApp::new);
    }
}
