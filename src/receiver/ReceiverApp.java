package receiver;

import Util.MetaDataUtil;
import Util.Payload;
import security.RSAUtil;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class ReceiverApp extends JFrame {

    private JTextField filePathField;
    private JButton browsePayloadButton;
    private JButton generateRSAKeyButton;
    private JButton decryptButton;
    private JButton verifySenderButton;
    private JButton verifyIntegrityButton;
    private JLabel statusLabel;

    private File selectedPayloadFile;
    private PrivateKey receiverPrivateKey;
    private PublicKey receiverPublicKey;

    private PublicKey senderPublicKey;

    public ReceiverApp() {
        setTitle("Secure File Receiver");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 300);
        setLocationRelativeTo(null);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Payload File Selection
        JLabel payloadLabel = new JLabel("Payload File:");
        gbc.gridx = 0;
        gbc.gridy = 0;
        add(payloadLabel, gbc);

        filePathField = new JTextField();
        filePathField.setEditable(false);
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        add(filePathField, gbc);

        browsePayloadButton = new JButton("Browse");
        gbc.gridx = 3;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        add(browsePayloadButton, gbc);

        // Generate RSA Key Pair
        generateRSAKeyButton = new JButton("Generate RSA Key Pair");
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        add(generateRSAKeyButton, gbc);

        // Decrypt Payload
        decryptButton = new JButton("Decrypt Payload");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 4;
        add(decryptButton, gbc);

        // Verify Sender
        verifySenderButton = new JButton("Verify Sender");
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 4;
        add(verifySenderButton, gbc);

        // Verify Integrity
        verifyIntegrityButton = new JButton("Verify Integrity");
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 4;
        add(verifyIntegrityButton, gbc);

        // Status Label
        statusLabel = new JLabel("Status: Waiting for input...");
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 4;
        add(statusLabel, gbc);

        setupListeners();
        setVisible(true);
    }

    private void setupListeners() {
        browsePayloadButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Select Payload JSON File");
            int result = fileChooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                selectedPayloadFile = fileChooser.getSelectedFile();
                filePathField.setText(selectedPayloadFile.getAbsolutePath());
                statusLabel.setText("Status: Payload file selected.");
                System.out.println("Selected File path: " + selectedPayloadFile.getAbsolutePath());
            }
        });

        generateRSAKeyButton.addActionListener(e -> {
            try {
                KeyPair keyPair = RSAUtil.generateRSAKeyPair(2048);
                receiverPrivateKey = keyPair.getPrivate();
                receiverPublicKey =keyPair.getPublic();
                System.out.println("Receiver public key: " + receiverPublicKey);
                System.out.println("Receiver private key: " + receiverPrivateKey);

                JFileChooser chooser = new JFileChooser();
                chooser.setDialogTitle("Select folder to save RSA keys");
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                int userSelection = chooser.showSaveDialog(this);
                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File dir = chooser.getSelectedFile();
                    String pubPath = dir.getAbsolutePath() + File.separator + "receiver_public.key";
                    String privPath = dir.getAbsolutePath() + File.separator + "receiver_private.key";

                    RSAUtil.savePublicKey(receiverPublicKey, pubPath);
                    RSAUtil.savePrivateKey(receiverPrivateKey, privPath);

                    statusLabel.setText("Status: RSA key pair saved.");
                    JOptionPane.showMessageDialog(this,
                            "Keys saved:\n" + pubPath + "\n" + privPath,
                            "Success", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    statusLabel.setText("RSA key generation canceled.");
                }
            } catch (Exception ex) {
                statusLabel.setText("Error: Failed to generate RSA keys.");
                ex.printStackTrace();
            }
        });

        decryptButton.addActionListener(e -> {
            try {
                if (selectedPayloadFile == null) {
                    JOptionPane.showMessageDialog(this, "Select a payload file first.");
                    return;
                }

                // Load sender's public key
                JFileChooser keyChooser = new JFileChooser();
                keyChooser.setDialogTitle("Select Sender's Public Key");
                int result = keyChooser.showOpenDialog(this);
                if (result != JFileChooser.APPROVE_OPTION) return;

                File senderPublicKeyFile = keyChooser.getSelectedFile();
                senderPublicKey = RSAUtil.loadPublicKey(senderPublicKeyFile.getAbsolutePath());
                System.out.println("Sender public key: "+ senderPublicKey);
                // Parse Payload JSON
                String json = Files.readString(selectedPayloadFile.toPath());
                Payload payload = new com.google.gson.Gson().fromJson(json, Payload.class);
                System.out.println("Encrypted payload: " + payload);

                // Select output directory for decrypted file
                JFileChooser outputChooser = new JFileChooser();
                outputChooser.setDialogTitle("Select Folder to Save Decrypted File");
                outputChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                if (outputChooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

                File outputDir = outputChooser.getSelectedFile();

                File decryptedFile = Util.PayloadUtil.decryptPayload(payload, receiverPrivateKey, senderPublicKey, outputDir.getAbsolutePath());

                statusLabel.setText("Status: Decryption successful.");
                JOptionPane.showMessageDialog(this, "Decrypted file saved at:\n" + decryptedFile.getAbsolutePath());

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error during decryption.");
                JOptionPane.showMessageDialog(this, "Failed to decrypt: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });


        verifySenderButton.addActionListener(e -> {
            try {
                if (selectedPayloadFile == null) {
                    JOptionPane.showMessageDialog(this, "Select a payload file first.");
                    return;
                }

                // Load sender's public key
                JFileChooser chooser = new JFileChooser();
                chooser.setDialogTitle("Select Sender's Public Key");
                if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

                File senderKeyFile = chooser.getSelectedFile();
                var senderPublicKey = RSAUtil.loadPublicKey(senderKeyFile.getAbsolutePath());

                // Load payload
                String json = Files.readString(selectedPayloadFile.toPath());
                Payload payload = new com.google.gson.Gson().fromJson(json, Payload.class);

                byte[] hash = Base64.getDecoder().decode(payload.H);
                byte[] signature = Base64.getDecoder().decode(payload.Signature);

                boolean verified = security.HashUtil.verifySignature(hash, signature, senderPublicKey);

                statusLabel.setText(verified ? "Sender verification successful." : "Sender verification failed.");
                JOptionPane.showMessageDialog(this,
                        verified ? "Signature is valid. Sender is verified." : "Signature invalid. Sender could not be verified.",
                        verified ? "Success" : "Failure",
                        verified ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE);

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error verifying sender.");
            }
        });


        verifyIntegrityButton.addActionListener(e -> {
            try {
                if (selectedPayloadFile == null) {
                    JOptionPane.showMessageDialog(this, "Select a payload file first.");
                    return;
                }

                // Load payload
                String json = Files.readString(selectedPayloadFile.toPath());
                Payload payload = new com.google.gson.Gson().fromJson(json, Payload.class);

                byte[] encryptedFileBytes = Base64.getDecoder().decode(payload.Enc_File);
                byte[] originalHash = Base64.getDecoder().decode(payload.H);
                String metadataJson = MetaDataUtil.toJson(payload.metadata);
                byte[] metadataBytes = metadataJson.getBytes();

                byte[] combined = new byte[encryptedFileBytes.length + metadataBytes.length];
                System.arraycopy(encryptedFileBytes, 0, combined, 0, encryptedFileBytes.length);
                System.arraycopy(metadataBytes, 0, combined, encryptedFileBytes.length, metadataBytes.length);

                byte[] recalculatedHash = security.HashUtil.hashBytes(combined);

                boolean matches = java.util.Arrays.equals(originalHash, recalculatedHash);

                statusLabel.setText(matches ? "Integrity verified." : "Integrity check failed.");
                JOptionPane.showMessageDialog(this,
                        matches ? "Integrity check passed. File is unmodified." : "Integrity check failed. File may be tampered.",
                        matches ? "Valid" : "Invalid",
                        matches ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error verifying integrity.");
            }
        });

    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(ReceiverApp::new);
    }
}
