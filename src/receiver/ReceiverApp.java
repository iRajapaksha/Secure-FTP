package receiver;

import Util.Payload;
import Util.PayloadUtil;
import security.RSAUtil;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;


public class ReceiverApp extends JFrame {

    private JButton generateRSAKeyButton;
    private JButton decryptButton;
    private JButton verifySenderButton;
    private JButton verifyIntegrityButton;
    private JLabel statusLabel;
    private File encryptedPayloadFile;
    private PrivateKey receiverPrivateKey;
    private PublicKey receiverPublicKey;
    private JButton connectButton;
    private JButton replaySafetyButton;
    private String folderPath;

    private static Socket socket = null;


    PayloadUtil payloadUtil = new PayloadUtil();
    public ReceiverApp() {
        setTitle("Secure File Receiver");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 400);
        setLocationRelativeTo(null);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Status Label
        statusLabel = new JLabel("Status: Generate RSA key pair.");
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 4;
        add(statusLabel, gbc);

        // Generate RSA Key Pair
        generateRSAKeyButton = new JButton("Generate RSA Key Pair");
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        add(generateRSAKeyButton, gbc);

        connectButton = new JButton("Connect to Server");
        connectButton.setEnabled(false);
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 4;
        add(connectButton, gbc);

        // Decrypt Payload
        decryptButton = new JButton("Decrypt Payload");
        decryptButton.setEnabled(false);
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 4;
        add(decryptButton, gbc);

        // Verify Integrity
        verifyIntegrityButton = new JButton("Verify Integrity");
        verifyIntegrityButton.setEnabled(false);
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 4;
        add(verifyIntegrityButton, gbc);

        // Verify Sender
        verifySenderButton = new JButton("Verify Sender");
        verifySenderButton.setEnabled(false);
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 4;
        add(verifySenderButton, gbc);

        // Verify Sender
        replaySafetyButton = new JButton("Check Replay Safety");
        replaySafetyButton.setEnabled(false);
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 4;
        add(replaySafetyButton, gbc);

        setupListeners();
        setVisible(true);
    }


    private void setupListeners() {
        connectButton.addActionListener(e -> {
            try {
                socket = new Socket("localhost", 9999);
                if(socket.isConnected()){
                    System.out.println("Connected to the server");
                    connectButton.setText("Connected");

                    String[] credentials = promptCredentials();

                    if(credentials == null){
                        statusLabel.setText("Status: Authentication canceled.");
                    }
                    else {
                        String username = credentials[0];
                        String password = credentials[1];

                        OutputStream os = socket.getOutputStream();
                        DataOutputStream dos = new DataOutputStream(os);

                        dos.writeUTF(username);
                        dos.writeUTF(password);
                        dos.flush();

                        System.out.println("Username and password sent.");
                    }

                    // Send receiver's public key
                    OutputStream os = socket.getOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(os);
                    oos.writeObject(receiverPublicKey.getEncoded());  // Send encoded form of public key
                    oos.flush();
                    System.out.println("Public key sent to sender.");

                }else{
                    System.out.println("No server detected");
                }

                // Prompt for destination folder
                JFileChooser chooser = new JFileChooser();
                chooser.setDialogTitle("Select Folder to Save Received File");
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

                File destDir = chooser.getSelectedFile();
                folderPath = destDir.getAbsolutePath();
                System.out.println("destination directory: " + folderPath);
                statusLabel.setText("Waiting for encrypted file...");
                new Thread(this::listenForFile).start();

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Connection  failed.");
            }
        });


        generateRSAKeyButton.addActionListener(e -> {
            try {
                KeyPair keyPair = RSAUtil.generateRSAKeyPair(2048);
                receiverPrivateKey = keyPair.getPrivate();
                receiverPublicKey =keyPair.getPublic();
                System.out.println("Receiver public key: " + receiverPublicKey);
                statusLabel.setText("Connect to the server.");
                connectButton.setEnabled(true);

            } catch (Exception ex) {
                statusLabel.setText("Error: Failed to generate RSA keys.");
                ex.printStackTrace();
            }
        });

        decryptButton.addActionListener(e -> {
            try {
                if (encryptedPayloadFile == null) {
                    JOptionPane.showMessageDialog(this, "Select a payload file first.");
                    return;
                }

                // Parse Payload JSON
                String json = Files.readString(encryptedPayloadFile.toPath());
                Payload payload = new com.google.gson.Gson().fromJson(json, Payload.class);
                System.out.println("Encrypted payload: " + payload);


                File decryptedFile = payloadUtil.decryptPayload(payload, receiverPrivateKey, folderPath);

                statusLabel.setText("Status: Decryption successful. Verify integrity.");
                verifyIntegrityButton.setEnabled(true);
                verifySenderButton.setEnabled(true);
                replaySafetyButton.setEnabled(true);
                JOptionPane.showMessageDialog(this, "Decrypted file saved at:\n" + decryptedFile.getAbsolutePath());

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error during decryption.");
                JOptionPane.showMessageDialog(this, "Failed to decrypt: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        verifySenderButton.addActionListener(e -> {
            boolean isValid = payloadUtil.verifySender();
            if(isValid){
                statusLabel.setText("Status: Sender Verified.");
            }
            else{
                statusLabel.setText("Status: Unverified Sender.");
            }
        });

        verifyIntegrityButton.addActionListener(e -> {
         boolean isHashEqual = payloadUtil.verifyPayload();
         if(isHashEqual){
             statusLabel.setText("Status: Integrity confirmed. Verify sender.");
         }
         else {
             statusLabel.setText("Status: Integrity compromised.");
         }
        });

        replaySafetyButton.addActionListener(e ->{
            boolean isReplaySafe = payloadUtil.isReplaySafe();
            if(isReplaySafe){
                statusLabel.setText("Replay safety confirmed.");
            }
            else{
                statusLabel.setText("Replay attack detected.");
            }
        });

    }

    private void listenForFile() {
        try {
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            while (true) {
                // Wait for file name
                String fileName = dis.readUTF();
                long fileLength = dis.readLong();
                byte[] fileBytes = new byte[(int) fileLength];
                dis.readFully(fileBytes);

                File outputFile = new File(folderPath, fileName);
                Files.write(outputFile.toPath(), fileBytes);
                encryptedPayloadFile = outputFile;
                System.out.println("Received and saved encrypted payload: " + outputFile.getAbsolutePath());

                // Update GUI in the Swing thread
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, "New file received: " + fileName);
                    statusLabel.setText("Status: File received. Ready to decrypt.");
                });
                decryptButton.setEnabled(true);
            }
        } catch (IOException e) {
            e.printStackTrace();
            SwingUtilities.invokeLater(() ->
                    statusLabel.setText("Error receiving file or connection closed.")
            );
        }
    }

    private String[] promptCredentials() {
        JTextField usernameField = new JTextField();
        JPasswordField passwordField = new JPasswordField();

        JPanel panel = new JPanel(new GridLayout(2, 2));
        panel.add(new JLabel("Username:"));
        panel.add(usernameField);
        panel.add(new JLabel("Password:"));
        panel.add(passwordField);

        int result = JOptionPane.showConfirmDialog(
                this,
                panel,
                "Enter Credentials",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );

        if (result == JOptionPane.OK_OPTION) {
            String username = usernameField.getText();
            String password = new String(passwordField.getPassword());
            return new String[]{username, password};
        } else {
            return null;
        }
    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(ReceiverApp::new);
    }
}
