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
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import java.util.Map;


public class SenderApp extends JFrame {

    private JTextField filePathField;
    private JButton browseButton;
    private JButton generateAESKeyButton;
    private JButton generateRSAKeyPairButton;
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
    private Map<String, String> allowedUsers = Map.of(
            "abc123", "pass123"
    );
    public SenderApp() {


        setTitle("Secure File Sender");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 400);
        setLocationRelativeTo(null);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Status label
        statusLabel = new JLabel("Status: Please start the server");
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 4;
        add(statusLabel, gbc);

        //Server connection
        connectButton = new JButton("Start Server");
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        add(connectButton, gbc);

        connectionStatus = new JLabel("Waiting for a connection");
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        add(connectionStatus,gbc);

        // File selection
        JLabel fileLabel = new JLabel("Selected File:");
        gbc.gridx = 0;
        gbc.gridy = 2;
        add(fileLabel, gbc);

        filePathField = new JTextField();
        filePathField.setEditable(false);
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        add(filePathField, gbc);

        browseButton = new JButton("Browse");
        gbc.gridx = 3;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        add(browseButton, gbc);

        // Generate AES Key
        generateAESKeyButton = new JButton("Generate AES Key");
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 4;
        add(generateAESKeyButton, gbc);

        // Generate RSA Key Pair
        generateRSAKeyPairButton = new JButton("Generate RSA Key Pair");
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 4;
        add(generateRSAKeyPairButton, gbc);

        // Encrypt and Generate Payload
        encryptButton = new JButton("Encrypt and Generate Payload");
        encryptButton.setEnabled(false); // only enable after all keys generated
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 4;
        add(encryptButton, gbc);

        // Send button
        sendButton = new JButton("Send Encrypted File");
        sendButton.setEnabled(false); // Only enabled after connecting client
        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.gridwidth = 4;
        add(sendButton, gbc);

        setupListeners();
        setVisible(true);
    }



    private void setupListeners() {

        connectButton.addActionListener(e -> {
            new Thread(() -> {
                try {
                    statusLabel.setText("Status: Server started.");
                    serverSocket = new ServerSocket(9999);
                    connectionStatus.setText("Waiting for client...");
                    clientSocket = serverSocket.accept(); // Blocking call
                    connectionStatus.setText("Connected to " + clientSocket.getInetAddress());
                    statusLabel.setText("Status: Authenticating user.");
                    try {

                        DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
                        String username = dis.readUTF();
                        String password = dis.readUTF();
                        login(username,password);

                        InputStream is = clientSocket.getInputStream();
                        ObjectInputStream ois = new ObjectInputStream(is);
                        byte[] keyBytes = (byte[]) ois.readObject();

                        // Convert to PublicKey
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        receiverPublicKey = keyFactory.generatePublic(keySpec);
                        statusLabel.setText("Status: Select a file to encrypt");

                        System.out.println("Received public key from receiver: " + receiverPublicKey);
                        connectionStatus.setText("Authenticated user: " + username );
                        updateEncryptButtonState();

                    } catch (IOException ex) {
                        ex.printStackTrace();
                        connectionStatus.setText("Connection failed");
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException | ClassNotFoundException ex) {
                        throw new RuntimeException(ex);
                    }


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
                statusLabel.setText("Status: Generate an AES key.");
            }
        });

        generateAESKeyButton.addActionListener(e -> {
            try {
                //  Generate AES Key
                aesKey = AESUtil.generateAESKey(128);
                System.out.println("AES Key: " + aesKey);
                statusLabel.setText("Status: Generate RSA key pair.");
                updateEncryptButtonState();


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
                statusLabel.setText("Status: Encrypt the file.");
                updateEncryptButtonState();
            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Error generating RSA key pair.");
                JOptionPane.showMessageDialog(this,
                        "Failed to generate RSA key pair:\n" + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
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
                    statusLabel.setText("Status: Send encrypted file");
                    sendButton.setEnabled(true);
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
    private void updateEncryptButtonState() {
        boolean ready = receiverPublicKey != null && aesKey != null && senderPrivateKey != null;
        encryptButton.setEnabled(ready);
    }

    private void login(String username, String password){
        if (allowedUsers.containsKey(username) && allowedUsers.get(username).equals(password)) {
            System.out.println("Authenticated user: " + username);
            connectionStatus.setText("Authenticated: " + username);
            // Continue receiving public key
        } else {
            System.out.println("Authentication failed");
            connectionStatus.setText("Authentication failed");
            //clientSocket.close();
            return;
        }

    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SenderApp::new);
    }
}
