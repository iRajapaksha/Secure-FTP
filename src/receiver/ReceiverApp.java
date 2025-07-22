package receiver;

import Util.MetaDataUtil;
import Util.Payload;
import Util.PayloadUtil;
import security.RSAUtil;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
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


    private BufferedReader in;
    private JButton connectButton;
    private JButton savePayloadButton;
    private String folderPath;
    public static final int port = 9999;
    private static Socket socket = null;
    public static InetAddress ipAddress = null;

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

        connectButton = new JButton("Connect to Server");
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 4;
        add(connectButton, gbc);

        savePayloadButton = new JButton("Save File");
        gbc.gridx = 3;
        gbc.gridy = 1;
        gbc.gridwidth = 3;
        add(savePayloadButton, gbc);

        // Payload File Selection
        JLabel payloadLabel = new JLabel("Payload File:");
        gbc.gridx = 0;
        gbc.gridy = 1;
        add(payloadLabel, gbc);

        filePathField = new JTextField();
        filePathField.setEditable(false);
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        add(filePathField, gbc);

        browsePayloadButton = new JButton("Browse");
        gbc.gridx = 3;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        add(browsePayloadButton, gbc);

        // Generate RSA Key Pair
        generateRSAKeyButton = new JButton("Generate RSA Key Pair");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 4;
        add(generateRSAKeyButton, gbc);

        // Decrypt Payload
        decryptButton = new JButton("Decrypt Payload");
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 4;
        add(decryptButton, gbc);

        // Verify Sender
        verifySenderButton = new JButton("Verify Sender");
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 4;
        add(verifySenderButton, gbc);

        // Verify Integrity
        verifyIntegrityButton = new JButton("Verify Integrity");
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 4;
        add(verifyIntegrityButton, gbc);

        // Status Label
        statusLabel = new JLabel("Status: Waiting for input...");
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 4;
        add(statusLabel, gbc);

        setupListeners();
        setVisible(true);
    }

    private void setupListeners() {
        connectButton.addActionListener(e -> {
            try {
                socket = new Socket("localhost", 9999);
                if(socket.isConnected()){
                    System.out.println("Connected to the server");
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
                statusLabel.setText("Connected. Output: " + folderPath);

            } catch (Exception ex) {
                ex.printStackTrace();
                statusLabel.setText("Connection  failed.");
            }
        });

        savePayloadButton.addActionListener(e->{
            saveFile();
        });

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
                //System.out.println("Receiver private key: " + receiverPrivateKey);

                JFileChooser chooser = new JFileChooser();
                chooser.setDialogTitle("Select folder to save RSA keys");
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                int userSelection = chooser.showSaveDialog(this);
                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File dir = chooser.getSelectedFile();
                    String pubPath = dir.getAbsolutePath() + File.separator + "receiver_public.key";
                   // String privPath = dir.getAbsolutePath() + File.separator + "receiver_private.key";

                    RSAUtil.savePublicKey(receiverPublicKey, pubPath);
                   // RSAUtil.savePrivateKey(receiverPrivateKey, privPath);

                    statusLabel.setText("Status: RSA public key saved.");
                    JOptionPane.showMessageDialog(this,
                            "Keys saved:\n" + pubPath + "\n" ,
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

                // Parse Payload JSON
                String json = Files.readString(selectedPayloadFile.toPath());
                Payload payload = new com.google.gson.Gson().fromJson(json, Payload.class);
                System.out.println("Encrypted payload: " + payload);


                File decryptedFile = payloadUtil.decryptPayload(payload, receiverPrivateKey, folderPath);

                statusLabel.setText("Status: Decryption successful.");
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
             statusLabel.setText("Status: Integrity is validated.");
         }
         else {
             statusLabel.setText("Status: Integrity compromised.");
         }
        });

    }

    private void saveFile() {
        try {
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            // Read file name
            String fileName = dis.readUTF();
            // Read file length
            long fileLength = dis.readLong();
            // Read file data
            byte[] fileBytes = new byte[(int) fileLength];
            dis.readFully(fileBytes);

            // Save received file
            File outputFile = new File(folderPath, fileName);
            Files.write(outputFile.toPath(), fileBytes);

            selectedPayloadFile = outputFile;

            System.out.println("Received and saved encrypted payload: " + outputFile.getAbsolutePath());
            statusLabel.setText("Status: File received and saved.");


        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(ReceiverApp::new);
    }
}
