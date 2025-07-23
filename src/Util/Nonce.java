package Util;

import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class Nonce {

    private static final Set<String> usedNoncesSender = new HashSet<>();
    private static final Set<String> usedNoncesReceiver = new HashSet<>();
    private static final String NONCE_FILE_SENDER = "used_nonces_sender.txt";
    private static final String NONCE_FILE_RECEIVER = "used_nonces_receiver.txt";


    static {
        // Load nonces from disk at startup
        loadNoncesFromDisk();
    }

    // Generate a random 128-bit nonce
    public static String generateNonce() {
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }

    // Check if nonce is already used
    public static boolean isNonceUsed(String nonce) {
        return usedNoncesReceiver.contains(nonce);
    }

    // Mark nonce as used
    public static void markNonceAsUsed(String nonce) {
        usedNoncesSender.add(nonce);
        saveNoncesToDisk(); //
    }

    // Save used nonces to disk
    private static void saveNoncesToDisk() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(NONCE_FILE_SENDER))) {
            for (String nonce : usedNoncesSender) {
                writer.write(nonce);
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("Error saving nonces: " + e.getMessage());
        }
    }

    // Load used nonces from disk
    private static void loadNoncesFromDisk() {
        File file = new File(NONCE_FILE_SENDER);
        if (!file.exists()) return;

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String nonce;
            while ((nonce = reader.readLine()) != null) {
                usedNoncesSender.add(nonce.trim());
            }
        } catch (IOException e) {
            System.err.println("Error loading nonces: " + e.getMessage());
        }
    }

    //  Clear nonce history
    public static void clearNonceHistory() {
        usedNoncesSender.clear();
        new File(NONCE_FILE_SENDER).delete();
    }
}
