package Util;

import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class Nonce {

    private static final Set<String> usedNonces = new HashSet<>();
    private static final String NONCE_FILE = "used_nonces.txt"; // file-based persistence (optional)

    static {
        // Load nonces from disk at startup
        loadNoncesFromDisk();
    }

    // 1. Generate a random 128-bit (16-byte) nonce
    public static String generateNonce() {
        byte[] nonceBytes = new byte[16]; // 128-bit
        new SecureRandom().nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }

    // 2. Check if nonce is already used
    public static boolean isNonceUsed(String nonce) {
        return usedNonces.contains(nonce);
    }

    // 3. Mark nonce as used
    public static void markNonceAsUsed(String nonce) {
        usedNonces.add(nonce);
        saveNoncesToDisk(); // optional: auto-save on each new nonce
    }

    // 4. Save used nonces to disk
    private static void saveNoncesToDisk() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(NONCE_FILE))) {
            for (String nonce : usedNonces) {
                writer.write(nonce);
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("Error saving nonces: " + e.getMessage());
        }
    }

    // 5. Load used nonces from disk
    private static void loadNoncesFromDisk() {
        File file = new File(NONCE_FILE);
        if (!file.exists()) return;

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String nonce;
            while ((nonce = reader.readLine()) != null) {
                usedNonces.add(nonce.trim());
            }
        } catch (IOException e) {
            System.err.println("Error loading nonces: " + e.getMessage());
        }
    }

    // 6. (Optional) Clear nonce history
    public static void clearNonceHistory() {
        usedNonces.clear();
        new File(NONCE_FILE).delete();
    }
}
