package Util;

import com.google.gson.Gson;

import java.time.Instant;

public class MetaDataUtil {

    private static final Gson gson = new Gson();

    // 1. Generate metadata from filename
    public static Metadata generateMetadata(String filename) {
        String nonce = Nonce.generateNonce();
        Nonce.markNonceAsUsed(nonce);

        long timestamp = Instant.now().toEpochMilli(); // or System.currentTimeMillis()

        return new Metadata(filename, timestamp, nonce);
    }

    // 2. Convert Metadata object to JSON string
    public static String toJson(Metadata metadata) {
        return gson.toJson(metadata);
    }

    // 3. Convert JSON string back to Metadata object
    public static Metadata fromJson(String json) {
        return gson.fromJson(json, Metadata.class);
    }
}
