package Util;

import com.google.gson.Gson;

import java.time.Instant;

public class MetaDataUtil {

    private static final Gson gson = new Gson();

    //  Generate metadata from filename
    public static Metadata generateMetadata(String filename) {
        String nonce = Nonce.generateNonce();
        Nonce.markNonceAsUsed(nonce);

        long timestamp = Instant.now().toEpochMilli();

        return new Metadata(filename, timestamp, nonce);
    }

    // Convert Metadata object to JSON string
    public static String toJson(Metadata metadata) {
        return gson.toJson(metadata);
    }

}
