package Util;

public class Metadata {
    private String filename;
    private long timestamp;
    private String nonce;

    public String getFilename() {
        return filename;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getNonce() {
        return nonce;
    }

    public Metadata(String filename, long timestamp, String nonce) {
        this.filename = filename;
        this.timestamp = timestamp;
        this.nonce = nonce;
    }
}
