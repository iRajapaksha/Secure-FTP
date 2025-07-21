package Util;

public class Metadata {
    private String filename;
    private long timestamp;
    private String nonce;

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public Metadata(String filename, long timestamp, String nonce) {
        this.filename = filename;
        this.timestamp = timestamp;
        this.nonce = nonce;
    }
}
