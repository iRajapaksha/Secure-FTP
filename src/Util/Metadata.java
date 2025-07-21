package Util;

public class Metadata {
    public String filename;
    public long timestamp;
    public String nonce;

    public Metadata(String filename, long timestamp, String nonce) {
        this.filename = filename;
        this.timestamp = timestamp;
        this.nonce = nonce;
    }
}
