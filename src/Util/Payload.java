package Util;

public class Payload {
    public String Enc_File;
    public String Enc_K;
    public Metadata metadata;
    public String H;
    public String Signature;

    public Payload(String encFile, String encK, Metadata metadata, String hash, String signature) {
        this.Enc_File = encFile;
        this.Enc_K = encK;
        this.metadata = metadata;
        this.H = hash;
        this.Signature = signature;
    }
}
