package Util;

import java.security.PublicKey;

public class Payload {
    public String Enc_File;
    public String Enc_K;
    public Metadata metadata;
    public String H;
    public String Signature;
    public String SenderPublicKey;

    public Payload(String encFile, String encK, Metadata metadata, String hash, String signature, String senderPublicKey) {
        this.Enc_File = encFile;
        this.Enc_K = encK;
        this.metadata = metadata;
        this.H = hash;
        this.Signature = signature;
        this.SenderPublicKey = senderPublicKey;
    }
}
