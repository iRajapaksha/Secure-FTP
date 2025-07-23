package Util;

import security.HashUtil;

import security.AESUtil;
import security.RSAUtil;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class PayloadUtil {

    private byte[] receivedHash;
    private byte[] receivedSignature;
    private Metadata metadata;
    private PublicKey senderPublicKey;
    private byte[] encryptedFileBytes;



    public static Payload encryptPayload(File inputFile,
                                         SecretKey aesKey,
                                         PublicKey receiverPublicKey,
                                         PrivateKey senderPrivateKey,
                                         PublicKey senderPublicKey) throws Exception {

        // Read file bytes
        byte[] fileBytes = Files.readAllBytes(inputFile.toPath());

        // Encrypt file using AES key
        byte[] encryptedFileBytes = AESUtil.encryptFile( inputFile,aesKey);

        // Generate metadata
        Metadata metadata = MetaDataUtil.generateMetadata(inputFile.getName());
        String metadataJson = MetaDataUtil.toJson(metadata);
        System.out.println("Generated metadata: " + metadataJson);
        byte[] metadataBytes = metadataJson.getBytes();

        // Hash (Enc_File + metadata)
       // byte[] encryptedFileBytes = Files.readAllBytes(encryptedFile.toPath());
        byte[] combined = new byte[encryptedFileBytes.length + metadataBytes.length];
        System.arraycopy(encryptedFileBytes, 0, combined, 0, encryptedFileBytes.length);
        System.arraycopy(metadataBytes, 0, combined, encryptedFileBytes.length, metadataBytes.length);
        byte[] hash = HashUtil.hashBytes(combined);

        // Sign hash with sender's private key
        byte[] signature = HashUtil.signHash(hash, senderPrivateKey);

        // Encrypt AES key using receiver’s RSA public key
        byte[] encryptedAESKey = RSAUtil.encryptWithRSAKey(aesKey, receiverPublicKey);


        // Encode all to Base64 and return Payload
        return new Payload(
                Base64.getEncoder().encodeToString(encryptedFileBytes),
                Base64.getEncoder().encodeToString(encryptedAESKey),
                metadata,
                Base64.getEncoder().encodeToString(hash),
                Base64.getEncoder().encodeToString(signature),
                Base64.getEncoder().encodeToString(senderPublicKey.getEncoded())
        );
    }

    private byte[] encryptedAESKey;
    private byte[] senderPublicKeyBytes;
    public  File decryptPayload(PrivateKey receiverPrivateKey,
                                      String outputDirPath) throws Exception {

        // Decrypt AES key with receiver’s private RSA key
        SecretKey aesKey = RSAUtil.decryptWithRSAKey(encryptedAESKey, receiverPrivateKey);

        // Decrypt file with AES key
        byte[] decryptedBytes = AESUtil.decryptFile(encryptedFileBytes, aesKey);

        // Save decrypted file
        File decryptedFile = new File(outputDirPath + "/decrypted_" + metadata.getFilename());
        Files.write(decryptedFile.toPath(), decryptedBytes);

        return decryptedFile;
    }

    public  boolean verifyPayload() {

        try {
            String metadataJson = MetaDataUtil.toJson(metadata);
            byte[] metadataBytes = metadataJson.getBytes();

            byte[] combined = new byte[encryptedFileBytes.length + metadataBytes.length];
            System.arraycopy(encryptedFileBytes, 0, combined, 0, encryptedFileBytes.length);
            System.arraycopy(metadataBytes, 0, combined, encryptedFileBytes.length, metadataBytes.length);

            byte[] computedHash = HashUtil.hashBytes(combined);

            // 6. Verify hash integrity
            boolean isHashEqual = java.util.Arrays.equals(receivedHash, computedHash);
            return isHashEqual;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }
    public  boolean verifySender(Payload payload){

        // Decode Base64 fields
        this.encryptedFileBytes = Base64.getDecoder().decode(payload.Enc_File);
        this.encryptedAESKey = Base64.getDecoder().decode(payload.Enc_K);
        this.receivedHash = Base64.getDecoder().decode(payload.H);
        this.receivedSignature= Base64.getDecoder().decode(payload.Signature);
        this.senderPublicKeyBytes = Base64.getDecoder().decode(payload.SenderPublicKey);
        this.metadata = payload.metadata;

        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(senderPublicKeyBytes);
            KeyFactory  keyFactory = KeyFactory.getInstance("RSA");
            this.senderPublicKey = keyFactory.generatePublic(keySpec);

            return  HashUtil.verifySignature(receivedHash, receivedSignature, senderPublicKey);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }


    private static final long MAX_TIME_DIFF_MS = 5 * 60 * 1000;

    public boolean isReplaySafe(){
        boolean isTimestampValid;
        boolean isNonceValid = true;

        long currentTime = System.currentTimeMillis();
        long messageTime = metadata.getTimestamp();
        isTimestampValid = Math.abs(currentTime - messageTime) <= MAX_TIME_DIFF_MS;

        {
            if ( Nonce.isNonceUsed(metadata.getNonce())) {
                isNonceValid = false;
                System.out.println("Reused nonce detected");// Replay detected
            }

        }
        return isNonceValid && isTimestampValid;



    }


}
