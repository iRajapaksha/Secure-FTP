package Util;

import security.HashUtil;

import security.AESUtil;
import security.RSAUtil;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class PayloadUtil {

    public static Payload encryptPayload(File inputFile,
                                         SecretKey aesKey,
                                         PublicKey receiverPublicKey,
                                         PrivateKey senderPrivateKey) throws Exception {

        // 1. Read file bytes
        byte[] fileBytes = Files.readAllBytes(inputFile.toPath());

        // 2. Encrypt file using AES key
        File encryptedFile = AESUtil.encryptFile( inputFile,aesKey);

        // 3. Generate metadata
        Metadata metadata = MetaDataUtil.generateMetadata(inputFile.getName());
        String metadataJson = MetaDataUtil.toJson(metadata);
        System.out.println("Generated metadata: " + metadataJson);
        byte[] metadataBytes = metadataJson.getBytes();

        // 4. Hash (Enc_File + metadata)
        byte[] encryptedFileBytes = Files.readAllBytes(encryptedFile.toPath());
        byte[] combined = new byte[encryptedFileBytes.length + metadataBytes.length];
        System.arraycopy(encryptedFileBytes, 0, combined, 0, encryptedFileBytes.length);
        System.arraycopy(metadataBytes, 0, combined, encryptedFileBytes.length, metadataBytes.length);
        byte[] hash = HashUtil.hashBytes(combined);

        // 5. Sign hash with sender's private key
        byte[] signature = HashUtil.signHash(hash, senderPrivateKey);

        // 6. Encrypt AES key using receiver’s RSA public key
        byte[] encryptedAESKey = RSAUtil.encryptWithRSAKey(aesKey, receiverPublicKey);

        // 7. Encode all to Base64 and return Payload
        return new Payload(
                Base64.getEncoder().encodeToString(encryptedFileBytes),
                Base64.getEncoder().encodeToString(encryptedAESKey),
                metadata,
                Base64.getEncoder().encodeToString(hash),
                Base64.getEncoder().encodeToString(signature)
        );
    }
    public static File decryptPayload(Payload payload,
                                      PrivateKey receiverPrivateKey,
                                      PublicKey senderPublicKey,
                                      String outputDirPath) throws Exception {

        // 1. Decode Base64 fields
        byte[] encryptedFileBytes = Base64.getDecoder().decode(payload.Enc_File);
        byte[] encryptedAESKey = Base64.getDecoder().decode(payload.Enc_K);
        byte[] receivedHash = Base64.getDecoder().decode(payload.H);
        byte[] receivedSignature = Base64.getDecoder().decode(payload.Signature);
        Metadata metadata = payload.metadata;
        System.out.println("Decrypted metadata: " + metadata);

        // 2. Decrypt AES key with receiver’s private RSA key
        SecretKey aesKey = RSAUtil.decryptWithRSAKey(encryptedAESKey, receiverPrivateKey);
        System.out.println("Decrypted aesKey: " + aesKey);
        // 3. Save encrypted file to temp file
        File encryptedTempFile = new File(outputDirPath + "/temp_encrypted_" + metadata.getFilename());
        Files.write(encryptedTempFile.toPath(), encryptedFileBytes);

        String encryptedTempFilePath = encryptedTempFile.toPath().toString();
        // 4. Decrypt file with AES key
        File decryptedFile = AESUtil.decryptFile(encryptedTempFilePath, aesKey);
        File decryptedTempFile = new File(outputDirPath + "/decrypted_" + metadata.getFilename());
        byte[] decryptedBytes =Files.readAllBytes(decryptedFile.toPath());
        Files.write(decryptedTempFile.toPath(),decryptedBytes);

        // 5. Recompute hash for integrity verification
        String metadataJson = MetaDataUtil.toJson(metadata);
        System.out.println("metadata json: "+ metadataJson);
        byte[] metadataBytes = metadataJson.getBytes();

        byte[] combined = new byte[encryptedFileBytes.length + metadataBytes.length];
        System.arraycopy(encryptedFileBytes, 0, combined, 0, encryptedFileBytes.length);
        System.arraycopy(metadataBytes, 0, combined, encryptedFileBytes.length, metadataBytes.length);

        byte[] computedHash = HashUtil.hashBytes(combined);

        // 6. Verify hash integrity
        boolean isHashEqual = java.util.Arrays.equals(receivedHash, computedHash);

        // 7. Verify signature with sender’s public key
        boolean isSignatureValid = HashUtil.verifySignature(receivedHash, receivedSignature, senderPublicKey);

        // 8. Print verification status (or return it if needed)
        System.out.println("Hash Integrity Match: " + isHashEqual);
        System.out.println("Signature Valid: " + isSignatureValid);

        return decryptedFile;
    }

}
