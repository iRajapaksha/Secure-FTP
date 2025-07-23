#  Secure File Transfer Protocol

A secure file transfer desktop application built in Java using Swing UI. It ensures **confidentiality**, **integrity**, **authenticity**, and **replay protection** during file transmission using **RSA** and **AES** cryptography.

## Features
- AES symmetric encryption for fast and secure file encryption

- RSA public-key cryptography for secure key exchange

- Digital signatures to verify sender authenticity

- Hashing (SHA-256) to ensure file integrity

- Replay attack detection using timestamps

- Username/password authentication before transmission

- GUI built using Java Swing

---
## Project Structure

```
.
├── sender/             # Sender-side application (Server)
├── receiver/           # Receiver-side application (Client)
├── Util/               # Shared utility classes (Payload handling, encryption)
├── security/           # Crypto helper classes (RSA, AES)
└── README.md
```
---
## Prerequisites
- Java JDK 17 or higher
- Maven (optional, for managing dependencies)
- Gson library (used for JSON serialization)

## Clone the repository
```bash
git clone https://github.com/iRajapaksha/Secure-FTP.git
cd secure-FTP
```

## Usage Instructions
1. Run the Sender app first. Click Start Server.

2. Run the Receiver app. Generate RSA keys and connect to the server.

3. When prompted, enter username/password (e.g., abc123 / pass123).

4. On successful authentication:

- The receiver's public key is transferred.

- Sender selects a file, generates AES key + RSA keys, and encrypts the payload.

- Save the payload JSON.

5. Click Send Encrypted File to send it to the receiver.

6. The receiver can now:

- Decrypt Payload

- Verify Integrity

- Verify Sender

- Check Replay Safety

---

## Default Credentials

Modify allowedUsers in **SenderApp.java** to update authentication logic.
```bash
Map<String, String> allowedUsers = Map.of(
    "abc123", "pass123"
);
```

## Security Notes
- Uses RSA-2048 for asymmetric encryption.

- Uses AES-128 for symmetric encryption.

- Uses SHA-256 for hashing.

- Ensure secure key management in production.

- In real deployments, consider using TLS and secure password storage.

## License

MIT License. Feel free to modify and enhance for educational or personal use.

## Credits

Created by [**Ishara Rajapaksha**](https://github.com/iRajapaksha) as part of a secure file transfer project using Java and Swing.

