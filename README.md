### Overview

This code defines two main classes: `Base64` and `RSA_Sample`. The `Base64` class provides methods for encoding and decoding data in Base64 format, while the `RSA_Sample` class handles RSA key generation, encryption, and decryption of messages.

### Base64 Class

- **Methods**:
  - `base64_encode`: Takes a byte array and its length as input, encodes it to a Base64 string without newlines, and returns the encoded string.
  - `base64_decode`: Accepts a Base64 encoded string, decodes it back to its original byte form, and returns the decoded string.

### RSA_Sample Class

- **Methods**:
  - `generateRSAKeys`: Generates a pair of RSA keys (public and private) with a key size of 2048 bits. The public key is extracted from the private key and stored in memory.
  - `encryptMessage`: Encrypts a given plaintext message using the public key and returns the encrypted message encoded in Base64 format.
  - `decryptMessage`: Takes a Base64 encoded encrypted message, decodes it, and decrypts it using the private key, returning the original plaintext message.

### Main Functionality

In the `main` function:

1. RSA keys are generated.
2. An original message ("Hello, RSA Encryption!") is defined and displayed.
3. The message is encrypted using the public key, and the encrypted message is displayed in Base64 format.
4. The encrypted message is decrypted using the private key, and the decrypted message is displayed.
5. Finally, the allocated RSA keys are freed to prevent memory leaks.

### Compilation Process for Linux

To compile and run this code on a Linux system, follow these steps:

1. **Install OpenSSL Development Libraries**:
   Make sure you have the OpenSSL library installed. You can install it using your package manager. For example, on Ubuntu, you can run:
   ```bash
   sudo apt-get update
   sudo apt-get install libssl-dev
   ```

2. **Create a Source File**:
   Save the provided code in a file named `rsa_example.cpp`.

3. **Compile the Code**:
   Use the `g++` compiler to compile the code, linking it with the OpenSSL libraries. Run the following command in your terminal:
   ```bash
   g++ -O2 rsa_example.cpp -o rsa_example -lssl -lcrypto
   ```

4. **Run the Executable**:
   After successful compilation, run the program with:
   ```bash
   ./rsa_example
   ```

### Usage

This code serves as a basic demonstration of RSA encryption and decryption, showcasing how to securely encode messages using public key cryptography. It can be extended or integrated into larger applications (but I don't recommend) requiring secure data transmission.
