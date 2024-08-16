#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Base64 Encoder and Decoder
class Base64 {
public:
    static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines

        BIO_write(bio, bytes_to_encode, in_len);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        return std::string(bufferPtr->data, bufferPtr->length);
    }

    static std::string base64_decode(const std::string &encoded_string) {
        BIO *bio, *b64;
        char buffer[512]; // Buffer have fixed size
        int decoded_length;

        bio = BIO_new_mem_buf(encoded_string.data(), encoded_string.size());
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines

        decoded_length = BIO_read(bio, buffer, encoded_string.size());
        BIO_free_all(bio);

        return std::string(buffer, decoded_length);
    }
};

// RSA Generation, Encryption and Decryption
class RSA_Sample {
public:
    static void generateRSAKeys(RSA **publicKey, RSA **privateKey) {
        *privateKey = RSA_generate_key(2048, RSA_F4, nullptr, nullptr); // Key size!
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(bio, *privateKey);
        
        // Read the public key
        *publicKey = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    }

    static std::string encryptMessage(const std::string &message, RSA *publicKey) {
        int rsaLen = RSA_size(publicKey);
        unsigned char *encrypted = new unsigned char[rsaLen];

        int result = RSA_public_encrypt(message.size(), (unsigned char*)message.c_str(), encrypted, publicKey, RSA_PKCS1_PADDING); // We use padding, also can be used with RSA_NO_PADDING
        if (result == -1) {
            ERR_print_errors_fp(stderr);
            delete[] encrypted;
            return "";
        }

        std::string encryptedMessage = Base64::base64_encode(encrypted, result);
        delete[] encrypted;
        return encryptedMessage;
    }

    static std::string decryptMessage(const std::string &encryptedMessage, RSA *privateKey) {
        std::string decodedMessage = Base64::base64_decode(encryptedMessage);
        int rsaLen = RSA_size(privateKey);
        unsigned char *decrypted = new unsigned char[rsaLen];

        int result = RSA_private_decrypt(decodedMessage.size(), (unsigned char*)decodedMessage.c_str(), decrypted, privateKey, RSA_PKCS1_PADDING);
        if (result == -1) {
            ERR_print_errors_fp(stderr);
            delete[] decrypted;
            return "";
        }

        std::string decryptedMessage(reinterpret_cast<char*>(decrypted), result);
        delete[] decrypted;
        return decryptedMessage;
    }
};


int main() {
    // Generate RSA keys
    RSA *publicKey = nullptr;
    RSA *privateKey = nullptr;
    RSA_Sample::generateRSAKeys(&publicKey, &privateKey);

    // Original message
    std::string originalMessage = "Hello, RSA Encryption!";
    std::cout << "Original Message: " << originalMessage << std::endl;

    // Encrypt the message
    std::string encryptedMessage = RSA_Sample::encryptMessage(originalMessage, publicKey);
    std::cout << "Encrypted Message (Base64): " << encryptedMessage << std::endl;

    // Decrypt the message
    std::string decryptedMessage = RSA_Sample::decryptMessage(encryptedMessage, privateKey);
    std::cout << "Decrypted Message: " << decryptedMessage << std::endl;

    // Clean up
    RSA_free(publicKey);
    RSA_free(privateKey);

    return 0;
}
