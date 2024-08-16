#include <iostream>
#include <memory>
#include <vector>
#include <openssl/pem.h>
#include <openssl/err.h>

class Base64 {
private:
    //  Auxiliary function for creating and configuring BIO
    static BIO* create_base64_bio(BIO* bio) {
        BIO* b64 = BIO_new(BIO_f_base64());
        if (b64 == nullptr) {
            throw std::runtime_error("Failed to create base64 BIO");
        }
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines
        return bio;
    }

public:
    static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
        BIO* bio = BIO_new(BIO_s_mem());
        bio = create_base64_bio(bio);

        if (BIO_write(bio, bytes_to_encode, in_len) <= 0) {
            BIO_free_all(bio);
            throw std::runtime_error("Failed to write data to BIO");
        }
        BIO_flush(bio);

        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        return std::string(bufferPtr->data, bufferPtr->length);
    }

    static std::string base64_decode(std::string_view encoded_string) {
        BIO* bio = BIO_new_mem_buf(encoded_string.data(), encoded_string.size());
        bio = create_base64_bio(bio);

        std::vector<char> buffer(encoded_string.size());
        int decoded_length = BIO_read(bio, buffer.data(), buffer.size());
        BIO_free_all(bio);

        if (decoded_length < 0) {
            throw std::runtime_error("Failed to decode base64 string");
        }

        return std::string(buffer.data(), decoded_length);
    }
};


class RSA_Sample {
public:
    static std::pair<std::unique_ptr<RSA, decltype(&RSA_free)>, std::unique_ptr<RSA, decltype(&RSA_free)>> generateRSAKeys() {
        std::unique_ptr<RSA, decltype(&RSA_free)> privateKey(RSA_generate_key(4096, RSA_F4, nullptr, nullptr), RSA_free);
        if (!privateKey) {
            throw std::runtime_error("Failed to generate RSA private key");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        if (PEM_write_bio_RSAPublicKey(bio, privateKey.get()) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write public key to BIO");
        }

        std::unique_ptr<RSA, decltype(&RSA_free)> publicKey(PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr), RSA_free);
        BIO_free_all(bio);

        if (!publicKey) {
            throw std::runtime_error("Failed to read public key from BIO");
        }

        return { std::move(publicKey), std::move(privateKey) };
    }

    static std::string encryptMessage(const std::string& message, RSA* publicKey) {
        int rsaLen = RSA_size(publicKey);
        std::vector<unsigned char> encrypted(rsaLen);

        int result = RSA_public_encrypt(message.size(), reinterpret_cast<const unsigned char*>(message.c_str()), encrypted.data(), publicKey, RSA_PKCS1_PADDING); // Using Padding 
        if (result == -1) {
            ERR_print_errors_fp(stderr);
            return "";
        }

        return Base64::base64_encode(encrypted.data(), result);
    }

    static std::string decryptMessage(const std::string& encryptedMessage, RSA* privateKey) {
        std::string decodedMessage = Base64::base64_decode(encryptedMessage);
        int rsaLen = RSA_size(privateKey);
        std::vector<unsigned char> decrypted(rsaLen);

        int result = RSA_private_decrypt(decodedMessage.size(), reinterpret_cast<const unsigned char*>(decodedMessage.c_str()), decrypted.data(), privateKey, RSA_PKCS1_PADDING); // Using Padding
        if (result == -1) {
            ERR_print_errors_fp(stderr);
            return "";
        }

        return std::string(reinterpret_cast<char*>(decrypted.data()), result);
    }
};


int main() {
    try {
        auto [publicKey, privateKey] = RSA_Sample::generateRSAKeys();

        std::string message = "Hello, RSA!";
        std::string encryptedMessage = RSA_Sample::encryptMessage(message, publicKey.get());
        std::cout << "Encrypted: " << encryptedMessage << std::endl;

        std::string decryptedMessage = RSA_Sample::decryptMessage(encryptedMessage, privateKey.get());
        std::cout << "Decrypted: " << decryptedMessage << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
