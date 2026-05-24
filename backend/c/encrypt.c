/*
 * CyberVault Security Platform - AES-256 Encryption Module
 * Modern OpenSSL 3.0+ EVP API Implementation
 * Industry-standard cryptographic operations for file encryption
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define IV_SIZE 16
#define BUFFER_SIZE 4096

// Error handling function
void handle_openssl_error(void) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Secure key derivation from password
void derive_key(const char* password, unsigned char* key, unsigned char* salt) {
    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, 16,  // Salt size
                          10000,     // Iterations
                          EVP_sha256(),
                          AES_KEY_SIZE, key) != 1) {
        handle_openssl_error();
    }
}

void encrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");

    if (!in) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        exit(EXIT_FAILURE);
    }
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        exit(EXIT_FAILURE);
    }

    // Generate random salt and IV
    unsigned char salt[16], iv[IV_SIZE], key[AES_KEY_SIZE];
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, IV_SIZE) != 1) {
        handle_openssl_error();
    }

    // Derive key from password
    derive_key(password, key, salt);

    // Write salt and IV to file (needed for decryption)
    fwrite(salt, 1, sizeof(salt), out);
    fwrite(iv, 1, IV_SIZE, out);

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_openssl_error();
    }

    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inlen, outlen;

    // Encrypt file in chunks
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            handle_openssl_error();
        }
        fwrite(outbuf, 1, outlen, out);
    }

    // Finalize encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        handle_openssl_error();
    }
    fwrite(outbuf, 1, outlen, out);

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    // Clear sensitive data
    OPENSSL_cleanse(key, AES_KEY_SIZE);
    OPENSSL_cleanse(iv, IV_SIZE);
}

void decrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");

    if (!in) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        exit(EXIT_FAILURE);
    }
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        exit(EXIT_FAILURE);
    }

    // Read salt and IV from file
    unsigned char salt[16], iv[IV_SIZE], key[AES_KEY_SIZE];
    if (fread(salt, 1, sizeof(salt), in) != sizeof(salt) ||
        fread(iv, 1, IV_SIZE, in) != IV_SIZE) {
        fprintf(stderr, "Error: Invalid encrypted file format\n");
        fclose(in);
        fclose(out);
        exit(EXIT_FAILURE);
    }

    // Derive key from password
    derive_key(password, key, salt);

    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_openssl_error();
    }

    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inlen, outlen;

    // Decrypt file in chunks
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            handle_openssl_error();
        }
        fwrite(outbuf, 1, outlen, out);
    }

    // Finalize decryption (handle padding)
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Error: Decryption failed - invalid key or corrupted file\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        // Clear sensitive data
        OPENSSL_cleanse(key, AES_KEY_SIZE);
        exit(EXIT_FAILURE);
    }
    fwrite(outbuf, 1, outlen, out);

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    // Clear sensitive data
    OPENSSL_cleanse(key, AES_KEY_SIZE);
    OPENSSL_cleanse(iv, IV_SIZE);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("CyberVault AES-256 Encryption Tool v2.0\n");
        printf("Usage: %s <encrypt/decrypt> <input_file> <output_file> <password>\n", argv[0]);
        printf("\nSecurity Features:\n");
        printf("  - AES-256-CBC encryption\n");
        printf("  - PBKDF2 key derivation (10,000 iterations)\n");
        printf("  - Random salt and IV generation\n");
        printf("  - Secure memory clearing\n");
        return EXIT_FAILURE;
    }

    // Validate file paths
    if (strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        fprintf(stderr, "Error: File paths cannot be empty\n");
        return EXIT_FAILURE;
    }

    // Validate password length
    if (strlen(argv[4]) < 8) {
        fprintf(stderr, "Error: Password must be at least 8 characters\n");
        return EXIT_FAILURE;
    }

    // Initialize OpenSSL
    if (!EVP_add_cipher(EVP_aes_256_cbc())) {
        handle_openssl_error();
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        printf("Encrypting '%s' -> '%s'\n", argv[2], argv[3]);
        encrypt_file(argv[2], argv[3], argv[4]);
        printf("✓ Encryption completed successfully\n");
    } else if (strcmp(argv[1], "decrypt") == 0) {
        printf("Decrypting '%s' -> '%s'\n", argv[2], argv[3]);
        decrypt_file(argv[2], argv[3], argv[4]);
        printf("✓ Decryption completed successfully\n");
    } else {
        fprintf(stderr, "Error: Invalid operation '%s'. Use 'encrypt' or 'decrypt'\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
