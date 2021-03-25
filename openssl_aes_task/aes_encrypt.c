#include <openssl/conf.h>
#include <openssl/evp.h>
#include "./utils.h"

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleOpenSSLErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleOpenSSLErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleOpenSSLErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleOpenSSLErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*
    Receives 2 arguments:
    arg1 (required): plain text/string to encrypt
    arg2 (optional): filepath of the AES key binary file, fallbacks to aes_key.dat
*/
int main(int argc, char* argv[]) {
    if(argc <= 1) {
        printf("Nothing to encrypt!\nExiting...\n");
        return 0;
    }

    char* plainText = argv[1];
    char* keyFile = argc > 2 ? argv[2] : "aes_key.dat";
    char key[33];

    if(!getAESKey(keyFile, key, sizeof(key))) {
        printf("Can't open file:'%s'!\nExiting...\n", keyFile);
        return 0;
    } 

    char* iv = "0123456789012345";
    int plaintTextLen = strlen(plainText);
    char cipherText[plaintTextLen * 2];

    int cipherTextLen = encrypt(plainText, plaintTextLen, key, iv, cipherText);
    writeToBinFile("encrypted.dat", cipherText, cipherTextLen);

    printf("Cipher Text DUMP:\n");
    BIO_dump_fp (stdout, (const char *)cipherText, cipherTextLen);

    char sha256[65];
    getSHA256(plainText, sha256);
    printf("\nSHA256 of plain text:\n%s\n", sha256);

    return 0;
}