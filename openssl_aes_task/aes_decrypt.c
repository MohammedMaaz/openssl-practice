#include <openssl/conf.h>
#include <openssl/evp.h>
#include "./utils.h"

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleOpenSSLErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleOpenSSLErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleOpenSSLErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleOpenSSLErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/*
    Receives 2 arguments:
    arg1 (optional): filepath of the encrypted binary file, fallbacks to encrypted.dat
    arg2 (optional): filepath of the AES key binary file, fallbacks to aes_key.dat
*/
int main(int argc, char* argv[]) {
    char* cipherTextFileName = (argc == 1? "encrypted.dat" : argv[1]);
    FILE* cipherFile = fopen(cipherTextFileName, "rb");
    if(!cipherFile) {
        fclose(cipherFile);
        printf("Can't open file:'%s'!\nExiting...\n", cipherTextFileName);
        return 0;
    }

    int cipherTextLen = getFileSize(cipherFile);
    char cipherText[cipherTextLen];
    fread(cipherText, cipherTextLen, 1, cipherFile);
    fclose(cipherFile);


    char* keyFile = argc > 2 ? argv[2] : "aes_key.dat";
    char key[33];

    if(!getAESKey(keyFile, key, sizeof(key))) {
        printf("Can't open file:'%s'!\nExiting...\n", keyFile);
        return 0;
    } 

    char* iv = "0123456789012345";
    char plainText[cipherTextLen];

    int plainTextLen = decrypt(cipherText, cipherTextLen, key, iv, plainText);
    plainText[plainTextLen] = '\0';

    printf("Cipher Text DUMP:\n");
    BIO_dump_fp (stdout, (const char *)cipherText, cipherTextLen);

    char sha256[65];
    getSHA256(plainText, sha256);
    printf("\nSHA256 of plain text:\n%s\n", sha256);

    printf("\nDecrypted Text:\n%s\n", plainText);

    return 0;
}