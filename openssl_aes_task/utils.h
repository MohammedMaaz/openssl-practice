#ifndef AES_UTILS
#define AES_UTILS

#include <stdlib.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>

void genRandBytes(char* buffer, int buffer_len) {
    srand(time(NULL));
    for(int i=0; i<buffer_len - 1; ++i) {
        buffer[i] = (unsigned char)rand();
    }
    buffer[buffer_len - 1] = '\0';
}

void handleOpenSSLErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void writeToBinFile(char* fileName, char* buffer, int buffer_len){
    FILE* fptr = fopen(fileName, "wb");
    fwrite(buffer, buffer_len, 1, fptr);
    fclose(fptr);
}

int getFileSize(FILE* fptr) {
    fseek(fptr, 0, SEEK_END);
    int size = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);
    return size;
}

int getAESKey(char* fileName, char* key, int key_len) {
    FILE* fptr = fopen(fileName, "rb");
    if(!fptr) {
        fclose(fptr);
        return 0;
    }

    fread(key, key_len, 1, fptr);
    fclose(fptr);
    return 1;
}

void getSHA256(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

#endif