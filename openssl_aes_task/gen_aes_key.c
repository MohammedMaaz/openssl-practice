#include <stdio.h>
#include <stdlib.h>
#include "./utils.h"

void genAESKey(char* key, int key_len) {
    genRandBytes(key, key_len);
}

/*
    Receives 1 argument:
    arg1 (optional): length of the AES key to generate (8 <= len <= 32), fallbacks to 32
*/
int main(int argc, char* argv[]) {
    const int len = (argc == 1? 32 : atoi(argv[1])) + 1;
    if(len < 9 || len > 33) {
        printf("Key size can't be greater than 32 bytes!\nExiting...\n");
        return 0;
    }

    char key[len];
    genAESKey(key, len);
    writeToBinFile("aes_key.dat", key, len);

    return 0;
}