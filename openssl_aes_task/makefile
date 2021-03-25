build: gen_aes_key.c aes_encrypt.c aes_decrypt.c utils.h
	mkdir -p bin
	gcc -o bin/gen_aes_key gen_aes_key.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto
	gcc -o bin/aes_encrypt aes_encrypt.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto
	gcc -o bin/aes_decrypt aes_decrypt.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto