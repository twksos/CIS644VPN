
#include <stdio.h>
#include <stdlib.h>

#include <openssl/conf.h> 
#include <openssl/evp.h>
#include <openssl/err.h>

int do_crypt(char *in, int inlen, char *out, unsigned char *key, int enc) { 
	//enc = 1 for encrypt
	//enc = 0 for decrypt
	int outlen, lastlen;
	EVP_CIPHER_CTX *ctx;

	unsigned char iv[16] = {0};


	#ifdef DEBUG
	printf("key is \n"); 
	hex(key, 16); 
	printf("IV is \n"); 
	hex(iv, 16);
	#endif
	
	ctx = EVP_CIPHER_CTX_new();
	/* Now we can set key and IV */ 
	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, enc);
	
	if(!EVP_CipherUpdate(ctx, out, &outlen, in, inlen)) {
	/* Error */ EVP_CIPHER_CTX_free(ctx); printf("update error\n"); return 0;
	}
	
	if(!EVP_CipherFinal_ex(ctx, out + outlen, &lastlen)) {
	/* Error */ EVP_CIPHER_CTX_free(ctx); printf("final error\n"); return 0;
	}
	
	outlen += lastlen; EVP_CIPHER_CTX_free(ctx);
	
	#ifdef DEBUG
	printf("outlen is %d\n", outlen);
	#endif
    
    return outlen;
}