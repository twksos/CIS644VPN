#include <stdio.h>
#include <stdlib.h>

#include <openssl/conf.h> 
#include <openssl/evp.h>
#include <openssl/err.h>

#include "util.h"

char * do_digest(EVP_MD_CTX * ctx, char *message, int message_len) {
	char * md_value = malloc(EVP_MAX_MD_SIZE);
	int md_len, i;
	unsigned long digest;

	// set digest type and impl
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, message, message_len);
	EVP_DigestFinal_ex(ctx, md_value, &md_len);

	return str_to_hex(md_value, md_len);
}

char password_folder[] = "./passwords/";
char salt_folder[] = "./salts/";

int verify_password(char * username, char * password) {
	EVP_MD_CTX * ctx;
	ctx = (EVP_MD_CTX *) EVP_MD_CTX_create();

	char * password_path = malloc(strlen(password_folder) + strlen(username) + 1);
	strcpy(password_path, password_folder);
	strcat(password_path, username);

	FILE * password_file = fopen(password_path, "rb");

	char stored_password[64];
	fscanf(password_file, "%s", stored_password);

#ifdef DEBUG
	printf("pw: %s\n", stored_password);
#endif

	char * salt_path = malloc(strlen(salt_folder) + strlen(username) + 1);
	strcpy(salt_path, salt_folder);
	strcat(salt_path, username);

	FILE * salt_file = fopen(salt_path, "rb");
	char stored_salt[64];
	fscanf(salt_file, "%s", stored_salt);

#ifdef DEBUG
	printf("sa: %s\n", stored_salt);
#endif

	int message_len = strlen(stored_salt) + strlen(password);
	char * message = malloc(message_len + 1);
	strcpy(message, stored_salt);
	strcat(message, password);

	char * verify_digist = do_digest(ctx, message, message_len);

#ifdef DEBUG
	printf("rs: %s\n", verify_digist);
#endif

	int result = memcmp(verify_digist, stored_password, sizeof(stored_password));
	EVP_MD_CTX_destroy(ctx);
	EVP_cleanup();
	return result;
}

//int main(){
//	int done = verify_password("user1", "password");
//	printf("cmp: %d\n",done);
//}