#ifndef PASSWORD_H_
#define PASSWORD_H_

char * do_digest(EVP_MD_CTX * ctx, char *message, int message_len);
int verify_password(char * username, char * password);
#endif