#ifndef KEY_EXCHANGE_SERVER_H_
#define KEY_EXCHANGE_SERVER_H_

int init_server(int port, int *sd, SSL_CTX** ctx, SSL** ssl);

int close_server(int sd, SSL_CTX* ctx, SSL* ssl);

int server_send(char *cmd, int cmd_len, SSL *ssl);
char * listen_client(SSL *ssl);
#endif
