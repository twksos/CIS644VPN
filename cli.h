#ifndef KEY_EXCHANGE_CLIENT_H_
#define KEY_EXCHANGE_CLIENT_H_

int init_client(char *addr, int port, char * username, char * password,
                        int* sd, SSL_CTX** ctx, SSL** ssl);

int close_client(int sd, SSL_CTX* ctx, SSL* ssl);

int client_send(char * msg, size_t msg_len, SSL* ssl);
char * listen_server(SSL* ssl);

#endif
