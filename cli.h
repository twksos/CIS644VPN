#ifndef KEY_EXCHANGE_CLIENT_H_
#define KEY_EXCHANGE_CLIENT_H_

int init_client(char * addr, int port, char * info,
                        int sd, SSL_CTX* ctx, SSL* ssl);

int close_client(int sd, SSL_CTX* ctx, SSL* ssl);

int listen_server(char * cmd, SSL* ssl);

#endif
