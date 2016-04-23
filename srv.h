#ifndef KEY_EXCHANGE_SERVER_H_
#define KEY_EXCHANGE_SERVER_H_

int init_server(char * cmd, int cmd_len, int port,
                int* sd, SSL_CTX** ctx, SSL** ssl);

int close_server(int sd, SSL_CTX* ctx, SSL* ssl);

int send_from_server(char * cmd, int cmd_len, SSL* ssl);
#endif
