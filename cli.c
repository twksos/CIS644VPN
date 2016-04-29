#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

#include "util.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./cert_client/"
/* Make these what you want for cert & key files */
#define CCERTF HOME "client.crt"
#define CKEYF  HOME "client.key"

#ifndef CACERT
#define CACERT "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err, s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#endif

int reply_challenge(SSL* ssl){
    int err;
    char buf[4096];
    err = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(err);

    printf("Got challenge %d chars:\n", err);
    hex(buf, err);

    err = SSL_write(ssl, buf, err);
    CHK_SSL(err);
}

int client_send(char * message, size_t message_len, SSL* ssl){
    int err;
    err = SSL_write(ssl, message, message_len);
    CHK_SSL(err);
}

int listen_server(char *cmd, SSL *ssl) {
    int err;
    char buf[4096];
    err = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(err);
    memcpy(cmd, buf, err);

    printf("client get cmd:\n");
    hex(cmd, err);
    return 0;
}

SSL_CTX *get_client_CTX() {
    SSL_CTX *ctx;
    const SSL_METHOD *meth;
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = SSLv23_client_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    return ctx;
}

int init_client(char *addr, int port, char * username, char * password,
                int* out_sd, SSL_CTX ** out_ctx, SSL **out_ssl) {
    int err;
    struct sockaddr_in sa;

    int sd;
    SSL_CTX* ctx;
    SSL* ssl;

    X509 *server_cert;
    char *str;
    char buf[4096];

    ctx = get_client_CTX();

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

    if (SSL_CTX_use_certificate_file(ctx, CCERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CKEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-3);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public key\n");
        exit(-4);
    }

    /* ----------------------------------------------- */
    /* Create a socket and connect to server using normal socket calls. */

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    memset (&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(addr);   /* Server IP */
    sa.sin_port = htons     (port);          /* Server Port number */

    err = connect(sd, (struct sockaddr *) &sa,
                  sizeof(sa));
    CHK_ERR(err, "connect");

    /* ----------------------------------------------- */
    /* Now we have TCP conncetion. Start SSL negotiation. */

    ssl = SSL_new(ctx);
    CHK_NULL(ssl);
    SSL_set_fd(ssl, sd);
    err = SSL_connect(ssl);
    CHK_SSL(err);

    /* Following two steps are optional and not required for
       data exchange to be successful. */

    /* Get the cipher - opt */

    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    /* Get server's certificate (note: beware of dynamic allocation) - opt */

    server_cert = SSL_get_peer_certificate(ssl);
    CHK_NULL(server_cert);
    printf("Server certificate:\n");

    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    if (strcmp(str, "/C=US/ST=New-York/O=GuangchengWei/CN=VPNSERVER") != 0) {
        printf("Server certification subject incorrect\n");
        return -1;
    }
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    if (strcmp(str, "/C=US/ST=New-York/L=Syracuse/O=GuangchengWei/CN=VPNCA") != 0) {
        printf("Server certification issuer incorrect\n");
        return -1;
    }

    OPENSSL_free(str);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */

    reply_challenge(ssl);
    client_send(username, strlen(username), ssl);
    client_send(password, strlen(password), ssl);

    X509_free(server_cert);

    *out_sd = sd;
    *out_ctx = ctx;
    *out_ssl = ssl;

    return 0;
}

int close_client(int sd, SSL_CTX *ctx, SSL *ssl) {
    SSL_shutdown(ssl);  /* send SSL/TLS close_notify */

    /* Clean up. */

    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

//int main(){
//    int sd;
//    SSL_CTX *ctx;
//    SSL *ssl;
//    init_client("127.0.0.1", 1111, "user1", "password", &sd, &ctx, &ssl);
//    close_client(sd, ctx, ssl);
//}

/* EOF - cli.cpp */
