#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "util.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./cert_server/"
/* Make these what you want for cert & key files */
#define SCERTF HOME "server.crt"
#define SKEYF  HOME "server.key"

#ifndef CACERT
#define CACERT "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#endif

int init_server(char * cmd, int cmd_len, int port,
                int sd, SSL_CTX* ctx, SSL* ssl)
{
  int err;
  int listen_sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  size_t client_len;
  X509*    client_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;
  
  /* SSL preliminaries. We keep the certificate and key with the context. */

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
  
  if (SSL_CTX_use_certificate_file(ctx, SCERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, SKEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }

  printf("listen to port: %d\n", port);
  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
  
  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (port);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
       sizeof (sa_serv));                   CHK_ERR(err, "bind");
       
  /* Receive a TCP connection. */
       
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  CHK_ERR(sd, "accept");
  close (listen_sd);

  printf ("Connection from %lx, port %x\n",
    sa_cli.sin_addr.s_addr, sa_cli.sin_port);
  
  /* ----------------------------------------------- */
  /* TCP connection is ready. Do server side SSL. */

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  SSL_set_fd (ssl, sd);
  err = SSL_accept (ssl);                        CHK_SSL(err);
  
  /* Get the cipher - opt */
  
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get client's certificate (note: beware of dynamic allocation) - opt */

  client_cert = SSL_get_peer_certificate (ssl);
  if (client_cert != NULL) {
    printf ("Client certificate:\n");
    
    str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t subject: %s\n", str);
    if(strcmp(str, "/C=US/ST=New-York/O=GuangchengWei/CN=VPNCLIENT") == 0){
      printf("subject correct\n");
    } else {
      printf("subject incorrect\n");
      return -1;
    }
    OPENSSL_free (str);
    
    str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t issuer: %s\n", str);
    if(strcmp(str, "/C=US/ST=New-York/L=Syracuse/O=GuangchengWei/CN=VPNCA") == 0){
      printf("issuer correct\n");
    } else {
      printf("issuer incorrect\n");
      return -1;
    }
    OPENSSL_free (str);
    
    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */

    err = SSL_write (ssl, cmd, cmd_len);  CHK_SSL(err);
    err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
    buf[err] = '\0';


    printf ("Got challenge %d chars:\n", err);
    hex(buf, err);
    
    if(memcmp(cmd, buf, err) == 0){
      printf ("Key exchange success\n");
    } else {
      printf ("Key exchange fail\n");
      return -1;
    }
    
    X509_free (client_cert);
  } else
    printf ("Client does not have certificate.\n");
}

int close_server(int sd, SSL_CTX* ctx, SSL* ssl){
  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

int send_from_server(char * cmd, int cmd_len, SSL* ssl)
{
  int err;
  char     buf [4096];

  /* DATA EXCHANGE - Receive message and send reply. */
  err = SSL_write (ssl, cmd, cmd_len);  CHK_SSL(err);
  return 0;
}

#ifdef DEBUG_PKI
int main(){
  key_exchange_server("12345678", 1111);
}
#endif
/* EOF - serv.cpp */
