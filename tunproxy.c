/*
 * tunproxy.c --- small demo program for tunneling over UDP with tun/tap
 *
 * Copyright (C) 2003  Philippe Biondi <phil@secdev.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "util.h"
#include "crypt.h"
#include "srv.h"
#include "cli.h"

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)


char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";

void usage()
{
	fprintf(stderr, "Usage: tunproxy [-s port|-c targetip:port] [-e]\n");
	exit(0);
}

struct communicate {
    int instruction;
    char key [16];
    char iv [16];
    long serial;
};

void print_commands();
void new_key_iv(struct communicate *state);
char* getuser();
void sync_tcp_udp(int in,int out, struct communicate* state, size_t state_size);

int main(int argc, char *argv[])
{
	struct sockaddr_in sin, sout, from;
	struct ifreq ifr;
	int fd, s, fromlen, soutlen, port, PORT, l, enclen, maci, md_len, total_len;
	int mac_valid;
	char c, *p, *ip;
	char buf[2000];
	char encbuf[2000 + EVP_MAX_BLOCK_LENGTH + 4 + EVP_MAX_MD_SIZE];
	char md_cmp[EVP_MAX_MD_SIZE];

	char * cmd;
	char key[16];
	char iv[16];

	fd_set fdset;
    int tcp_port;
	

	int MODE = 0, TUNMODE = IFF_TUN;

	while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
		switch (c) {
		case 'h':
			usage();
		case 's':
			MODE = 1;
            tcp_port =atoi(optarg);
            PORT = tcp_port + 1;
			break;
		case 'c':
			MODE = 2;
			p = memchr(optarg,':',16);
			if (!p) ERROR("invalid argument : [%s]\n",optarg);
			*p = 0;
			ip = optarg;
			tcp_port = atoi(p+1);
            port = tcp_port +1;
			PORT = 0;
			break;
		case 'e':
			TUNMODE = IFF_TAP;
			break;
		default:
			usage();
		}
	}
	if (MODE == 0) usage();

    SSL_CTX* ssl_ctx;
    SSL*     ssl;
    int ssl_sd;

    size_t state_size = sizeof(struct communicate);
    struct communicate *state = malloc(state_size);
    size_t serial_size = sizeof(long);
	memset(state, 0, state_size);

    int pipe_ctd[2];
    int pipe_dtc[2];
    pipe2(pipe_ctd,O_NONBLOCK);
    pipe2(pipe_dtc,O_NONBLOCK);

    write(pipe_ctd[1], state, state_size);
    write(pipe_dtc[1], state, state_size);

	int pid = fork();
	if(pid > 0){
		close(pipe_ctd[1]);
		close(pipe_dtc[0]);

		if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = TUNMODE;
		strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
		if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");
#ifdef DEBUG
		printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
#endif
		s = socket(PF_INET, SOCK_DGRAM, 0);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		sin.sin_port = htons(PORT);
		if ( bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");

		fromlen = sizeof(from);

		if (MODE == 1) {
			while(1) {
				l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
				if (l < 0) PERROR("recvfrom");
				if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) == 0)
					break;
				printf("Bad magic word from %s:%i\n",
				       (char *)inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
			}
			l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
			if (l < 0) PERROR("sendto");
		} else {
			from.sin_family = AF_INET;
			from.sin_port = htons(port);
			inet_aton(ip, &from.sin_addr);
			l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, sizeof(from));
			if (l < 0) PERROR("sendto");
			l = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
			if (l < 0) PERROR("recvfrom");
			if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0))
				ERROR("Bad magic word for peer\n");
		}

#ifdef DEBUG
		printf("Connection with %s:%i established\n", 
		       (char *)inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
#endif

        while (state->instruction == 0)read(pipe_ctd[0], state, state_size);
#ifdef DEBUG
        printf("key and iv set %ld\n", state->serial);
#endif
		while (1) {
			read(pipe_ctd[0], state, state_size);
            if(state->instruction != 0){
                if(state->instruction == 2) {
                    exit(0);
                } else {
                    state->instruction = 0;
                }
				write(pipe_dtc[1], state, state_size);
			}
#ifdef DEBUG
            printf("sync serial: %ld\n", state->serial);
#endif

			FD_ZERO(&fdset);
			FD_SET(fd, &fdset);
			FD_SET(s, &fdset);
			if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
			if (FD_ISSET(fd, &fdset)) {
				l = read(fd, buf, sizeof(buf));
				if (l < 0) PERROR("read");

				// encrypt before send
				enclen = do_crypt(buf, l, encbuf, (unsigned char *) state->key, (unsigned char *) state->iv, 1);
				#ifdef DEBUG_MODE
				printf("enc %d to %d bytes\n", l, enclen);
				hex(encbuf, enclen);
                #endif
                state->serial++;
                memcpy(encbuf+enclen, &state->serial, serial_size);
#ifdef DEBUG
                printf("set serial: %ld\n", state->serial);
                hex(encbuf+enclen, 4);
                hex((const char *) &state->serial, 4);
#endif
				//HMAC generation
				for (maci = 0; maci < EVP_MAX_MD_SIZE; maci ++) {
					encbuf[enclen + serial_size + maci] = '\0';
				}
				HMAC(EVP_sha256(), state->key, sizeof(state->key), encbuf, enclen+serial_size, encbuf + serial_size + enclen, &md_len);
				total_len = enclen + serial_size + EVP_MAX_MD_SIZE;

				#ifdef DEBUG_MAC_MODE
				printf("enclen:%d  total_len:%d\n", enclen, total_len);
				hex(encbuf + enclen, EVP_MAX_MD_SIZE);
				#endif

				if (sendto(s, encbuf, total_len, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
			} else {
				total_len = recvfrom(s, encbuf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
#ifdef DEBUG
				if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))

					printf("Got packet from  %s:%i instead of %s:%i\n",
					       (char *)inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
					       (char *)inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
#endif

				//HMAC validation
				enclen = total_len - serial_size - EVP_MAX_MD_SIZE;

				for (maci = 0; maci < EVP_MAX_MD_SIZE; maci ++) {
					md_cmp[maci] = '\0';
				}
				HMAC(EVP_sha256(), state->key, sizeof(state->key), encbuf, enclen + serial_size, md_cmp, &md_len);

				#ifdef DEBUG_MAC_MODE
				printf("enclen:%d  total_len:%d\n", enclen, total_len);
				hex(md_cmp, EVP_MAX_MD_SIZE);
                #endif

				mac_valid = memcmp(encbuf + enclen + serial_size, md_cmp, EVP_MAX_MD_SIZE);

				if(mac_valid == 0){
                    long serial;
                    memcpy(&serial, encbuf + enclen , serial_size);
#ifdef DEBUG
                    printf("get serial: %ld\n", serial);
                    hex(encbuf+enclen, 4);
                    hex((const char *) &serial, 4);
                    printf("hav serial: %ld\n", state->serial);
#endif
                    if(state->serial >= serial) {
                        printf("invalid serial\n");
                        continue;
                    } else {
                        state->serial = serial;
                    }
					// decrypt before write to net
					#ifdef DEBUG_MODE
					printf("hmac valid\n");
					hex(encbuf, enclen);
                    #endif
					l = do_crypt(encbuf, enclen, buf, (unsigned char *) state->key, (unsigned char *) state->iv, 0);
					#ifdef DEBUG_MODE
					printf("dec %d to %d bytes\n", enclen, l);
					#endif

					if (write(fd, buf, l) < 0) PERROR("write");
				} else {
					printf("invalid hmac\n");
				}
			}
		}
	} else if (pid == 0) {
        close(pipe_ctd[0]);
        close(pipe_dtc[1]);
        if (MODE == 1) {
            int server_started = init_server(tcp_port, &ssl_sd, &ssl_ctx, &ssl);
            if (server_started != 0) {
                printf("Server not started");
            }
            while (state->instruction != 2) {
                //server receive command and write
                char *ins = listen_client(ssl);
                memcpy(state, ins, state_size);

                if(state->instruction != 0) {
#ifdef DEBUG
                    printf("new key:");
                    hex(state->key, 16);
#endif
                    //pass to udp
                    sync_tcp_udp(pipe_ctd[1], pipe_dtc[0], state, state_size);
                }
            }

            close_server(ssl_sd, ssl_ctx, ssl);
        } else {
            char *username = getuser();
            char *password = getpass("Password:\n");
            init_client(ip, tcp_port, username, password, &ssl_sd, &ssl_ctx, &ssl);
            new_key_iv(state);
#ifdef DEBUG
            printf("new key:");
            hex(state->key, 16);
#endif
            client_send((char *) state, state_size, ssl);
            sync_tcp_udp(pipe_ctd[1], pipe_dtc[0], state, state_size);

            while (state->instruction != 2) {
                print_commands();
                scanf("%d", &state->instruction);

#ifdef DEBUG
                printf("receive %d", state->instruction);
#endif

                //client compose command and send to server
                if (state->instruction == 1) {
                    new_key_iv(state);
                }

                client_send((char *) state, state_size, ssl);

                //pass to udp
                sync_tcp_udp(pipe_ctd[1], pipe_dtc[0], state, state_size);
            }

            close_client(ssl_sd, ssl_ctx, ssl);
		}
	} else {
		printf("fork error!!");
	}
}

void new_key_iv(struct communicate *state){
    int randomData = open("/dev/urandom", O_RDONLY);
    state->instruction = 1;
    read(randomData, state->key, sizeof(state->key));
    read(randomData, state->iv, sizeof(state->iv));
    read(randomData, &state->serial, sizeof(state->serial));
    state->serial = state->serial >> 2;
}

char* getuser(){
    char scan_buf[1024];
    size_t username_len;
    char * username;
    printf("Username:\n");
    scanf("%s", scan_buf);
    username_len = strlen(scan_buf);
    username = malloc(username_len);
    memcpy(username, scan_buf, username_len);
    return username;
}

void sync_tcp_udp(int in,int out, struct communicate* state, size_t state_size) {
    write(in, state, state_size);
    if (state->instruction == 2) { exit(0); }
    while (state->instruction != 0) {
        read(out, state, state_size);
    }
    write(in, state, state_size);
}

void print_commands() {
	printf("\nCommands:\n");
	printf("1: new key and iv\n");
	printf("2: quit\n");
}

	
