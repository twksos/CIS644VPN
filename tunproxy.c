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
#include <openssl/conf.h> 
#include <openssl/evp.h> 
#include <openssl/err.h>

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

#define DEBUG_MODE

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";

void hex(const char *s, int bytes){
	int i;
	for(i=0;i<bytes;i++) 
		printf("%02x ", (unsigned char) *s++); 
	printf("\n"); 
}

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

void usage()
{
	fprintf(stderr, "Usage: tunproxy [-s port|-c targetip:port] [-e]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in sin, sout, from;
	struct ifreq ifr;
	int fd, s, fromlen, soutlen, port, PORT, l, enclen, maci, md_len, total_len;
	int mac_valid;
	char c, *p, *ip;
	char buf[2000];
	char encbuf[2000 + EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE];
	char md_cmp[EVP_MAX_MD_SIZE];

	char key[16] = "1234567890ABCDEF";

	fd_set fdset;
	
	

	int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;

	while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
		switch (c) {
		case 'h':
			usage();
		case 'd':
			DEBUG++;
			break;
		case 's':
			MODE = 1;
			PORT = atoi(optarg);
			break;
		case 'c':
			MODE = 2;
			p = memchr(optarg,':',16);
			if (!p) ERROR("invalid argument : [%s]\n",optarg);
			*p = 0;
			ip = optarg;
			port = atoi(p+1);
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

	if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = TUNMODE;
	strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");

	printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
	
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
			       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
		} 
		l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
		if (l < 0) PERROR("sendto");
	} else {
		from.sin_family = AF_INET;
		from.sin_port = htons(port);
		inet_aton(ip, &from.sin_addr);
		l =sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, sizeof(from));
		if (l < 0) PERROR("sendto");
		l = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
		if (l < 0) PERROR("recvfrom");
		if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0))
			ERROR("Bad magic word for peer\n");
	}
	printf("Connection with %s:%i established\n", 
	       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
	while (1) {
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s, &fdset);
		if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
		if (FD_ISSET(fd, &fdset)) {
			if (DEBUG) write(1,">", 1);
			l = read(fd, buf, sizeof(buf));
			if (l < 0) PERROR("read");

			// encrypt before send
			enclen = do_crypt(buf, l, encbuf, key, 1);
			#ifdef DEBUG_MODE
			printf("enc %d to %d bytes\n", l, enclen);
			hex(encbuf, enclen);
			#endif

			//HMAC generation
			for (maci = 0; maci < EVP_MAX_MD_SIZE; maci ++) {
				encbuf[enclen + maci] = '\0';
			}
			HMAC(EVP_sha256(), "key", 3, encbuf, enclen, encbuf + enclen, &md_len);
			total_len = enclen + EVP_MAX_MD_SIZE;

			#ifdef DEBUG_MAC_MODE
			printf("enclen:%d  total_len:%d\n", enclen, total_len);
			hex(encbuf + enclen, EVP_MAX_MD_SIZE);
			#endif

			if (sendto(s, encbuf, total_len, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
		} else {
			if (DEBUG) write(1,"<", 1);
			total_len = recvfrom(s, encbuf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
			if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
				printf("Got packet from  %s:%i instead of %s:%i\n", 
				       inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
				       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));

			//HMAC validation
			enclen = total_len - EVP_MAX_MD_SIZE;

			for (maci = 0; maci < EVP_MAX_MD_SIZE; maci ++) {
				md_cmp[maci] = '\0';
			}
			HMAC(EVP_sha256(), "key", 3, encbuf, enclen, md_cmp, &md_len);

			#ifdef DEBUG_MAC_MODE
			printf("enclen:%d  total_len:%d\n", enclen, total_len);
			hex(md_cmp, EVP_MAX_MD_SIZE);
			#endif
			mac_valid = memcmp(encbuf + enclen, md_cmp, EVP_MAX_MD_SIZE);

			if(mac_valid == 0){
				printf("hmac valid\n");
				// decrypt before write to net
				#ifdef DEBUG_MODE
				hex(encbuf, enclen);
				#endif
				l = do_crypt(encbuf, enclen, buf, key, 0);
				#ifdef DEBUG_MODE
				printf("dec %d to %d bytes\n", enclen, l);
				#endif

				if (write(fd, buf, l) < 0) PERROR("write");
			} else {
				printf("invalid hmac\n");
			}
		}
	}
}
	       
	
