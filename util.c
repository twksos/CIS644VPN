#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void hex(const char *s, int bytes){
	int i;
	for(i=0;i<bytes;i++) {
		printf("%02x ", (unsigned char) *s++); 
	}
	printf("\n");
}

char * str_to_hex(char *src, int src_len){
	int i;
	char *hex = malloc((size_t) (src_len * 2 +1));
	for(i=0;i<src_len;i++) {
		sprintf(hex+i*2, "%02x", (unsigned char) src[i]);
	}
	hex[src_len * 2] = '\0';
	return hex;
}

int hex_to_str(char * hex, int hex_len, char * str){
	int i;
	int tmp;
	for(i=0;i<hex_len;i++) {
		tmp = hex[i*2] - '0';
		tmp = tmp << 4;
		tmp += hex [i*2 + 1];
		str[i] = (char) tmp;
	}
	return i>>1;
}

int same_domain(char * str, char * domain) {
	int domain_len = strlen(domain);
	int str_len = strlen(str);
	int start = str_len - domain_len;
	int domain_correct = memcmp(str + start, domain, domain_len);
#ifdef DEBUG
	printf("str: %s\n", str + start);
	printf("chr: %c\n", str[start-1]);
#endif
	bool sym_correct = str[start-1] == '=' || str[start-1] == '.' ;

	if (domain_correct == 0 && sym_correct == 1) return 1;
	else return 0;
}

//int main(){
//	char * hex = str_to_hex("1234", 4);
//	printf("hex: %s", hex);
//	char * str = malloc(4);
//	int strlen = hex_to_str(hex, 8, str);
//	int i;
//	printf("len %d", strlen);
//
//	for (i = 0; i < strlen; ++i) {
//		printf("%c", str[i]);
//	}
//
//	if(same_domain("/C=US/ST=New-York/O=GuangchengWei/CN=VPNCLIENT", "VPNCLIENT")) printf("VPN\n");
//	if(same_domain("/C=US/ST=New-York/O=GuangchengWei/CN=www.google.com", "google.com")) printf("wwwgoogle\n");
//	if(same_domain("/C=US/ST=New-York/O=GuangchengWei/CN=google.com", "google.com")) printf("google\n");
//	if(same_domain("/C=US/ST=New-York/O=GuangchengWei/CN=fakegoogle.com", "google.com")) printf("fakegoogle\n");
//}