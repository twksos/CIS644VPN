#include <stdio.h>

void hex(const char *s, int bytes){
	int i;
	for(i=0;i<bytes;i++) {
		printf("%02x ", (unsigned char) *s++); 
	}
	printf("\n");
}