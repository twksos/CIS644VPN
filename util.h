#ifndef MY_UTIL_H_
#define MY_UTIL_H_

void hex(const char *s, int bytes);
char * str_to_hex(char *src, int src_len);
int hex_to_str(char * hex, int hex_len, char * str);

#endif