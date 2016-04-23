INC=/usr/local/ssl/include
LIB=/usr/local/ssl/lib
all:
	gcc -I$(INC) -L$(LIB) tunproxy.c crypt.c cli.c srv.c util.c -o tunproxy -lssl -lcrypto -ldl