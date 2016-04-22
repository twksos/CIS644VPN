INC=/usr/local/ssl/include
LIB=/usr/local/ssl/lib
all:
	gcc -I$(INC) -L$(LIB) tunproxy.c crypt.c cli.c srv.c -o tunproxy -lssl -lcrypto -ldl

	# gcc -I$(INC) -L$(LIB) cli.c -o cli -lssl -lcrypto -ldl
	# gcc -I$(INC) -L$(LIB) srv.c -o srv -lssl -lcrypto -ldl