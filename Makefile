all:
	gcc -I/usr/local/ssl/include -L/usr/local/ssl/lib tunproxy.c -o tunproxy -lcrypto -ldl
