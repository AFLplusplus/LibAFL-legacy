CC=gcc
CFLAGS=-shared -fPIC -I./include -I../include

libaflpp.so: ./src/libaflpp.so.c ./include/libaflpp.h
	$(CC) ./src/libaflpp.so.c -o lipaflpp.so $(CFLAGS)
