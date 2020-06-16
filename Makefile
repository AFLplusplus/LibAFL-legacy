CC=gcc
CFLAGS=-shared -g -O0 -fPIC -I./include -I../include -I../AFLplusplus/include

all:	libaflpp.so lib-common.so

clean:
	rm ./*.so

lib-common.o: ./src/lib-common.c ./include/lib-common.h
	$(CC) ./src/lib-common.c -o lib-common.so $(CFLAGS)

lib-common.so: ./src/lib-common.o
	$(CC) ./src/lib-common.o -o lib-common.so $(CFLAGS)

libaflpp.o: ./src/libaflpp.c ./include/libaflpp.h ./include/lib-common.h ./src/lib-common.c
	$(CC) ./src/libaflpp.c -o lipaflpp.so $(CFLAGS)

libaflpp.so: ./src/libaflpp.o
	$(CC) ./src/libaflpp.o -o lipaflpp.so $(CFLAGS)

code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i examples/*.c
	./.custom-format.py -i examples/*.h
