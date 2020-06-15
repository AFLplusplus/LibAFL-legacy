CC=gcc
CFLAGS=-shared -g -O0 -fPIC -I./include -I../include -I../AFLplusplus/include

all:	libaflpp.so

clean:
	rm ./*.so

libaflpp.o: ./src/libaflpp.c ./include/libaflpp.h
	$(CC) ./src/libaflpp.c -o lipaflpp.so $(CFLAGS)

libaflpp.so: ./src/libaflpp.o
	$(CC) ./src/libaflpp.o -o lipaflpp.so $(CFLAGS)

code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i examples/*.c
	./.custom-format.py -i examples/*.h
