AFL_CC=~/AFLplusplus/afl-clang
CC=gcc
AFL_DIR=$(PWD)/../..
CFLAGS=-g -L$(AFL_DIR)/LibAFL -I$(AFL_DIR)/LibAFL/include -I$(AFL_DIR)/include -laflpp

all: clean target executor

target: ./target.c
	$(AFL_CC) -g target.c -o target
	mkdir /tmp/inp
	echo "AAAAAA" > /tmp/inp/a
	echo "BBBBBB" > /tmp/inp/b
	echo "CCCCCC" > /tmp/inp/c

executor: ./executor.c
	$(CC) executor.c -o executor $(CFLAGS)

clean:
	rm out ./executor ./target ./success 2>/dev/null || true
	rm -rf /tmp/inp 2>/dev/null	|| true
