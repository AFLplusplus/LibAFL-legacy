MAKEFILE_PATH := $(abspath .)
AFL_DIR?=$(realpath $(MAKEFILE_PATH)/../../)
AFL_CC:=afl-clang-fast
CFLAGS+=-g -L.. -I../include -I$(AFL_DIR)/include -pthread -laflpp -lm -Wall -Wextra -Wno-variadic-macros -fno-omit-frame-pointer -D_FORTIFY_SOURCE=2 -O1 -fstack-protector

$(info AFL_DIR is $(AFL_DIR))

all: clean target executor

target: ./target.c
	$(AFL_CC) -g target.c -o target

executor: ./executor.c
	gcc executor.c -o executor $(CFLAGS)

test: clean executor target
	make -C ..
	mkdir ./in || true
	echo "AAAAAA" > ./in/a
	echo "BBBBBB" > ./in/b
	echo "CCCCCC" > ./in/c
	LD_LIBRARY_PATH=.. ./executor ./in 2 ./target
	rm -rf ./in
	rm -rf ./out-*
	rm -rf ./crashes-* 2>/dev/null || trues

llmp-main: ./llmp-main.c
	$(CC) llmp-main.c -o llmp-main $(CFLAGS)

clean:
	rm out ./executor ./target ./success ./in-mem 2>/dev/null || true
	rm -rf ./in 2>/dev/null	|| true
	rm -rf ./crashes-* 2>/dev/null || true
	rm -rf ./out-*

in-memory-fuzzer: in-memory-fuzzer.c
	clang in-memory-fuzzer.c ./libpng.a -g $(CFLAGS) -L.  -Iexecutors -Ifeedbacks -laflpp -o in-mem -lz -lm  $(AFL_DIR)/afl-llvm-rt.o
