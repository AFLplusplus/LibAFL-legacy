MAKEFILE_PATH := $(abspath .)
AFL_DIR:=$(realpath $(MAKEFILE_PATH)/../../)
AFL_CC:=$(AFL_DIR)/AFLplusplus/afl-clang-fast
CFLAGS+=-g -L$(AFL_DIR)/LibAFL -I$(AFL_DIR)/LibAFL/include -I$(AFL_DIR)/include -pthread -fsanitize=address -laflpp -lm -Wall -Wextra -Werror -Wno-variadic-macros -fno-omit-frame-pointer -D_FORTIFY_SOURCE=2 -O1 -fstack-protector

all: clean target executor

target: ./target.c
	$(AFL_CC) -g target.c -o target

executor: ./executor.c
	$(CC) executor.c -o executor $(CFLAGS)

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

clean:
	rm out ./executor ./target ./success 2>/dev/null || true
	rm -rf ./in 2>/dev/null	|| true
	rm -rf ./crashes-* 2>/dev/null || true
	rm -rf ./out-*

in-memory-fuzzer: in-memory-fuzzer.c
	clang Runtime.c in-memory-fuzzer.c ./libpng.a -g -L/home/jack_0f_spades/LibAFL -L/home/jack_0f_spades/LibAFL/examples -I/home/jack_0f_spades/LibAFL/include -I/home/jack_0f_spades/LibAFL/examples/executors -laflpp -o in-mem -lz -lm $(AFL_DIR)/AFLplusplus/afl-llvm-rt.o
