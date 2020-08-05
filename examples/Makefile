AFL_DIR=$(PWD)/../..
AFL_CC=$(AFL_DIR)/AFLplusplus/afl-clang
# TODO: Disable/fix -Wincompatible-pointer-types
CFLAGS+=-g -L$(AFL_DIR)/LibAFL -I$(AFL_DIR)/LibAFL/include -I$(AFL_DIR)/include -laflpp -lm -Wall -Wextra -Werror -fsanitize=address -fno-omit-frame-pointer -D_FORTIFY_SOURCE=2 -O1 -fstack-protector -Wno-incompatible-pointer-types

all: clean target executor

target: ./target.c
	$(AFL_CC) -g target.c -o target

executor: ./executor.c
	$(CC) executor.c -o executor $(CFLAGS)

test: executor target
	make -C ..
	mkdir ./in || true
	echo "AAAAAA" > ./in/a
	echo "BBBBBB" > ./in/b
	echo "CCCCCC" > ./in/c
	LD_LIBRARY_PATH=.. ./executor ./target ./in ./out
	rm -rf ./in
	rm -rf ./out

clean:
	rm out ./executor ./target ./success 2>/dev/null || true
	rm -rf ./in 2>/dev/null	|| true
