MAKEFILE_PATH := $(abspath .)
AFL_DIR:=$(realpath $(MAKEFILE_PATH)/../../)
AFL_CC:=$(AFL_DIR)/AFLplusplus/afl-clang
override CFLAGS+=-g -L$(AFL_DIR)/LibAFL -I$(AFL_DIR)/LibAFL/include -I$(AFL_DIR)/include -laflpp -lm -Wall -Wextra -Wshadow -Werror -fno-omit-frame-pointer -Og -fstack-protector-strong -fsanitize=address 

all: test

unit_test: ./unit_test.c
	$(CC) ./unit_test.c -o ./unit_test -Wl,--wrap=exit -Wl,--wrap=printf -lcmocka $(CFLAGS) -lrt

unit_llmp: ./unit_llmp.c
	$(CC) ./unit_llmp.c -o ./unit_llmp -Wl,--wrap=exit -Wl,--wrap=printf -lcmocka $(CFLAGS) -lrt

test: unit_test unit_llmp
	make DEBUG=1 ASAN=1 -C .. libaflpp.a
	rm -rf ./testcases || true
	LD_LIBRARY_PATH=.. ./unit_test
	LD_LIBRARY_PATH=.. ./unit_llmp

clean:
	rm -rf ./testcases || true
	rm unit_test || true
	rm unit_llmp || true
