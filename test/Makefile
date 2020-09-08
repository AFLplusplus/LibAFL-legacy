MAKEFILE_PATH := $(abspath .)
#AFL_DIR:=$(realpath $(MAKEFILE_PATH)/../examples/AFLplusplus)
override CFLAGS+=-g -L$(MAKEFILE_PATH)/.. -I$(MAKEFILE_PATH)/../include ../libafl.a -lm -Wall -Wextra -Wshadow -Werror -fno-omit-frame-pointer -Og -fstack-protector-strong -fsanitize=address -DLLMP_DEBUG=1 

all: test

../libafl.a:
	make DEBUG=1 ASAN=1 -C .. libafl.a
	

unit_test: ./unit_test.c ../libafl.a
	$(CC) ./unit_test.c -o ./unit_test -Wl,--wrap=exit -Wl,--wrap=printf -lcmocka $(CFLAGS) -lrt

unit_llmp: ./unit_llmp.c ../libafl.a
	$(CC) ./unit_llmp.c -o ./unit_llmp -Wl,--wrap=exit -Wl,--wrap=printf -lcmocka $(CFLAGS) -lrt

test: unit_test unit_llmp
	rm -rf ./testcases || true
	LD_LIBRARY_PATH=.. ./unit_test
	LD_LIBRARY_PATH=.. ./unit_llmp

clean:
	rm -rf ./testcases || true
	rm unit_test || true
	rm unit_llmp || true
