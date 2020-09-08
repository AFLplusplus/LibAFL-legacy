MAKEFILE_PATH := $(abspath .)
AFL_PATH ?= $(MAKEFILE_PATH)/AFLplusplus
AFL_CC := $(AFL_PATH)/afl-clang-fast
CFLAGS += -g -Wall -Wextra -Wshadow -Wno-variadic-macros -D_FORTIFY_SOURCE=2 -O3 -fstack-protector-strong
override CFLAGS += -L.. -I../include -I$(AFL_PATH)/include -lm 
override LDFLAGS += ../libaflpp.a -lpthread -lm -lrt
LIBPNG_URL = http://prdownloads.sourceforge.net/libpng/libpng-1.6.37.tar.gz?download

$(info AFL_PATH is $(AFL_PATH))

all: target executor in-memory-fuzzer

$(AFL_PATH)/llvm_mode/afl-llvm-rt.c:
	-git submodule init 2> /dev/null
	-git submodule update 2> /dev/null
	test -d $(AFL_PATH) || git clone https://github.com/AFLplusplus/AFLplusplus
	$(MAKE) -C $(AFL_PATH)
	$(MAKE) -C $(AFL_PATH)/llvm_mode

$(AFL_PATH)/afl-llvm-rt.o:	$(AFL_PATH)/llvm_mode/afl-llvm-rt.c

libpng-1.6.37.tar.gz:
	wget -c $(LIBPNG_URL) -O libpng-1.6.37.tar.gz

libpng16.a:	libpng-1.6.37.tar.gz
	tar -xvzf ./libpng-1.6.37.tar.gz || rm -f ./libpng-1.6.37.tar.gz
	cd libpng-1.6.37 && CC=$(AFL_CC) CXX=$(AFL_PATH)/afl-clang-fast++ ./configure CFLAGS= LDFLAGS= --disable-shared && $(MAKE)
	cp libpng-1.6.37/.libs/libpng16.a ./

target: $(AFL_PATH)/afl-llvm-rt.o ./target.c
	$(AFL_CC) -g target.c -o target

executor: ./executor.c
	$(CC) $(CFLAGS) executor.c -o executor $(LDFLAGS)

llmp-main: ./llmp-main.c
	$(CC) $(CFLAGS) llmp-main.c -o llmp-main $(LDFLAGS)

in-memory-fuzzer: libpng16.a $(AFL_PATH)/afl-llvm-rt.o in-memory-fuzzer.c
	clang in-memory-fuzzer.c ./libpng16.a -g $(CFLAGS) -Ilibpng-1.6.37 -Iexecutors -Ifeedbacks -o in-memory-fuzzer $(AFL_PATH)/afl-llvm-rt.o $(LDFLAGS) -lz

test: clean executor target
	mkdir ./in || true
	echo "AAAAAA" > ./in/a
	echo "BBBBBB" > ./in/b
	LD_LIBRARY_PATH=.. ./executor ./in 2 ./target
	rm -rf ./in
	rm -rf ./out-*
	rm -rf ./crashes-* 2>/dev/null || trues

clean:
	rm out ./executor ./target ./success ./in-mem 2>/dev/null || true
	rm -rf ./in 2>/dev/null	|| true
	rm -rf ./crashes-* 2>/dev/null || true
	rm -rf ./llmp-main || true
	rm -rf ./out-* || true
	rm -rf ./libpng-1.6.37 libpng16.a 2>/dev/null || true
