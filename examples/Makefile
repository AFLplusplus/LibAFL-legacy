MAKEFILE_PATH := $(abspath .)
AFL_PATH?=$(realpath $(MAKEFILE_PATH)/AFLplusplus)
AFL_CC:=$(AFL_PATH)/afl-clang-fast
CFLAGS += -g -L.. -I../include -I$(AFL_PATH)/include -lm -Wall -Wextra -Wshadow -Wno-variadic-macros -D_FORTIFY_SOURCE=2 -O3 #-fstack-protector-strong -fsanitize=address -fno-omit-frame-pointer 
LDFLAGS += ../libaflpp.a -lpthread -lm
LIBPNG_URL=http://prdownloads.sourceforge.net/libpng/libpng-1.6.37.tar.gz?download

$(info AFL_PATH is $(AFL_PATH))

all: target executor in-memory-fuzzer

lib:
	make -C ..

afl:
	-git submodule init
	-git submodule update
	test -d $(AFL_PATH) || git clone https://github.com/AFLplusplus/AFLplusplus
	make -C $(AFL_PATH)
	make -C $(AFL_PATH)/llvm_mode

libpng-1.6.37.tar.gz:
	wget -c $(LIBPNG_URL) -O libpng-1.6.37.tar.gz

libpng16.a:	libpng-1.6.37.tar.gz
	tar -xvzf ./libpng-1.6.37.tar.gz || rm -f ./libpng-1.6.37.tar.gz
	cd libpng-1.6.37 && CC=$(AFL_CC) CXX=$(AFL_PATH)/afl-clang-fast++ ./configure --disable-shared && make
	cp libpng-1.6.37/.libs/libpng16.a ./

target: afl ./target.c
	$(AFL_CC) -g target.c -o target

executor: lib ./executor.c
	$(CC) $(CFLAGS) executor.c -o executor $(LDFLAGS)

llmp-main: lib ./llmp-main.c
	$(CC) $(CFLAGS) llmp-main.c -o llmp-main $(LDFLAGS)

in-memory-fuzzer: lib libpng16.a afl in-memory-fuzzer.c
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
