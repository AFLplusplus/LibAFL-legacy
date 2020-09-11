MAKEFILE_PATH := $(abspath .)
AFL_PATH ?= $(MAKEFILE_PATH)/AFLplusplus
LIBAFL_PATH := $(MAKEFILE_PATH)/..
AFL_CC := $(AFL_PATH)/afl-clang-fast
CFLAGS += -g -Wall -Wextra -Wshadow -fstack-protector-strong
override CFLAGS += -L.. -I../include -lm 
override LDFLAGS += ../libafl.a -lpthread -lm -lrt
LIBPNG_URL = http://prdownloads.sourceforge.net/libpng/libpng-1.6.37.tar.gz?download

ifdef DEBUG
  override CFLAGS += -DDEBUG -ggdb -O0 -DLLMP_DEBUG=1
endif
ifndef DEBUG
  override CFLAGS += -D_FORTIFY_SOURCE=2 -O3
endif
ifdef ASAN
  override CFLAGS += -fsanitize=address -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=address
endif
ifdef MSAN
  CC := clang
  override CFLAGS += -fsanitize=memory -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=memory
endif

$(info AFL_PATH is $(AFL_PATH))

all: target forking-fuzzer in-memory-fuzzer llmp-main

 $(AFL_PATH)/llvm_mode/afl-llvm-rt.o.c:
	-git submodule init 2> /dev/null
	-git submodule update 2> /dev/null
	test -d $(AFL_PATH) || git clone https://github.com/AFLplusplus/AFLplusplus

$(AFL_PATH)/afl-llvm-rt.o: $(AFL_PATH)/llvm_mode/afl-llvm-rt.o.c
	$(MAKE) CFLAGS= LDFLAGS= -C $(AFL_PATH)
	$(MAKE) CFLAGS= LDFLAGS= -C $(AFL_PATH)/llvm_mode

.PHONY: ../libafl.a
../libafl.a:
	$(MAKE) -C $(LIBAFL_PATH) "CFLAGS=$(CFLAGS)" "LDFLAGS=$(LDFLAGS)" "ASAN=$(ASAN)" "DEBUG=$(DEBUG)" libafl.a

libpng-1.6.37.tar.gz:
	wget -c $(LIBPNG_URL) -O libpng-1.6.37.tar.gz

libpng16.a:	libpng-1.6.37.tar.gz
	tar -xvzf ./libpng-1.6.37.tar.gz || rm -f ./libpng-1.6.37.tar.gz
	cd libpng-1.6.37 && CC=$(AFL_CC) CXX=$(AFL_PATH)/afl-clang-fast++ ./configure CFLAGS=-D_DEFAULT_SOURCE LDFLAGS= --disable-shared && $(MAKE) CFLAGS=-D_DEFAULT_SOURCE LDFLAGS=
	cp libpng-1.6.37/.libs/libpng16.a ./
	rm -rf libpng-1.6.37

target: $(AFL_PATH)/afl-llvm-rt.o target.c
	$(AFL_CC) -g target.c -o target

forking-fuzzer: ./forking-fuzzer.c ../libafl.a
	$(CC) $(CFLAGS) forking-fuzzer.c -o forking-fuzzer $(LDFLAGS)

llmp-main: ./llmp-main.c  ../libafl.a
	$(CC) $(CFLAGS) llmp-main.c -o llmp-main $(LDFLAGS)

in-memory-fuzzer: libpng16.a $(AFL_PATH)/afl-llvm-rt.o in-memory-fuzzer.c ../libafl.a
	clang in-memory-fuzzer.c ./libpng16.a -g $(CFLAGS) -Ilibpng-1.6.37 -Iexecutors -Ifeedbacks -o in-memory-fuzzer $(AFL_PATH)/afl-llvm-rt.o $(LDFLAGS) -lz

test: clean forking-fuzzer target
	mkdir ./in || true
	echo "AAAAAA" > ./in/a
	echo "BBBBBB" > ./in/b
	LD_LIBRARY_PATH=.. ./forking-fuzzer ./in 2 ./target
	rm -rf ./in
	rm -rf ./out-*
	rm -rf ./crashes-* 2>/dev/null || trues

clean:
	rm  out forking-fuzzer target success in-memory-fuzzer llmp-main 2>/dev/null || true
	rm -rf in 2>/dev/null	|| true
	rm -rf crashes-* 2>/dev/null || true
	rm -rf llmp-main || true
	rm -rf out-* || true

deepclean: clean
	$(make) -C $(AFL_PATH) clean || true
	rm -rf libpng-1.6.37 libpng16.a 2>/dev/null || true
