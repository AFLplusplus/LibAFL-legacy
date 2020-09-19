MAKEFILE_PATH := $(abspath .)
LIBAFL_PATH := $(MAKEFILE_PATH)/..
CFLAGS += -g -Wall -Wextra -Wshadow -fstack-protector-strong
override CFLAGS += -I../include
override LDFLAGS += ../libafl.a -lpthread -lrt
LIBPNG_URL = http://prdownloads.sourceforge.net/libpng/libpng-1.6.37.tar.gz?download

ifdef DEBUG
  AFL_DEBUG=1
  override CFLAGS += -DDEBUG -ggdb -O0 -DAFL_DEBUG=1
endif
ifndef DEBUG
  override CFLAGS += -D_FORTIFY_SOURCE=2 -O3
endif
ifdef ASAN
  override CFLAGS += -fsanitize=address -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=address
endif
ifdef UBSAN
  override CFLAGS += -fsanitize=undefined -fno-omit-frame-pointer -lpthread
  override LDFLAGS += -fsanitize=undefined -lpthread
endif
ifdef MSAN
  CC := clang
  override CFLAGS += -fsanitize=memory -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=memory
endif

all: target forking-fuzzer libaflfuzzer-libpng llmp-main

afl-compiler-rt.o: afl-compiler-rt.o.c
	clang -O3 -I../include -c -o afl-compiler-rt.o afl-compiler-rt.o.c

.PHONY: ../libafl.a
../libafl.a:
	$(MAKE) -C $(LIBAFL_PATH) "CFLAGS=$(CFLAGS)" "LDFLAGS=$(LDFLAGS)" "ASAN=$(ASAN)" "DEBUG=$(DEBUG)" libafl.a

libpng-1.6.37.tar.gz:
	wget -c $(LIBPNG_URL) -O libpng-1.6.37.tar.gz

libpng16.a:	libpng-1.6.37.tar.gz
	tar -xvzf ./libpng-1.6.37.tar.gz || rm -f ./libpng-1.6.37.tar.gz
	cd libpng-1.6.37 && \
	export CC=clang && export CXX=clang++ && \
	export CFLAGS="-D_DEFAULT_SOURCE -fsanitize-coverage=trace-pc-guard" && \
	export CXXFLAGS="$CFLAGS" && unset LDFLAGS && \
	./configure --disable-shared && \
	$(MAKE)
	cp libpng-1.6.37/.libs/libpng16.a ./

target: afl-compiler-rt.o target.c
	clang -fsanitize-coverage=trace-pc-guard -g target.c -o target

forking-fuzzer: forking-fuzzer.c ../libafl.a
	$(CC) $(CFLAGS) forking-fuzzer.c -o forking-fuzzer $(LDFLAGS)

llmp-main: llmp-main.c  ../libafl.a
	$(CC) $(CFLAGS) llmp-main.c -o llmp-main $(LDFLAGS)

libaflfuzzer-libpng: libpng16.a libaflfuzzer-harness-libpng.c ../libaflfuzzer.a
	clang -g -fsanitize-coverage=trace-pc-guard -Ilibpng-1.6.37 -o libaflfuzzer-libpng ../libaflfuzzer.a libaflfuzzer-harness-libpng.c ./libpng16.a -pthread -lrt  -lz -lm

test: clean forking-fuzzer target
	mkdir ./in || true
	echo "AAAAAA" > ./in/a
	echo "BBBBBB" > ./in/b
	LD_LIBRARY_PATH=.. ./forking-fuzzer ./in 2 ./target
	rm -rf ./in
	rm -rf ./out-*
	rm -rf ./crashes-* 2>/dev/null || trues

clean:
	rm -rf out forking-fuzzer target success libaflfuzzer-libpng llmp-main 2>/dev/null || true
	rm -rf in 2>/dev/null	|| true
	rm -rf crashes-* 2>/dev/null || true
	rm -rf llmp-main || true
	rm -rf out-* || true

deepclean: clean
	rm -rf libpng-1.6.37 libpng16.a 2>/dev/null || true
