MAKEFILE_PATH := $(abspath .)
#AFL_DIR:=$(realpath $(MAKEFILE_PATH)/../examples/AFLplusplus)
override CFLAGS+=-g -L$(MAKEFILE_PATH)/.. -I$(MAKEFILE_PATH)/../include ../libafl.a -lm -Wall -Wextra -Wshadow -Werror -fno-omit-frame-pointer -Og -fstack-protector-strong -DLLMP_DEBUG=1 

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

all: test

../libafl.a:
	make DEBUG=1 ASAN=1 -C .. libafl.a

unit_test: ./unit_test.c ../libafl.a
	$(CC) ./unit_test.c -o ./unit_test -Wl,--wrap=exit -lcmocka $(CFLAGS) -lrt -lpthread

unit_llmp: ./unit_llmp.c ../libafl.a
	$(CC) ./unit_llmp.c -o ./unit_llmp -Wl,--wrap=exit -lcmocka $(CFLAGS) -lrt -lpthread #-Wl,--wrap=printf 

test: unit_test unit_llmp
	rm -rf ./testcases || true
	LD_LIBRARY_PATH=.. ./unit_test
	LD_LIBRARY_PATH=.. ./unit_llmp

clean:
	rm -rf ./testcases || true
	rm unit_test || true
	rm unit_llmp || true
