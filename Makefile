override CFLAGS  += -g -fPIC -Iinclude -Iexamples/AFLplusplus/include -Wall -Wextra -Werror -Wshadow -Wno-variadic-macros -fstack-protector-strong -fsanitize=address -DLLMP_DEBUG=1
LDFLAGS += -fsanitize=address

ifdef DEBUG
  override CFLAGS += -DDEBUG -ggdb -Og
endif
ifndef DEBUG
  override CFLAGS += -D_FORTIFY_SOURCE=2 -O3
endif
ifdef ASAN
  override CFLAGS += -fsanitize=address
  override LDFLAGS += -fsanitize=address
endif

all:	libafl.so libafl.a make-examples example-fuzzer libaflfuzzer.a examples/libaflfuzzer-test

clean:
	rm -f src/*.o examples/*.o
	rm -f libafl.so libafl.a libaflfuzzer.a
	rm -f example-fuzzer examples/libaflfuzzer-test

# Compiling the common  file
common.o: src/common.c include/common.h
	$(CC) $(CFLAGS) src/common.c -c -o common.o

# Compiling the input  file
input.o: src/input.c include/input.h include/common.h
	$(CC) $(CFLAGS) src/input.c -c -o input.o

# Compiling the observation channel  file
observationchannel.o: src/observationchannel.c include/observationchannel.h include/common.h
	$(CC) $(CFLAGS) src/observationchannel.c -c -o observationchannel.o

# Compiling the queue  file
queue.o: src/queue.c include/queue.h src/input.o src/common.o
	$(CC) $(CFLAGS) src/queue.c -c -o queue.o

# Compiling the mutator  file
mutator.o: src/mutator.c include/mutator.h src/common.o src/input.o
	$(CC) $(CFLAGS) src/mutator.c -c -o mutator.o

# Compiling the feedback library
feedback.o: src/feedback.c include/feedback.h src/common.o src/queue.o
	$(CC) $(CFLAGS) src/feedback.c -c -o feedback.o

# Compiling the fuzzone library
fuzzone.o: src/fuzzone.c include/fuzzone.h src/common.o
	$(CC) $(CFLAGS) src/fuzzone.c -c -o fuzzone.o

shmem.o: src/shmem.c include/afl-shmem.h
	$(CC) $(CFLAGS) src/shmem.c -c -o shmem.o

# Compiling the Stage library
stage.o: src/stage.c include/stage.h src/input.o
	$(CC) $(CFLAGS) src/stage.c -c -o stage.o

# Compiling the engine library
engine.o: src/engine.c include/engine.h src/feedback.o src/queue.o src/common.o include/afl.h
	$(CC) $(CFLAGS) src/engine.c -c -o engine.o

# Compiling the OS helper  for the library
os.o: src/os.c include/os.h src/common.o src/input.o
	$(CC) $(CFLAGS) src/os.c -c -o os.o

# Compiling the OS helper  for the library
llmp.o: src/llmp.c include/llmp.h
	$(CC) $(CFLAGS) src/os.c -c -o llmp.o

# Compiling the final library
afl.o: src/aflpp.c include/aflpp.h src/observationchannel.o src/input.observation
	$(CC) $(CFLAGS) src/aflpp.c -c -o aflpp.o

libafl.so: src/llmp.o src/aflpp.o src/engine.o src/stage.o src/fuzzone.o src/feedback.o src/mutator.o src/queue.o src/observationchannel.o src/input.o src/common.o src/os.o src/shmem.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $^ -o libafl.so

libafl.a: src/llmp.o src/aflpp.o src/engine.o src/stage.o src/fuzzone.o src/feedback.o src/mutator.o src/queue.o src/observationchannel.o src/input.o src/common.o src/os.o src/shmem.o
	@rm -f libafl.a
	ar -crs libafl.a $^

libaflfuzzer.a: libafl.a examples
	@rm -f libaflfuzzer.a
	clang $(CFLAGS) $(LDFLAGS) -c -o examples/libaflfuzzer.o examples/libaflfuzzer.c
	ar -crs libaflfuzzer.a src/*.o examples/AFLplusplus/afl-llvm-rt.o examples/libaflfuzzer.o

examples/libaflfuzzer-test:	libaflfuzzer.a
	clang -fsanitize-coverage=trace-pc-guard -Iexamples/AFLplusplus/include/ -o examples/libaflfuzzer-test examples/AFLplusplus/examples/aflpp_driver/aflpp_driver_test.c libaflfuzzer.a examples/AFLplusplus/src/afl-performance.o -pthread $(LDFLAGS) -lrt

.PHONY: make-examples
make-examples:
	$(MAKE) -C examples

example-fuzzer: libafl.a
	$(CC) $(CFLAGS) -o example-fuzzer examples/executor.c libafl.a -pthread $(LDFLAGS) -lrt

code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i examples/*.c
	./.custom-format.py -i test/*.c
