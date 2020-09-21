TARGETS=libafl.so libafl.a libaflfuzzer.a examples/libaflfuzzer-test
override CFLAGS  += -g -fPIC -Iinclude -Wall -Wextra -Werror -Wshadow -fstack-protector-strong 

ifdef DEBUG
  AFL_DEBUG=1 # always enable logs for now
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
  override CFLAGS += -fsanitize=undefined -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=undefined
endif
ifdef MSAN
  CC := clang
  override CFLAGS += -fsanitize=memory -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=memory
endif

all:	$(TARGETS) examples 

clean:
	rm -f src/*.o examples/*.o
	rm -f $(TARGETS) example-fuzzer
	$(MAKE) -C examples clean

deepclean: clean
	$(MAKE) -C examples deepclean

# Compiling the common  file
src/common.o: src/common.c include/common.h
	$(CC) $(CFLAGS) src/common.c -c -o src/common.o

# Compiling the input  file
src/input.o: src/input.c include/input.h include/common.h
	$(CC) $(CFLAGS) src/input.c -c -o src/input.o

# Compiling the observation channel  file
src/observer.o: src/observer.c include/observer.h include/common.h
	$(CC) $(CFLAGS) src/observer.c -c -o src/observer.o

# Compiling the queue  file
src/queue.o: src/queue.c include/queue.h src/input.o src/common.o
	$(CC) $(CFLAGS) src/queue.c -c -o src/queue.o

# Compiling the mutator  file
src/mutator.o: src/mutator.c include/mutator.h src/common.o src/input.o
	$(CC) $(CFLAGS) src/mutator.c -c -o src/mutator.o

# Compiling the feedback library
src/feedback.o: src/feedback.c include/feedback.h src/common.o src/queue.o
	$(CC) $(CFLAGS) src/feedback.c -c -o src/feedback.o

# Compiling the fuzzone library
src/fuzzone.o: src/fuzzone.c include/fuzzone.h src/common.o
	$(CC) $(CFLAGS) src/fuzzone.c -c -o src/fuzzone.o

src/shmem.o: src/shmem.c include/shmem.h
	$(CC) $(CFLAGS) src/shmem.c -c -o src/shmem.o

# Compiling the Stage library
src/stage.o: src/stage.c include/stage.h src/input.o
	$(CC) $(CFLAGS) src/stage.c -c -o src/stage.o

# Compiling the engine library
src/engine.o: src/engine.c include/engine.h src/feedback.o src/queue.o src/common.o include/aflpp.h
	$(CC) $(CFLAGS) src/engine.c -c -o src/engine.o

# Compiling the OS helper  for the library
src/os.o: src/os.c include/os.h src/common.o src/input.o
	$(CC) $(CFLAGS) src/os.c -c -o src/os.o

# Compiling the OS helper  for the library
src/llmp.o: src/llmp.c include/llmp.h
	$(CC) $(CFLAGS) src/llmp.c -c -o src/llmp.o

# Compiling the final library
src/afl.o: src/aflpp.c include/aflpp.h src/observer.o src/input.observation
	$(CC) $(CFLAGS) src/aflpp.c -c -o src/aflpp.o

libafl.so: src/llmp.o src/aflpp.o src/engine.o src/stage.o src/fuzzone.o src/feedback.o src/mutator.o src/queue.o src/observer.o src/input.o src/common.o src/os.o src/shmem.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $^ -o libafl.so

libafl.a: src/llmp.o src/aflpp.o src/engine.o src/stage.o src/fuzzone.o src/feedback.o src/mutator.o src/queue.o src/observer.o src/input.o src/common.o src/os.o src/shmem.o
	@rm -f libafl.a
	ar -crs libafl.a $^

examples/afl-compiler-rt.o:	examples/afl-compiler-rt.o.c
	clang -O3 -Iinclude -c -o examples/afl-compiler-rt.o examples/afl-compiler-rt.o.c

libaflfuzzer.a: libafl.a examples/afl-compiler-rt.o examples/libaflfuzzer.c
	@rm -f libaflfuzzer.a
	clang $(CFLAGS) $(LDFLAGS) -c -o examples/libaflfuzzer.o examples/libaflfuzzer.c
	ar -crs libaflfuzzer.a src/*.o examples/afl-compiler-rt.o examples/libaflfuzzer.o

examples/libaflfuzzer-test:	libaflfuzzer.a examples/libaflfuzzer-harness-test.c
	clang -Iinclude -fsanitize-coverage=trace-pc-guard -o examples/libaflfuzzer-test examples/libaflfuzzer-harness-test.c libaflfuzzer.a -pthread -lrt $(CFLAGS) $(LDFLAGS)

.PHONY: examples
examples:
	$(MAKE) -C examples "CFLAGS=$(CFLAGS)" "LDFLAGS=$(LDFLAGS)"

code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i examples/*.c
	./.custom-format.py -i test/*.c
