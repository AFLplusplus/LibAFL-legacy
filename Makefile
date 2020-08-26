CFLAGS+=-g -fPIC -I./include -I../include -I../AFLplusplus/include -Wall -Wextra -Werror -Wshadow -Wno-variadic-macros -fno-omit-frame-pointer -D_FORTIFY_SOURCE=2 -O3 -fstack-protector -std=gnu89
LDFLAGS+=-shared

all:	libaflpp.so

clean:
	rm ./src/*.o || true
	rm ./*.so || true
	rm example-fuzzer || true

# Compiling the common  file
common.o: ./src/common.c ./include/common.h
	$(CC) ./src/common.c -o common.so $(CFLAGS)


# Compiling the input  file
input.o: ./src/input.c ./include/input.h ./include/common.h
	$(CC) ./src/input.c -o input.so $(CFLAGS)


# Compiling the observation channel  file
observationchannel.o: ./src/observationchannel.c ./include/observationchannel.h ./include/common.h
	$(CC) ./src/observationchannel.c -o observationchannel.so $(CFLAGS)


# Compiling the queue  file
queue.o: ./src/queue.c ./include/queue.h ./src/input.o ./src/common.o
	$(CC) ./src/queue.c -o queue.so $(CFLAGS)


# Compiling the mutator  file
mutator.o: ./src/mutator.c ./include/mutator.h ./src/common.o ./src/input.o
	$(CC) ./src/mutator.c -o mutator.so $(CFLAGS)


# Compiling the feedback library
feedback.o: ./src/feedback.c ./include/feedback.h ./src/common.o ./src/queue.o
	$(CC) ./src/feedback.c -o feedback.so $(CFLAGS)


# Compiling the fuzzone library
fuzzone.o: ./src/fuzzone.c ./include/fuzzone.h ./src/common.o
	$(CC) ./src/fuzzone.c -o fuzzone.so $(CFLAGS)


# Compiling the Stage library
stage.o: ./src/stage.c ./include/stage.h ./src/input.o
	$(CC) ./src/stage.c -o stage.so $(CFLAGS)


# Compiling the engine library
engine.o: ./src/engine.c ./include/engine.h ./src/feedback.o ./src/queue.o ./src/common.o ./include/aflpp.h
	$(CC) ./src/engine.c -o engine.so $(CFLAGS)

# Compiling the OS helper  for the library
os.o: ./src/os.c ./include/os.h ./src/common.o ./src/input.o
	$(CC ./src/os.c -o os.so $(CFLAGS)

# Compiling the OS helper  for the library
llmp.o: ./src/llmp.c ./include/llmp.h
	$(CC ./src/os.c -o llmp.o $(CFLAGS)

# Compiling the final library
aflpp.o: ./src/aflpp.c ./include/aflpp.h ./src/observationchannel.o ./src/input.observation
	$(CC) ./src/aflpp.c -o aflpp.so $(CFLAGS)

libaflpp.so: ./src/llmp.o ./src/aflpp.o ./src/engine.o ./src/stage.o ./src/fuzzone.o ./src/feedback.o ./src/mutator.o ./src/queue.o ./src/observationchannel.o ./src/input.o ./src/common.o ./src/os.o
	$(CC) ./src/llmp.o ./src/aflpp.o ./src/engine.o ./src/stage.o ./src/fuzzone.o ./src/feedback.o ./src/mutator.o ./src/queue.o ./src/observationchannel.o ./src/input.o ./src/common.o ./src/os.o -o libaflpp.so $(CFLAGS) $(LDFLAGS)

example-fuzzer: ./src/llmp.o ./src/aflpp.o ./src/engine.o ./src/stage.o ./src/fuzzone.o ./src/feedback.o ./src/mutator.o ./src/queue.o ./src/observationchannel.o ./src/input.o ./src/common.o ./src/os.o
	$(CC) ./src/llmp.o ./src/aflpp.o ./src/engine.o ./src/stage.o ./src/fuzzone.o ./src/feedback.o ./src/mutator.o ./src/queue.o ./src/observationchannel.o ./src/input.o ./src/common.o ./src/os.o ./examples/executor.c -o example-fuzzer $(CFLAGS)



code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i examples/*.c
	./.custom-format.py -i test/*.c
