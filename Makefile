CC=gcc
CFLAGS=-g -O0 -fPIC -I./include -I../include -I../AFLplusplus/include -Wall -Werror
LDFLAGS=-shared

all:	libaflpp.so

clean:
	rm ./src/*.o || true
	rm ./*.so || true

# Compiling the common lib file
libcommon.o: ./src/libcommon.c ./include/libcommon.h
	$(CC) ./src/libcommon.c -o libcommon.so $(CFLAGS)


# Compiling the input lib file
libinput.o: ./src/libinput.c ./include/libinput.h ./include/libcommon.h
	$(CC) ./src/libinput.c -o libinput.so $(CFLAGS)


# Compiling the observation channel lib file
libobservationchannel.o: ./src/libobservationchannel.c ./include/libobservationchannel.h ./include/libcommon.h
	$(CC) ./src/libobservationchannel.c -o libobservationchannel.so $(CFLAGS)


# Compiling the queue lib file
libqueue.o: ./src/libqueue.c ./include/libqueue.h ./src/libinput.o ./src/libcommon.o
	$(CC) ./src/libqueue.c -o libqueue.so $(CFLAGS)


# Compiling the mutator lib file
libmutator.o: ./src/libmutator.c ./include/libmutator.h ./src/libcommon.o ./src/libinput.o
	$(CC) ./src/libmutator.c -o libmutator.so $(CFLAGS)


# Compiling the feedback library
libfeedback.o: ./src/libfeedback.c ./include/libfeedback.h ./src/libcommon.o ./src/libqueue.o
	$(CC) ./src/libfeedback.c -o libfeedback.so $(CFLAGS)


# Compiling the fuzzone library
libfuzzone.o: ./src/libfuzzone.c ./include/libfuzzone.h ./src/libcommon.o
	$(CC) ./src/libfuzzone.c -o libfuzzone.so $(CFLAGS)


# Compiling the Stage library
libstage.o: ./src/libstage.c ./include/libstage.h ./src/libinput.o
	$(CC) ./src/libstage.c -o libstage.so $(CFLAGS)


# Compiling the engine library
libengine.o: ./src/libengine.c ./include/libengine.h ./src/libfeedback.o ./src/libqueue.o ./src/libcommon.o ./include/libaflpp.h
	$(CC) ./src/libengine.c -o libengine.so $(CFLAGS)

# Compiling the OS helper lib for the library
libos.o: ./src/libos.c ./include/libos.h ./src/libcommon.o ./src/libinput.o
	$(CC ./src/libos.c -o libos.so $(CFLAGS)

# Compiling the final library
libaflpp.o: ./src/libaflpp.c ./include/libaflpp.h ./src/libobservationchannel.o ./src/libinput.observation
	$(CC) ./src/libaflpp.c -o libaflpp.so $(CFLAGS)

libaflpp.so: ./src/libaflpp.o ./src/libengine.o ./src/libstage.o ./src/libfuzzone.o ./src/libfeedback.o ./src/libmutator.o ./src/libqueue.o ./src/libobservationchannel.o ./src/libinput.o ./src/libcommon.o ./src/libos.o
	$(CC) ./src/libaflpp.o ./src/libengine.o ./src/libstage.o ./src/libfuzzone.o ./src/libfeedback.o ./src/libmutator.o ./src/libqueue.o ./src/libobservationchannel.o ./src/libinput.o ./src/libcommon.o ./src/libos.o -o libaflpp.so $(CFLAGS) $(LDFLAGS)
	# rm ./src/*.o

code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i examples/*.c
	./.custom-format.py -i examples/*.h
