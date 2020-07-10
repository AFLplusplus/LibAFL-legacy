CC=gcc
CFLAGS=-shared -g -O0 -fPIC -I./include -I../include -I../AFLplusplus/include

all:	libcommon.so libinput.so libobservationchannel.so libqueue.so libmutator.so libfeedback.so 

clean:
	rm ./*.so

# Compiling the common lib file
libcommon.o: ./src/libcommon.c ./include/libcommon.h
	$(CC) ./src/libcommon.c -o libcommon.so $(CFLAGS)

libcommon.so: ./src/libcommon.o
	$(CC) ./src/libcommon.o -o libcommon.so $(CFLAGS)

# Compiling the input lib file
libinput.o: ./src/libinput.c ./include/libinput.h ./include/libcommon.h
	$(CC) ./src/libinput.c -o libinput.so $(CFLAGS)

libinput.so: ./src/libinput.o
	$(CC) ./src/libinput.o -o libinput.so $(CFLAGS)

# Compiling the observation channel lib file
libobservationchannel.o: ./src/libobservationchannel.c ./include/libobservationchannel.h ./include/libcommon.h
	$(CC) ./src/libobservationchannel.c -o libobservationchannel.so $(CFLAGS)

libobservationchannel.so: ./src/libobservationchannel.o
	$(CC) ./src/libobservationchannel.o -o libobservationchannel.so $(CFLAGS)

# Compiling the queue lib file
libqueue.o: ./src/libqueue.c ./include/libqueue.h ./src/libinput.o ./src/libcommon.o
	$(CC) ./src/libqueue.c -o libqueue.so $(CFLAGS)

libqueue.so: ./src/libqueue.o
	$(CC) ./src/libqueue.o -o libqueue.so $(CFLAGS)

# Compiling the mutator lib file
libmutator.o: ./src/libmutator.c ./include/libmutator.h ./src/libcommon.o ./src/libinput.o
	$(CC) ./src/libmutator.c -o libmutator.so $(CFLAGS)

libmutator.so:./src/libmutator.o
	$(CC) ./src/libmutator.o -o libmutator.so $(CFLAGS)

# Compiling the feedback library
libfeedback.o: ./src/libfeedback.c ./include/libfeedback.h ./src/libcommon.o ./src/libqueue.o
	$(CC) ./src/libfeedback.c -o libfeedback.so $(CFLAGS)

libfeedback.so:	./src/libfeedback.o
	$(CC) ./src/libfeedback.o -o libfeedback.so $(CFLAGS)

# Compiling the fuzzone library
libfuzzone.o: ./src/libfuzzone.c ./include/libfuzzone.h ./src/libcommon.o
	$(CC) ./src/libfuzzone.c -o libfuzzone.so $(CFLAGS)

libfuzzone.so: ./src/libfuzzone.o
	$(CC) ./src/libfuzzone.o -o libfuzzone.so $(CFLAGS)

# Compiling the Stage library
libstage.o: ./src/libstage.c ./include/libstage.h ./src/libinput.o
	$(CC) ./src/libstage.c -o libstage.so $(CFLAGS)

libstage.so: ./src/libstage.so
	$(CC) ./src/libstage.o -o libstage.so $(CFLAGS)


code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i examples/*.c
	./.custom-format.py -i examples/*.h
