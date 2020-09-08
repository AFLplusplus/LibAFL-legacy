# LibAFL Examples

This folder contains all examples we curated so far.

# `forking-fuzzer.c`
To run the main one, a multi-threaded AFL++ clone, run `make test`. This will get aflpp (for its compilers), compile `target.c`, build the lib, then build and run `executor.c`, the actual fuzzer.

# `in-memory-fuzzer.c`
The build tis example, run make the lib (`make -C ..`) then `make-in-mem-fuzzer`. Then, run `LD_LIBRARY_PATH=.. ./in-mem`.
This will run the (commited, we are sorry) `libpng.a` with an in-memory executor.

# `llmp-main`
Not really a fuzzer, but merely a test for fast, lock-free multiprocessing.
Using `make llmp-main`, you can build a multiprocess example. Afterwards, you can run one broker with `LD_LIBRARY_PATH=.. ./llmp-main main [threadnum]` and spawn additinal out-of-process workers using `LD_LIBRARY_PATH=.. ./llmp-main worker`.