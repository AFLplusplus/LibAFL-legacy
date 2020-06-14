/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */

#include "afl-fuzz.h"
#include <types.h>

/*
This is the generic forkserver interface that we have, in order to use the library to build something,
"inherit" from this struct (yes, we'll be trying OO design principles here :D) and then extend adding your own
fields to it.
*/

typedef struct afl_queue_entry {

    u8 * file_name;
    u32 len;

    struct afl_queue_entry * next_queue_entry;

} afl_queue_entry_t ;

typedef struct afl_executor {
    list_t observors;    // This will be swapped for the observation channel once its ready

    afl_queue_entry_t * current_input;  //Holds current input for the executor

    struct afl_executor_operation * executor_ops; // afl executor_ops;

} afl_executor_t;


typedef struct afl_executor_operation {
    u8 (*init_cb)(afl_executor_t *, void *); // can be NULL
    u8 (*destroy_cb)(afl_executor_t *); // can be NULL

    u8 (*run_target_cb)(afl_executor_t *, u32 , void *);  //Similar to afl_fsrv_run_target we have in afl
    u8 (*place_input_cb)(afl_executor_t *, u8 * buf, size_t len); //similar to the write_to_testcase function in afl.
} afl_executor_operations_t;


// This is like the generic vtable for the executor.

list_t afl_executor_list;


typedef struct afl_queue {

    struct afl_queue_entry * queue_top;    // Top entry of queue
    struct afl_queue_entry * queue_current;    // Current entry of queue

    afl_executor_t * executor;    // Executor this queue belongs too. 
        // We don't plan to share the testcases among executors

    // Function pointers specific to the queue

    void (*init_queue_entry)(struct afl_queue_entry * entry);
    void (*destroy_queue_entry)(struct afl_queue_entry * entry);

} afl_queue_t;

afl_queue_t * afl_queue_init();
void afl_queue_deinit(afl_queue_t *);



// A generic sharememory region to be used by any functions (queues or feedbacks too.)

typedef struct afl_sharedmem {
    #ifdef USEMMAP
        int g_shm_id;
        char g_shm_fname[L_tmpnam];
    #else
        int shm_id;
    #endif

    u8 * map;
    ssize_t map_size;

} afl_sharedmem_t;

// Functions to create Shared memory region, for feedback and opening inputs and stuff.
u8 * afl_sharedmem_init(afl_sharedmem_t *, size_t);
void afl_sharedmem_deinit(afl_sharedmem_t *);

void fuzz_start(afl_executor_t *);
afl_executor_t * afl_executor_init();
void afl_executor_deinit(afl_executor_t *);
