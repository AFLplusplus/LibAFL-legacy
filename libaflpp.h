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

typedef struct afl_executor {
    // TODO
} afl_executor;

struct afl_queue_entry {

    u8 * file_name;
    u32 len;

    struct afl_queue_entry * next_queue_entry;

};

typedef struct afl_queue {

    struct afl_queue_entry * queue_top;    // Top entry of queue
    struct afl_queue_entry * queue_current;    // Current entry of queue

    afl_executor * executor;    // Executor this queue belongs too. 
        // We don't plan to share the testcases among executors

    // Function pointers specific to the queue

    void (*init_queue_entry)(struct afl_queue_entry * entry);
    void (*destroy_queue_entry)(struct afl_queue_entry * entry);

} afl_queue;

afl_queue * afl_queue_init();
void afl_queue_deinit(afl_queue * queue);
