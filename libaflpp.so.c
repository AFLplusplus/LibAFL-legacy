/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This the actual coded for the library framework.

 */

#include "libaflpp.h"

afl_queue * afl_queue_init() {
    afl_queue * queue = ck_alloc(sizeof(afl_queue));

    queue->queue_current = NULL;
    queue->queue_top = NULL;

    queue->executor = NULL;
    queue->destroy_queue_entry = NULL;
    queue->init_queue_entry = NULL;
}

void afl_queue_deinit(afl_queue * queue) {

    struct afl_queue_entry * current;

    current = queue->queue_top;
    if (!current) FATAL("The queue is empty, cannot deinit");

    // Free each entry present in the queue.
    while (current) {
        struct afl_queue_entry * temp = current->next_queue_entry;

        ck_free(current);
        current = temp;
    }

    ck_free(queue); // Free the queue itself now.

    SAYF("queue has been deinited");

}

