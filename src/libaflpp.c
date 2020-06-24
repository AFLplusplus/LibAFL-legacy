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

   This the actual code for the library framework.

 */

#include "libaflpp.h"

afl_queue_t * afl_queue_init() {

  afl_queue_t *queue = ck_alloc(sizeof(afl_queue_t));

  queue->queue_current = NULL;
  queue->queue_top = NULL;

  queue->executor = NULL;
  afl_queue_operations_t *queue_ops = ck_alloc(sizeof(afl_queue_operations_t));

  queue->queue_ops = queue_ops;

  return queue;

}

void afl_queue_deinit(afl_queue_t *queue) {

  struct afl_queue_entry *current;

  current = queue->queue_top;
  if (!current) FATAL("The queue is empty, cannot deinit");

  // Free each entry present in the queue.
  while (current) {

    struct afl_queue_entry *temp = current->next_queue_entry;

    ck_free(current);
    current = temp;

  }

  ck_free(queue);  // Free the queue itself now.

  SAYF("queue has been deinited");

}

afl_executor_t *afl_executor_init() {

  afl_executor_t *executor = ck_alloc(sizeof(afl_executor_t));

  executor->current_input = NULL;

  // These function pointers can be given a default forkserver pointer here when
  // it is ported, thoughts?
  struct afl_executor_operations *executor_ops =
      ck_alloc(sizeof(struct afl_executor_operations));
  executor->executor_ops = executor_ops;

  return executor;

}

void afl_executor_deinit(afl_executor_t *executor) {

  if (!executor) FATAL("Cannot free a NULL pointer");

  ck_free(executor);

}

// Functions to allocate and deallocate the standard observation channel struct
afl_observation_channel_t * afl_observation_init(void) {

  afl_observation_channel_t * obs_channel = ck_alloc(sizeof(afl_observation_channel_t));

  obs_channel->operations = ck_alloc(sizeof(afl_obs_channel_operations_t));

  return obs_channel;
}

void afl_observation_deinit(afl_observation_channel_t * obs_channel) {
  ck_free(obs_channel->operations);
  ck_free(obs_channel);
}

/* This is the primary function for the entire library, for each executor, we
would pass it to this function which start fuzzing it, something similar to what
afl_fuzz's main function does.
This will be the entrypoint of a new thread when it is created (for each
executor instance).*/
void fuzz_start(afl_executor_t *executor) {

  while (1) {

    // Pre input writing stuff, probably mutations, feedback stuff etc.

    // Still need a bit of work before we can pass the extra arguments to the
    // virtual functions
    if (executor->executor_ops->place_inputs_cb)
      executor->executor_ops->place_inputs_cb(executor, NULL, 0);

    executor->executor_ops->run_target_cb(executor, 0, NULL);

    // Post run functions, writing results to the "feedback", or whatever afl
    // does right now.

  }

}

