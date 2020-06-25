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
#include "list.h"

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

// Functions to allocate and deallocate the standard feedback structs

afl_feedback_t * afl_feedback_init(void) {

  afl_feedback_t * feedback = ck_alloc(sizeof(afl_feedback_t));

  feedback->operations = ck_alloc(sizeof(afl_fbck_operations_t));

  return feedback;

}

void afl_feedback_deinit(afl_feedback_t * feedback) {

  ck_free(feedback->operations);
  ck_free(feedback);

}

/* This is the primary function for the entire library, for each executor, we
would pass it to this function which start fuzzing it, something similar to what
afl_fuzz's main function does.
This will be the entrypoint of a new thread when it is created (for each
executor instance).*/
u8 fuzz_start(afl_executor_t *executor, afl_feedback_t * feedback) {

  while (1) {

    // Pre input writing stuff, probably mutations, feedback stuff etc.

    u8 * mem; //Mutated data we want to fuzz with.
    size_t len; //Length of mutated data

    if (!executor->executor_ops->place_inputs_cb) return AFL_PLACE_INPUT_MISSING;
    
    executor->executor_ops->place_inputs_cb(executor, mem, len);

    // Pre run clean up for the observation channels
    LIST_FOREACH(&executor->observors, struct afl_observation_channel , {
      if (el->operations->pre_run_call)
        el->operations->pre_run_call(el);
    });

    executor->executor_ops->run_target_cb(executor, 0, NULL);
    
    // Post run call of the observation channel...
    // TODO: Should this be done after feedback reduction or before??
    LIST_FOREACH(&executor->observors, struct afl_observation_channel , {
      if (el->operations->post_run_call)
        el->operations->post_run_call(el);
    });

    // Feedback functions called now.

    // Based on above steps, we calculate the previous value and proposed value for the queue feedback.
    u64 prev_value, proposed_value; //Arguments for the feedback reducer call

    if (feedback->operations->reducer_function)
      feedback->operations->reducer_function(feedback, prev_value, proposed_value);

    // Scheduler functions for the queues run after this.

  }

}

