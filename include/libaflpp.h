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
#include "lib-common.h"
#include <types.h>

/*
This is the generic interface implementation for the queue and queue entries.
We've tried to keep it generic and yet including, but if you want to extend the
queue/entry, simply "inherit" this struct by including it in your custom struct
and keeping it as the first member of your struct.
*/
typedef struct afl_queue_entry {

  u8 *file_name;
  u32 len;

  struct afl_queue_entry *next_queue_entry;

} afl_queue_entry_t;

typedef struct afl_queue {

  struct afl_queue_entry *queue_top;      // Top entry of queue
  struct afl_queue_entry *queue_current;  // Current entry of queue

  struct afl_executor
      *executor; /* Executor this queue belongs to, one executor can have many
                    queues, thus the mapping is done in the queue itself. */

  // Function pointers specific to the queue
  struct afl_queue_operations *queue_ops;

} afl_queue_t;

typedef struct afl_queue_operations {

  void (*init_queue_entry)(struct afl_queue_entry *entry);
  void (*destroy_queue_entry)(struct afl_queue_entry *entry);

} afl_queue_operations_t;

afl_queue_t *afl_queue_init();           /* Function to initialize the queue*/
void afl_queue_deinit(afl_queue_t *); /* Function to destroy the given queue*/

/*
This is the generic forkserver interface that we have, in order to use the
library to build something, agin "inherit" from this struct (yes, we'll be
trying OO design principles here :D) and then extend adding your own fields to
it. See the example forksever executor that we have in examples/
*/

typedef struct afl_executor {

  list_t observors;  // This will be swapped for the observation channel once
                     // its ready

  afl_queue_entry_t *current_input;  // Holds current input for the executor

  struct afl_executor_operations *executor_ops;  // afl executor_ops;

} afl_executor_t;

// This is like the generic vtable for the executor.

typedef struct afl_executor_operations {

  u8 (*init_cb)(afl_executor_t *, void *);  // can be NULL
  u8 (*destroy_cb)(afl_executor_t *);       // can be NULL

  u8 (*run_target_cb)(afl_executor_t *, u32,
                      void *);  // Similar to afl_fsrv_run_target we have in afl
  u8 (*place_input_cb)(
      afl_executor_t *, u8 *,
      size_t);  // similar to the write_to_testcase function in afl.

} afl_executor_operations_t;

list_t afl_executor_list;  // We'll be maintaining a list of executors.

afl_executor_t *afl_executor_init();
void            afl_executor_deinit(afl_executor_t *);

/*
This is the interface for the observation channel for the library. To get the gist of it,
it resembles the bitmap in original AFL.
*/

typedef struct afl_observation_channel {

  afl_queue_t * queue;        // Each observation channel is connected to a queue, for which it collects data to send to a feedback.
  void * interface;           /* A void pointer to keep the interface (can be a shared map, or something else, anything) generic. 
                                 TODO: Better ideas for this, guys?? */

  struct afl_obs_channel_operations_t * operations;

} afl_observation_channel_t;

typedef struct afl_obs_channel_operations {
  u8 (*init_cb)(struct afl_observation_channel*);     // can be NULL
  u8 (*destroy_cb)(struct afl_observation_channel*);  // can be NULL

  u8 (*flush_cb)(struct afl_observation_channel*);    // can be NULL
  u8 (*reset_cb)(struct afl_observation_channel*);    // can be NULL
} afl_obs_channel_operations_t;

/*
The generic interface for the feedback for the observation channel, this channel is queue specifc. 
*/

typedef struct afl_feedback {
  afl_executor_t * executor;  // The execuotr for which feedback is done.
  /*TODO: Should the executor be here? Considering we have the executor specified in the queue itself??*/
  afl_observation_channel_t * obs_channel;  //The observation channel (which contains the queue).

  struct afl_fbck_operations * operations;

} afl_feedback_t;

typedef struct afl_fbck_operations {

  u8 (*init_cb)(struct afl_feedback *); // can be NULL
  u8 (*destroy_cb)(struct afl_feedback *); // can be NULL

  u64 (*reducer_function)(u64, u64); // new_value = reducer(old_value, proposed_value)
  s32 (*is_interesting_cb)(struct afl_executor*); // returns rate

} afl_fbck_operations_t ;


void fuzz_start(afl_executor_t *);

