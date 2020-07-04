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
#include "lib-obserationchannel.h"
#include "libinput.h"
#include <types.h>

/*
This is the generic forkserver interface that we have, in order to use the
library to build something, agin "inherit" from this struct (yes, we'll be
trying OO design principles here :D) and then extend adding your own fields to
it. See the example forksever executor that we have in examples/
*/

typedef struct executor {

  list_t observors;  // This will be swapped for the observation channel once
                     // its ready

  raw_input_t *current_input;  // Holds current input for the executor

  struct executor_operations *executor_ops;  // afl executor_ops;

} executor_t;

// This is like the generic vtable for the executor.

struct executor_operations {

  u8 (*init_cb)(executor_t *, void *);  // can be NULL
  u8 (*destroy_cb)(executor_t *);       // can be NULL

  u8 (*run_target_cb)(executor_t *, u32,
                      void *);  // Similar to afl_fsrv_run_target we have in afl
  u8 (*place_inputs_cb)(
      executor_t *, u8 *,
      size_t);  // similar to the write_to_testcase function in afl.

  list_t (*get_observation_channels)(
      executor_t *);  // Getter function for observation channels list

  u8 (*add_observation_channel)(
      executor_t *, struct afl_observation_channel
                            *);  // Add an observtion channel to the list

  raw_input_t *(*get_current_input)(
      executor_t *);  // Getter function for the current input

};

list_t afl_executor_list;  // We'll be maintaining a list of executors.

executor_t *afl_executor_init();
void            afl_executor_deinit(executor_t *);
u8              _add_observation_channel_(executor_t *, void *);
list_t          _get_observation_channels_(executor_t *);
raw_input_t *   _get_current_input_(executor_t *);

/*
The generic interface for the feedback for the observation channel, this channel
is queue specifc.
*/


u8 fuzz_start(executor_t *);

enum {

  ALL_OK,                  // 0
  AFL_PLACE_INPUT_MISSING  // 1

};

