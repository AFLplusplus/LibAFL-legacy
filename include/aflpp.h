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

#ifndef LIBAFLPP_H
#define LIBAFLPP_H

#include <types.h>

#include "common.h"
#include "config.h"
#include "observationchannel.h"
#include "input.h"
#include "mutator.h"
#include "queue.h"
#include "engine.h"
#include "fuzzone.h"
#include "feedback.h"
#include "stage.h"
#include "list.h"
#include "os.h"
#include "afl-returns.h"

#define MAX_OBS_CHANNELS 5

/*
This is the generic forkserver interface that we have, in order to use the
library to build something, agin "inherit" from this struct (yes, we'll be
trying OO design principles here :D) and then extend adding your own fields to
it. See the example forksever executor that we have in examples/
*/

struct executor_functions {

  afl_ret_t (*init_cb)(executor_t *);  // can be NULL
  u8 (*destroy_cb)(executor_t *);      // can be NULL

  exit_type_t (*run_target_cb)(
      executor_t *);  // Similar to afl_fsrv_run_target we have in afl
  u8 (*place_input_cb)(
      executor_t *,
      raw_input_t *);  // similar to the write_to_testcase function in afl.

  observation_channel_t *(*get_observation_channels)(
      executor_t *, size_t);  // Getter function for observation channels list

  u8 (*add_observation_channel)(
      executor_t *,
      observation_channel_t *);  // Add an observtion channel to the list

  raw_input_t *(*get_current_input)(
      executor_t *);  // Getter function for the current input

  void (*reset_observation_channels)(
      executor_t *);  // Reset the observation channels

};

// This is like the generic vtable for the executor.

struct executor {

  observation_channel_t
      *observors[MAX_OBS_CHANNELS];  // This will be swapped for the observation
                                     // channel once its ready

  u32 observors_num;

  raw_input_t *current_input;  // Holds current input for the executor

  struct executor_functions funcs;  // afl executor_ops;

};

list_t afl_executor_list;  // We'll be maintaining a list of executors.

afl_ret_t afl_executor_init(executor_t *);
void      afl_executor_deinit(executor_t *);
u8 afl_add_observation_channel_default(executor_t *, observation_channel_t *);
observation_channel_t *afl_get_observation_channels_default(executor_t *,
                                                            size_t);
raw_input_t *          afl_get_current_input_default(executor_t *);
void                   afl_reset_observation_channel_default(executor_t *);

// Function used to create an executor, we alloc the memory ourselves and
// initialize the executor

static inline executor_t *afl_executor_create() {

  executor_t *new_executor = calloc(1, sizeof(executor_t));
  if (!new_executor) { return NULL; }
  if (afl_executor_init(new_executor) != AFL_RET_SUCCESS) {

    free(new_executor);
    return NULL;

  }

  return new_executor;

}

static inline void afl_executor_delete(executor_t *executor) {

  afl_executor_deinit(executor);
  free(executor);

}

/* Forkserver executor */
typedef struct afl_forkserver {

  executor_t base;                       /* executer struct to inherit from */

  u8 *trace_bits;                       /* SHM with instrumentation bitmap  */
  u8  use_stdin;                        /* use stdin for sending data       */

  s32 fsrv_pid,                         /* PID of the fork server           */
      child_pid,                        /* PID of the fuzzed program        */
      child_status,                     /* waitpid result for the child     */
      out_dir_fd,                       /* FD of the lock file              */
      dev_null_fd;

  s32 out_fd,                           /* Persistent fd for fsrv->out_file */

      fsrv_ctl_fd,                      /* Fork server control pipe (write) */
      fsrv_st_fd;                       /* Fork server status pipe (read)   */

  u32 exec_tmout;                       /* Configurable exec timeout (ms)   */
  u32 map_size;                         /* map size used by the target      */

  u64 total_execs;                      /* How often fsrv_run_target was called */

  char *out_file,                       /* File to fuzz, if any             */
      *target_path;                     /* Path of the target               */

  char **target_args;

  u32 last_run_timed_out;               /* Traced process timed out?        */

  u8 last_kill_signal;                  /* Signal that killed the child     */

} afl_forkserver_t;

/* Functions related to the forkserver defined above */
afl_forkserver_t *fsrv_init(char *target_path, char **extra_target_args);
exit_type_t       fsrv_run_target(executor_t *fsrv_executor);
u8 fsrv_place_input(executor_t *fsrv_executor, raw_input_t *input);
afl_ret_t fsrv_start(executor_t *fsrv_executor);


/* In-memory executor */

/* Function ptr for the harness */
typedef exit_type_t (*harness_function_type)(u8* data, size_t size);

typedef struct in_memeory_executor {
    
    executor_t base;
    harness_function_type harness;

} in_memeory_executor_t;

exit_type_t in_memory_run_target(executor_t * executor);
u8 in_mem_executor_place_input(executor_t * executor, raw_input_t * input);
exit_type_t in_memory_run_target(executor_t * executor);
void in_memory_exeutor_init(in_memeory_executor_t * in_memeory_executor, harness_function_type harness);

#endif

