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

#ifndef AFLPP_H
#define AFLPP_H

#include <types.h>

#include "common.h"
#include "config.h"
#include "observer.h"
#include "input.h"
#include "mutator.h"
#include "queue.h"
#include "engine.h"
#include "fuzzone.h"
#include "feedback.h"
#include "stage.h"
#include "os.h"
#include "afl-returns.h"

/*
This is the generic forkserver interface that we have, in order to use the
library to build something, agin "inherit" from this struct (yes, we'll be
trying OO design principles here :D) and then extend adding your own fields to
it. See the example forksever executor that we have in examples/
*/

struct afl_executor_funcs {
  afl_ret_t (*init_cb)(afl_executor_t *);  // can be NULL
  u8 (*destroy_cb)(afl_executor_t *);      // can be NULL

  afl_exit_t (*run_target_cb)(afl_executor_t *);              // Similar to afl_fsrv_run_target we have in afl
  u8 (*place_input_cb)(afl_executor_t *, afl_input_t *);  // similar to the write_to_testcase function in afl.

  afl_observer_t *(*observers_get)(afl_executor_t *, size_t);  // Getter function for observation channels list

  afl_ret_t (*observer_add)(afl_executor_t *, afl_observer_t *);  // Add an observtion channel to the list

  afl_input_t *(*input_get)(afl_executor_t *);  // Getter function for the current input

  void (*observers_reset)(afl_executor_t *);  // Reset the observation channels
};

// This is like the generic vtable for the executor.

struct afl_executor {
  afl_observer_t **observors;  // This will be swapped for the observation channel once its ready

  u32 observors_count;

  afl_input_t *current_input;  // Holds current input for the executor

  struct afl_executor_funcs funcs;  // afl executor_ops;
};

afl_ret_t        afl_executor_init(afl_executor_t *);
void             afl_executor_deinit(afl_executor_t *);
afl_ret_t        afl_observer_add_default(afl_executor_t *, afl_observer_t *);
afl_observer_t * afl_get_observers_default(afl_executor_t *, size_t);
afl_input_t *afl_current_input_get_default(afl_executor_t *);
void             afl_observers_reset_default(afl_executor_t *);

// Function used to create an executor, we alloc the memory ourselves and
// initialize the executor

AFL_NEW_AND_DELETE_FOR(afl_executor)

/* Forkserver executor */
typedef struct afl_forkserver {
  afl_executor_t base; /* executer struct to inherit from */

  u8 *trace_bits; /* SHM with instrumentation bitmap  */
  u8  use_stdin;  /* use stdin for sending data       */

  s32 fsrv_pid,     /* PID of the fork server           */
      child_pid,    /* PID of the fuzzed program        */
      child_status, /* waitpid result for the child     */
      out_dir_fd,   /* FD of the lock file              */
      dev_null_fd;

  s32 out_fd, /* Persistent fd for fsrv->out_file */

      fsrv_ctl_fd, /* Fork server control pipe (write) */
      fsrv_st_fd;  /* Fork server status pipe (read)   */

  u32 exec_tmout; /* Configurable exec timeout (ms)   */
  u32 map_size;   /* map size used by the target      */

  u64 total_execs; /* How often fsrv_run_target was called */

  char *out_file,   /* File to fuzz, if any             */
      *target_path; /* Path of the target               */

  char **target_args;

  u32 last_run_timed_out; /* Traced process timed out?        */

  u8 last_kill_signal; /* Signal that killed the child     */

} afl_forkserver_t;

/* Functions related to the forkserver defined above */
afl_forkserver_t *fsrv_init(char *target_path, char **extra_target_args);
afl_exit_t        fsrv_run_target(afl_executor_t *fsrv_executor);
u8                fsrv_place_input(afl_executor_t *fsrv_executor, afl_input_t *input);
afl_ret_t         fsrv_start(afl_executor_t *fsrv_executor);

/* In-memory executor */

/* Function ptr for the harness */
typedef afl_exit_t (*harness_function_type)(afl_executor_t *executor, u8 *, size_t);

typedef struct in_memeory_executor {
  afl_executor_t        base;
  harness_function_type harness;
  char **               argv;  // These are to support the libfuzzer harnesses
  int                   argc;  // To support libfuzzer harnesses

} in_memory_executor_t;

afl_exit_t in_memory_run_target(afl_executor_t *executor);
u8         in_mem_executor_place_input(afl_executor_t *executor, afl_input_t *input);
void       in_memory_executor_init(in_memory_executor_t *in_memeory_executor, harness_function_type harness);

#endif
