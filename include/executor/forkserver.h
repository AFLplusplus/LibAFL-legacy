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

#ifndef LIBAFL_EXECUTOR_FORKSERVER_H
#define LIBAFL_EXECUTOR_FORKSERVER_H

#include "executor.h"

/* Forkserver executor */
typedef struct afl_forkserver {

  afl_executor_t base;                                                           /* executer struct to inherit from */

  u8 *trace_bits;                                                               /* SHM with instrumentation bitmap  */
  u8  use_stdin;                                                                /* use stdin for sending data       */

  s32 fsrv_pid,                                                                 /* PID of the fork server           */
      child_pid,                                                                /* PID of the fuzzed program        */
      child_status,                                                             /* waitpid result for the child     */
      out_dir_fd,                                                               /* FD of the lock file              */
      dev_null_fd;

  s32 out_fd,                                                                   /* Persistent fd for fsrv->out_file */

      fsrv_ctl_fd,                                                              /* Fork server control pipe (write) */
      fsrv_st_fd;                                                               /* Fork server status pipe (read)   */

  u32 exec_tmout;                                                               /* Configurable exec timeout (ms)   */
  u32 map_size;                                                                 /* map size used by the target      */

  u64 total_execs;                                                              /* How often run_target was called  */

  char *out_file,                                                               /* File to fuzz, if any             */
      *target_path;                                                             /* Path of the target               */

  char **target_args;

  u32 last_run_timed_out;                                                       /* Traced process timed out?        */
  u32 last_run_time;                                                            /* Time this exec took to execute   */

  u8 last_kill_signal;                                                          /* Signal that killed the child     */

} afl_forkserver_t;

// TODO rename to afl_forkserver_init etc. names must be coherent

/* Functions related to the forkserver defined above */
afl_forkserver_t *fsrv_init(char *target_path, char **extra_target_args);
afl_exit_t        fsrv_run_target(afl_executor_t *fsrv_executor);
u8                fsrv_place_input(afl_executor_t *fsrv_executor, afl_input_t *input);
afl_ret_t         fsrv_start(afl_executor_t *fsrv_executor);

#endif
