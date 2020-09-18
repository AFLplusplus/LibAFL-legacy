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

   This is the actual code for the library framework.

 */

#include <signal.h>

#include "executor/forkserver.h"

/* Function to simple initialize the forkserver */
afl_forkserver_t *fsrv_init(char *target_path, char **target_args) {

  afl_forkserver_t *fsrv = calloc(1, sizeof(afl_forkserver_t));
  if (!fsrv) { return NULL; }

  if (afl_executor_init(&(fsrv->base))) {

    free(fsrv);
    return NULL;

  }

  /* defining standard functions for the forkserver vtable */
  fsrv->base.funcs.init_cb = fsrv_start;
  fsrv->base.funcs.place_input_cb = fsrv_place_input;
  fsrv->base.funcs.run_target_cb = fsrv_run_target;
  fsrv->use_stdin = 1;

  fsrv->target_path = target_path;
  fsrv->target_args = target_args;
  fsrv->out_file = calloc(1, 50);
  snprintf(fsrv->out_file, 50, "out-%d", rand());

  char **target_args_copy = target_args;
  while (*target_args_copy != NULL) {

    if (!strcmp(*target_args_copy, "@@")) {

      fsrv->use_stdin = 0;
      *target_args_copy = fsrv->out_file;  // Replace @@ with the output file name
      break;

    }

    target_args_copy++;

  }

  /* FD for the stdin of the child process */
  if (fsrv->use_stdin) {

    if (!fsrv->out_file) {

      fsrv->out_fd = -1;

    } else {

      fsrv->out_fd = open((char *)fsrv->out_file, O_WRONLY | O_CREAT, 0600);
      if (!fsrv->out_fd) {

        afl_executor_deinit(&fsrv->base);
        free(fsrv);
        return NULL;

      }

    }

  }

  fsrv->out_dir_fd = -1;

  fsrv->dev_null_fd = open("/dev/null", O_WRONLY);
  if (!fsrv->dev_null_fd) {

    close(fsrv->out_fd);
    afl_executor_deinit(&fsrv->base);
    free(fsrv);
    return NULL;

  }

  /* exec related stuff */
  fsrv->child_pid = -1;
  fsrv->exec_tmout = 0;                                                                  /* Default exec time in ms */

  return fsrv;

}

/* This function starts up the forkserver for further process requests */
afl_ret_t fsrv_start(afl_executor_t *fsrv_executor) {

  afl_forkserver_t *fsrv = (afl_forkserver_t *)fsrv_executor;

  int st_pipe[2], ctl_pipe[2];
  s32 status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) { return AFL_RET_ERRNO; }

  fsrv->last_run_timed_out = 0;
  fsrv->fsrv_pid = fork();

  if (fsrv->fsrv_pid < 0) { return AFL_RET_ERRNO; }

  if (!fsrv->fsrv_pid) {

    /* CHILD PROCESS */

    setsid();

    if (fsrv->use_stdin) {

      fsrv->out_fd = open((char *)fsrv->out_file, O_RDONLY | O_CREAT, 0600);
      if (!fsrv->out_fd) { PFATAL("Could not open outfile in child"); }

      dup2(fsrv->out_fd, 0);
      close(fsrv->out_fd);

    }

    dup2(fsrv->dev_null_fd, 1);
    dup2(fsrv->dev_null_fd, 2);

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) { PFATAL("dup2() failed"); }
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) { PFATAL("dup2() failed"); }

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    execv(fsrv->target_path, fsrv->target_args);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    fsrv->trace_bits = (u8 *)0xdeadbeef;
    fprintf(stderr, "Error: execv to target failed\n");
    exit(0);

  }

  /* PARENT PROCESS */

  char pid_buf[16];
  sprintf(pid_buf, "%d", fsrv->fsrv_pid);
  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv->fsrv_ctl_fd = ctl_pipe[1];
  fsrv->fsrv_st_fd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  rlen = 0;
  if (fsrv->exec_tmout) {

    u32 time_ms = afl_read_s32_timed(fsrv->fsrv_st_fd, &status, fsrv->exec_tmout * FORK_WAIT_MULT);

    if (!time_ms) {

      kill(fsrv->fsrv_pid, SIGKILL);

    } else if (time_ms > fsrv->exec_tmout * FORK_WAIT_MULT) {

      fsrv->last_run_timed_out = 1;
      kill(fsrv->fsrv_pid, SIGKILL);

    } else {

      rlen = 4;

    }

  } else {

    rlen = read(fsrv->fsrv_st_fd, &status, 4);

  }

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {

    OKF("All right - fork server is up.");
    return AFL_RET_SUCCESS;

  }

  if (fsrv->trace_bits == (u8 *)0xdeadbeef) {

    WARNF("Unable to execute target application ('%s')", fsrv->target_args[0]);
    return AFL_RET_EXEC_ERROR;

  }

  WARNF("Fork server handshake failed");
  return AFL_RET_BROKEN_TARGET;

}

/* Places input in the executor for the target */
u8 fsrv_place_input(afl_executor_t *fsrv_executor, afl_input_t *input) {

  afl_forkserver_t *fsrv = (afl_forkserver_t *)fsrv_executor;

  if (!fsrv->use_stdin) { fsrv->out_fd = open(fsrv->out_file, O_RDWR | O_CREAT | O_EXCL, 00600); }

  ssize_t write_len = write(fsrv->out_fd, input->bytes, input->len);

  if (write_len < 0 || (size_t)write_len != input->len) { FATAL("Short Write"); }

  fsrv->base.current_input = input;

  if (!fsrv->use_stdin) { close(fsrv->out_fd); }

  return write_len;

}

/* Execute target application. Return status
   information.*/
afl_exit_t fsrv_run_target(afl_executor_t *fsrv_executor) {

  afl_forkserver_t *fsrv = (afl_forkserver_t *)fsrv_executor;

  s32 res;
  u32 exec_ms;
  u32 write_value = fsrv->last_run_timed_out;

  /* After this memset, fsrv->trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  // memset(fsrv->trace_bits, 0, fsrv->map_size);

  MEM_BARRIER();

  /* we have the fork server (or faux server) up and running
  First, tell it if the previous run timed out. */

  if ((res = write(fsrv->fsrv_ctl_fd, &write_value, 4)) != 4) {

    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  fsrv->last_run_timed_out = 0;

  if ((res = read(fsrv->fsrv_st_fd, &fsrv->child_pid, 4)) != 4) {

    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  if (fsrv->child_pid <= 0) { FATAL("Fork server is misbehaving (OOM?)"); }

  exec_ms = afl_read_s32_timed(fsrv->fsrv_st_fd, &fsrv->child_status, fsrv->exec_tmout);

  if (exec_ms > fsrv->exec_tmout) {

    /* If there was no response from forkserver after timeout seconds,
    we kill the child. The forkserver should inform us afterwards */

    kill(fsrv->child_pid, SIGKILL);
    fsrv->last_run_timed_out = 1;
    if (read(fsrv->fsrv_st_fd, &fsrv->child_status, 4) < 4) { exec_ms = 0; }

  }

  if (!exec_ms) {}

  if (!WIFSTOPPED(fsrv->child_status)) { fsrv->child_pid = 0; }

  fsrv->total_execs++;
  if (!fsrv->use_stdin) { unlink(fsrv->out_file); }

  /* Any subsequent operations on fsrv->trace_bits must not be moved by the
     compiler below this point. Past this location, fsrv->trace_bits[]
     behave very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  /* Report outcome to caller. */

  if (WIFSIGNALED(fsrv->child_status)) {

    fsrv->last_kill_signal = WTERMSIG(fsrv->child_status);

    if (fsrv->last_run_timed_out && fsrv->last_kill_signal == SIGKILL) { return AFL_EXIT_TIMEOUT; }

    return AFL_EXIT_CRASH;

  }

  return AFL_EXIT_OK;

}
