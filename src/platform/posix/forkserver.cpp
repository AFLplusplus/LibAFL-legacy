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

#include "executor/forkserver.hpp"
#include "platform/forkserver.hpp"

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>

using namespace afl;

#define FORKSRV_FD 198

/* This function uses select calls to wait on a child process for given
 * timeout_ms milliseconds and kills it if it doesn't terminate by that time */
template <typename IntegerType>
static u32 ReadTimed(s32 fd, IntegerType* buf, u32 timeout_ms) {
  fd_set readfds;
  struct timeval timeout;
  int sret;
  ssize_t len_read;

  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);

  timeout.tv_sec = (timeout_ms / 1000);
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
#if !defined(__linux__)
  u32 read_start = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
#endif

  /* set exceptfds as well to return when a child exited/closed the pipe. */
restart_select:
  sret = select(fd + 1, &readfds, NULL, NULL, &timeout);

  if (likely(sret > 0)) {
  restart_read:
    len_read = read(fd, static_cast<void*>(buf), sizeof(*buf));

    if (likely(len_read == 4)) {  // for speed we put this first

#if defined(__linux__)
      u32 exec_ms = MIN(
          timeout_ms,
          ((u64)timeout_ms - (timeout.tv_sec * 1000 + timeout.tv_usec / 1000)));
#else
      u32 exec_ms = MIN(timeout_ms,
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                                .count() -
                            read_start);
#endif

      // ensure to report 1 ms has passed (0 is an error)
      return exec_ms > 0 ? exec_ms : 1;

    } else if (unlikely(len_read == -1 && errno == EINTR)) {
      goto restart_read;

    } else if (unlikely(len_read < 4)) {
      return 0;
    }

  } else if (unlikely(!sret)) {
    *buf = -1;
    return timeout_ms + 1;

  } else if (unlikely(sret < 0)) {
    if (likely(errno == EINTR))
      goto restart_select;

    *buf = -1;
    return 0;
  }

  return 0;  // not reached
}

ForkServerHelper::ForkServerHelper() {}

Result<void> ForkServerHelper::Start(ForkServerExecutor* executor,
                                     char** argv) {
  int st_pipe[2], ctl_pipe[2];
  s32 status;
  s32 rlen;

  // print spawning forkserver

  if (pipe(st_pipe) || pipe(ctl_pipe))
    return ERR(OSError, errno);

  lastRunTimedOut = false;
  pid = fork();

  if (pid < 0)
    return ERR(OSError, errno);

  if (!pid) {
    /* CHILD PROCESS */

    setsid();

    if (executor->GetInputType() == ForkServerExecutor::InputType::kStdin) {
      outFd = open(outFileName, O_RDONLY | O_CREAT, 0600);
      if (!outFd)
        goto child_error;

      dup2(outFd, 0);
      close(outFd);
    }

    dup2(devNullFd, 1);
    dup2(devNullFd, 2);

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0)
      goto child_error;
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0)
      goto child_error;

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    execv(argv[0], argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

  child_error:
    messagePtr[0] = 0xdeadbeef;
    messagePtr[1] = errno;
    exit(0);
  }

  /* PARENT PROCESS */

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  ctlFd = ctl_pipe[1];
  stFd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  rlen = 0;
  if (executor->GetTimeoutMs()) {
    u32 time_ms = ReadTimed(stFd, &status, executor->GetTimeoutMs());

    if (!time_ms) {
      kill(pid, SIGKILL);

    } else if (time_ms > executor->GetTimeoutMs()) {
      lastRunTimedOut = true;
      kill(pid, SIGKILL);

    } else {
      rlen = 4;
    }

  } else {
    rlen = read(stFd, &status, 4);
  }

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    // OKF("All right - fork server is up.");
    return OK();
  }

  if (messagePtr[0] == 0xdeadbeef) {
    // WARNF("Unable to execute target application ('%s')",
    // fsrv->target_args[0]);
    return ERR(ChildExecutionError, messagePtr[1]);
  }

  // WARNF("Fork server handshake failed");
  return ERR(ChildBrokenError);
}

Result<void> ForkServerHelper::WriteInput(ForkServerExecutor* executor,
                                          u8* buffer,
                                          size_t size) {
  
  // TODO in memory case
  
  if (executor->GetInputType() != ForkServerExecutor::InputType::kStdin) {
    outFd = open(outFileName, O_RDWR | O_CREAT | O_EXCL, 00600);
  }

  ssize_t write_len = write(outFd, buffer, size);

  if (write_len < 0) return ERR(OSError, errno);
  if (write_len != size) return ERR(ShortWriteError, write_len, size);

  if (executor->GetInputType() != ForkServerExecutor::InputType::kStdin) {
    close(outFd);
  }
  
  return OK();
}

Result<ExitType> ForkServerHelper::ExecuteOnce(ForkServerExecutor* executor) {
  
  int res;

  /*
    We have the fork server up and running.
    First, tell it if the previous run timed out.
  */
  
  u32 write_value = static_cast<u32>(lastRunTimedOut);

  if ((res = write(ctlFd, &write_value, 4)) != 4) {

    return ERR(RuntimeError, "Unable to request new process from ForkServer (OOM?)");

  }

  lastRunTimedOut = false;

  if ((res = read(stFd, &pid, 4)) != 4) {

    return ERR(RuntimeError, "Unable to request new process from ForkServer (OOM?)");

  }

  if (pid <= 0) { FATAL("Fork server is misbehaving (OOM?)"); }

  auto timeout_ms = executor->GetTimeoutMs();

  u32 exec_ms = ReadTimed(stFd, &childStatus, timeout_ms);

  if (exec_ms > timeout_ms) {

    /* If there was no response from forkserver after timeout seconds,
    we kill the child. The forkserver should inform us afterwards */

    kill(pid, SIGKILL);
    lastRunTimedOut = true;
    if (read(stFd, &childStatus, 4) < 4) { exec_ms = 0; }

  }

  if (!exec_ms) {}

  if (!WIFSTOPPED(childStatus)) { pid = 0; }

  if (executor->GetInputType() != ForkServerExecutor::InputType::kStdin) {
    unlink(outFileName);
  }

  /* Report outcome to caller. */

  if (WIFSIGNALED(childStatus)) {

    lastKillSignal = WTERMSIG(childStatus);

    if (lastRunTimedOut && lastKillSignal == SIGKILL) return ExitType::kTimeOut;

    return ExitType::kCrash;

  }

  return ExitType::kOk;
}
