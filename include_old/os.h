#ifndef LIBOS_H
#define LIBOS_H

#include "common.h"
#include "input.h"

#include <stdbool.h>
#include <sys/types.h>

// This has a few parts, the first deals with crash handling.

/* afl_exit_t is for the fuzzed target, as opposed to afl_ret_t
which is for internal functions. */
typedef enum afl_exit {

  AFL_EXIT_OK,
  AFL_EXIT_STOP,
  AFL_EXIT_CRASH,
  AFL_EXIT_SEGV,
  AFL_EXIT_BUS,
  AFL_EXIT_ABRT,
  AFL_EXIT_ILL,
  AFL_EXIT_FPE,
  AFL_EXIT_TIMEOUT,
  AFL_EXIT_OOM,

} afl_exit_t;

/* TODO: Add implementations for installing crash handlers */
typedef void (*afl_crash_handler_func)(afl_exit_t type, void *data);

void install_crash_handler(afl_crash_handler_func callback);

typedef enum afl_fork_result { FORK_FAILED, CHILD, PARENT } afl_fork_result_t;

typedef struct afl_os {

  struct afl_os *(*current)(struct afl_os *);
  afl_fork_result_t (*fork)(struct afl_os *);
  void (*suspend)(struct afl_os *);
  void (*resume)(struct afl_os *);
  afl_exit_t (*wait)(struct afl_os *, bool untraced);

  pid_t handler_process;  // Something similar to the child process

} afl_os_t;

void _afl_process_init_internal(afl_os_t *);

static inline afl_os_t *afl_process_init(afl_os_t *process, pid_t handler_pid) {

  afl_os_t *new_process;

  if (process) {

    _afl_process_init_internal(process);
    process->handler_process = handler_pid;
    return process;

  }

  else {

    new_process = calloc(1, sizeof(afl_os_t));
    if (!new_process) { return NULL; }
    _afl_process_init_internal(new_process);
    new_process->handler_process = (handler_pid);

  }

  return new_process;

}

afl_fork_result_t afl_proc_fork(afl_os_t *);
void              afl_proc_suspend(afl_os_t *);
void              afl_proc_resume(afl_os_t *);
afl_exit_t        afl_proc_wait(afl_os_t *, bool);

afl_ret_t bind_to_cpu();
/* Run `handle_file` for each file in the dirpath, recursively.
void *data will be passed to handle_file as 2nd param.
if handle_file returns false, further execution stops. */
afl_ret_t afl_for_each_file(char *dirpath, bool (*handle_file)(char *filename, void *data), void *data);

#endif

