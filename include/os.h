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

afl_ret_t dump_crash_to_file(afl_input_t *, afl_engine_t *);  // This function dumps an input which causes a
                                                                  // crash in the target to a crash file

/* TODO: Add implementations for installing crash handlers */
typedef void (*afl_crash_handler_func)(afl_exit_t type, void *data);

void install_crash_handler(afl_crash_handler_func callback);

typedef enum fork_result { FORK_FAILED, CHILD, PARENT } fork_result_t;

typedef struct process {

  struct process *(*current)(struct process *);
  fork_result_t (*fork)(struct process *);
  void (*suspend)(struct process *);
  void (*resume)(struct process *);
  afl_exit_t (*wait)(struct process *, bool untraced);

  pid_t handler_process;  // Something similar to the child process

} process_t;

void _afl_process_init_internal(process_t *);

static inline process_t *afl_process_init(process_t *process, pid_t handler_pid) {

  process_t *new_process;

  if (process) {

    _afl_process_init_internal(process);
    process->handler_process = handler_pid;
    return process;

  }

  else {

    new_process = calloc(1, sizeof(process_t));
    if (!new_process) { return NULL; }
    _afl_process_init_internal(new_process);
    new_process->handler_process = (handler_pid);

  }

  return new_process;

}

process_t *   return_current_default(process_t *);
fork_result_t do_fork_default(process_t *);
void          suspend_default(process_t *);
void          resume_default(process_t *);
afl_exit_t   wait_default(process_t *, bool);

#endif

