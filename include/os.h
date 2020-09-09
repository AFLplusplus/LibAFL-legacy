#ifndef LIBOS_H
#define LIBOS_H

#include "common.h"
#include "input.h"

#include <stdbool.h>
#include <sys/types.h>
// This has a few parts, the first deals with crashe handling.
typedef enum exit_type {

  NORMAL,
  STOP,
  CRASH,
  SEGV,
  BUS,
  ABRT,
  ILL,
  FPE,
  TIMEOUT,
  OOM,

} exit_type_t;

afl_ret_t dump_crash_to_file(raw_input_t *, engine_t *);  // This function dumps an input which causes a
                                                          // crash in the target to a crash file

/* TODO: Add implementations for installing crash handlers */
typedef void (*crash_handler_function)(exit_type_t type, void *data);

void install_crash_handler(crash_handler_function callback);

typedef enum fork_result { FORK_FAILED, CHILD, PARENT } fork_result_t;

typedef struct process {

  struct process *(*current)(struct process *);
  fork_result_t (*fork)(struct process *);
  void (*suspend)(struct process *);
  void (*resume)(struct process *);
  exit_type_t (*wait)(struct process *, bool untraced);

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
exit_type_t   wait_default(process_t *, bool);

#endif

