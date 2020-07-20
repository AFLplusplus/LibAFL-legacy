#include "libcommon.h"
#include "libinput.h"

#include <stdbool.h>
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

void dump_crash_to_file(exit_type_t, raw_input_t *); //This function dumps an input which causes a crash in the target to a crash file

/* TODO: Add implementations for installing crash handlers */
typedef void (*crash_handler_function)(exit_type_t type, void* data);

void install_crash_handler(crash_handler_function callback);

crash_handler_function crash_callback;


typedef enum fork_result {
  FORK_FAILED,
  CHILD,
  PARENT
} fork_result_t;

typedef struct process {

  struct process * (*current)(struct process *);
  fork_result_t (*fork)(struct process *);
  void (*suspend)(struct process *);
  void (*resume)(struct process *);
  exit_type_t (*wait)(struct process *, bool untraced);

  void * handler_process;  // "handler" pid or the process which spawned this one

} process_t;

void afl_process_init(process_t *);


static inline process_t * AFL_PROCESS_INIT(process_t * process, pid_t handler_pid) {

  process_t * new_process;

  if (process) {
    afl_process_init(process);
    process->handler_process = (void *)(intptr_t)(handler_pid);
    return process;
  }

  else {
    new_process = ck_alloc(sizeof(process_t));
    afl_process_init(new_process);
    new_process->handler_process = (void *)(intptr_t)(handler_pid);
  }

  return new_process;
}


process_t * _return_current_(process_t * );
fork_result_t _do_fork_(process_t * );
void _suspend_(process_t * );
void _resume_(process_t * );
exit_type_t _wait_(process_t * , bool );
