#include <signal.h>
#include <assert.h>
#include <types.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "os.h"
#include "engine.h"
#include "xxh3.h"

// Crash related functions
afl_ret_t dump_crash_to_file(afl_input_t *data, afl_engine_t *engine) {

  char filename[128];
  (void)(engine);

  /* TODO: This filename should be replaced by "crashes-SHA_OF_BYTES" later */

  u64 input_data_checksum = XXH64(data->bytes, data->len, HASH_CONST);
  snprintf(filename, sizeof(filename) - 1, "crashes-%016llx", input_data_checksum);

  FILE *f = fopen(filename, "w+");
  if (!f) { return AFL_RET_FILE_OPEN_ERROR; }
  fwrite(data->bytes, 1, data->len, f);

  fclose(f);
  return AFL_RET_SUCCESS;

}

// Process related functions

void _afl_process_init_internal(afl_os_t *afl_os) {

  afl_os->fork = afl_proc_fork;

  afl_os->resume = afl_proc_resume;
  afl_os->wait = afl_proc_wait;
  afl_os->suspend = afl_proc_suspend;

}

afl_fork_result_t afl_proc_fork(afl_os_t *afl_os) {

  pid_t child = fork();

  if (child == 0)
    return CHILD;
  else if (child < 0)
    return FORK_FAILED;

  afl_os->handler_process = child;
  return PARENT;

}

void afl_proc_suspend(afl_os_t *afl_os) {

  kill(afl_os->handler_process, SIGSTOP);

}

void afl_proc_resume(afl_os_t *afl_os) {

  kill(afl_os->handler_process, SIGCONT);

}

afl_exit_t afl_proc_wait(afl_os_t *afl_os, bool untraced) {

  int status = 0;
  if (waitpid((afl_os->handler_process), &status, untraced ? WUNTRACED : 0) < 0)
    return -1;  // Waitpid fails here, how should we handle this?

  if (WIFEXITED(status)) return AFL_EXIT_OK;

  // If the afl_os was simply stopped , we return AFL_EXIT_STOP
  if (WIFSTOPPED(status)) return AFL_EXIT_STOP;

  // If the afl_os exited with a signal, we check the corresponsing signum of
  // the afl_os and return values correspondingly
  if (WIFSIGNALED(status)) {

    int signal_num = WTERMSIG(status);  // signal number
    switch (signal_num) {

      case SIGKILL:
        return AFL_EXIT_TIMEOUT;
      case SIGSEGV:
        return AFL_EXIT_SEGV;
      case SIGABRT:
        return AFL_EXIT_ABRT;
      case SIGBUS:
        return AFL_EXIT_BUS;
      case SIGILL:
        return AFL_EXIT_ILL;
      default:
        /* Any other SIGNAL we need to take care of? */
        return AFL_EXIT_CRASH;

    }

  }

  else {

    FATAL("BUG: Currently Unhandled");

  }

}

