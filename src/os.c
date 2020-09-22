#include <signal.h>
#include <assert.h>
#include <types.h>
#include <unistd.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "os.h"
#include "engine.h"
#include "xxh3.h"

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

static afl_ret_t __afl_for_each_file(char *dirpath, bool (*handle_file)(char *filename, void *data), void *data) {

  DIR *          dir_in = NULL;
  struct dirent *dir_ent = NULL;
  char           infile[PATH_MAX];
  uint32_t       ok = 0;

  if (!(dir_in = opendir(dirpath))) { return AFL_RET_FILE_OPEN_ERROR; }

  while ((dir_ent = readdir(dir_in))) {

    if (dir_ent->d_name[0] == '.') {

      continue;  // skip anything that starts with '.'

    }

    snprintf((char *)infile, sizeof(infile), "%s/%s", dirpath, dir_ent->d_name);
    infile[sizeof(infile) - 1] = '\0';

    /* TODO: Error handling? */
    struct stat st;
    if (access(infile, R_OK) != 0 || stat(infile, &st) != 0) { continue; }
    if (S_ISDIR(st.st_mode)) {

      if (__afl_for_each_file(infile, handle_file, data) == AFL_RET_SUCCESS) { ok = 1; }
      continue;

    }

    if (!S_ISREG(st.st_mode)) { continue; }

    if (!handle_file(infile, data)) {

      DBG("Finishing recursive file read");
      break;

    } else {

      ok = 1;

    }

  }

  closedir(dir_in);

  if (ok) {

    return AFL_RET_SUCCESS;

  } else {

    return AFL_RET_EMPTY;

  }

}

/* Run `handle_file` for each file in the dirpath, recursively.
void *data will be passed to handle_file as 2nd param.
if handle_file returns false, further execution stops. */
afl_ret_t afl_for_each_file(char *dirpath, bool (*handle_file)(char *filename, void *data), void *data) {

  size_t dir_name_size = strlen(dirpath);
  if (dirpath[dir_name_size - 1] == '/') { dirpath[dir_name_size - 1] = '\0'; }
  if (access(dirpath, R_OK | X_OK) != 0) return AFL_RET_FILE_OPEN_ERROR;

  return __afl_for_each_file(dirpath, handle_file, data);

}

