#include "libos.h"
#include <signal.h>
#include <assert.h>
#include <types.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

// Crash related functions
void dump_crash_to_file(exit_type_t exit_type, raw_input_t * data) {

    char * filename = ck_alloc(100);

    /* This filename will be replaced by "crashes-SHA_OF_BYTES" later */
    snprintf(filename, 100, "crashes-%d", rand());

    FILE * f = fopen(filename, "w+");
    fwrite(data->bytes,1 , data->len, f);

    fclose(f);

}



// Process related functions


static process_t * current_process;

void afl_process_init(process_t * process) {

    process->current = _return_current_;
    process->fork = _do_fork_;

    process->resume = _resume_;
    process->wait = _wait_;
    process->suspend = _suspend_;

}


process_t * _return_current_(process_t * process) {

    if (current_process)    return current_process;

    process_t * p = AFL_PROCESS_INIT(NULL, getpid());

    current_process = p;
    return p;

}


fork_result_t _do_fork_(process_t * process) {
    pid_t child = fork();

    if (child == 0) 
        return CHILD;
    else if (child < 0)
        return FORK_FAILED;

    process->handler_process = (void*)(intptr_t)child;
    return PARENT;

}

void _suspend_(process_t * process) {
    
    kill((pid_t)(intptr_t)(process->handler_process), SIGSTOP);

}


void _resume_(process_t * process) {

    kill((pid_t)(intptr_t)(process->handler_process), SIGCONT);

}

exit_type_t _wait_(process_t * process, bool untraced) {

    int status = 0;
    if (waitpid((pid_t)(intptr_t)(process->handler_process), &status, untraced ? WUNTRACED : 0) < 0)    return -1;  // Waitpid fails here, how should we handle this?

    if (WIFEXITED(status))  return NORMAL;

    // If the process was simply stopped , we return STOP
    if (WIFSTOPPED(status)) return STOP;

    // If the process exited with a signal, we check the corresponsing signum of the process and return values correspondingly
    if (WIFSIGNALED(status)) {

        int signal_num = WTERMSIG(status); // signal number
        switch (signal_num) {
            case SIGKILL:
                return TIMEOUT;
            case SIGSEGV:
                return SEGV;
            case SIGABRT: 
                return ABRT;
            case SIGBUS:
                return BUS;
            case SIGILL: 
                return ILL;
            default: 
                /* Any other SIGNAL we need to take care of? */
                return CRASH;
        }
    }

    else {
        FATAL("Currently Unhandled");
    }

}

