#include "libaflpp.h"

typedef struct afl_forkserver_executor {

  /* a program that includes afl-forkserver needs to define these */

  executor_t super;                 /* Base executor "class"            */

  u8  uses_asan;                        /* Target uses ASAN?                */
  u8 *trace_bits;                       /* SHM with instrumentation bitmap  */
  u8  use_stdin;                        /* use stdin for sending data       */

  s32 fsrv_pid,                         /* PID of the fork server           */
      child_pid,                        /* PID of the fuzzed program        */
      child_status,                     /* waitpid result for the child     */
      out_dir_fd;                       /* FD of the lock file              */

  s32 out_fd,                           /* Persistent fd for fsrv->out_file */
#ifndef HAVE_ARC4RANDOM
      dev_urandom_fd,                   /* Persistent fd for /dev/urandom   */
#endif
      dev_null_fd,                      /* Persistent fd for /dev/null      */
      fsrv_ctl_fd,                      /* Fork server control pipe (write) */
      fsrv_st_fd;                       /* Fork server status pipe (read)   */

  u8 no_unlink;                         /* do not unlink cur_input          */

  u32 exec_tmout;                       /* Configurable exec timeout (ms)   */
  u32 map_size;                         /* map size used by the target      */
  u32 snapshot;                         /* is snapshot feature used         */
  u64 mem_limit;                        /* Memory cap for child (MB)        */

  u64 total_execs;                      /* How often run_target was called  */

  u8 *out_file,                         /* File to fuzz, if any             */
      *target_path;                     /* Path of the target               */

  FILE *plot_file;                      /* Gnuplot output file              */

  /* Note: lat_run_timed_out is u32 to send it to the child as 4 byte array */
  u32 last_run_timed_out;               /* Traced process timed out?        */

  u8 last_kill_signal;                  /* Signal that killed the child     */

  u8 qemu_mode;                         /* if running in qemu mode or not   */

  char *cmplog_binary;                  /* the name of the cmplog binary    */

  /* Function to kick off the forkserver child */
  void (*init_child_func)(struct afl_forkserver *fsrv, char **argv);

  u8 *function_opt;                     /* for autodictionary: afl ptr      */

  void (*function_ptr)(void *afl_tmp, u8 *mem, u32 len);

} afl_forkserver_executor_t;

struct forkserver_start_args {

  char **      argv;
  volatile u8 *stop_soon_p;
  u8           debug_child_output;

};

void afl_fsrv_exc_init(executor_t *);
void afl_fsrv_exc_init_dup(executor_t *, executor_t *);
void afl_fsrv_exc_start(executor_t *, void *);
void afl_fsrv_exc_write_to_testcase(executor_t *, u8 *, size_t);
fsrv_run_result_t afl_fsrv_exc_run_target(executor_t *, u32, void *);
void              afl_fsrv_exc_killall(void);
void              afl_fsrv_exc_kill(executor_t *fsrv);

