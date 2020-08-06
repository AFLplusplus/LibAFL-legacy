#define AFL_MAIN

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <math.h>

#include <sys/wait.h>
#include <sys/time.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "libaflpp.h"
#include "libos.h"
#include "libfeedback.h"
#include "libengine.h"
#include "libmutator.h"
#include "libfuzzone.h"
#include "libstage.h"

#undef MAP_SIZE
#define MAP_SIZE 65536
#define MAX_PATH_LEN 100

#define SUPER_INTERESTING 0.5
#define VERY_INTERESTING 0.4
#define INTERESTING 0.3

/* We are defining our own executor, a forkserver */
typedef struct afl_forkserver {

  executor_t base;                       /* executer struct to inherit from */

  u8 *trace_bits;                       /* SHM with instrumentation bitmap  */
  u8  use_stdin;                        /* use stdin for sending data       */

  s32 fsrv_pid,                         /* PID of the fork server           */
      child_pid,                        /* PID of the fuzzed program        */
      child_status,                     /* waitpid result for the child     */
      out_dir_fd,                       /* FD of the lock file              */
      dev_null_fd;

  s32 out_fd,                           /* Persistent fd for fsrv->out_file */

      fsrv_ctl_fd,                      /* Fork server control pipe (write) */
      fsrv_st_fd;                       /* Fork server status pipe (read)   */

  u32 exec_tmout;                       /* Configurable exec timeout (ms)   */
  u32 map_size;                         /* map size used by the target      */

  u64 total_execs;                 /* How often fsrv_run_target was called  */

  char *out_file,                       /* File to fuzz, if any             */
      *target_path;                     /* Path of the target               */

  char **extra_args;

  u32 last_run_timed_out;               /* Traced process timed out?        */

  u8 last_kill_signal;                  /* Signal that killed the child     */

} afl_forkserver_t;

/* We implement a simple map maximising feedback here. */
typedef struct maximize_map_feedback {

  feedback_t base;

  u8 *   virgin_bits;
  size_t size;

} maximize_map_feedback_t;

/* Helper functions here */
static u32 read_s32_timed(s32 fd, s32 *buf, u32 timeout_ms);

/* Functions related to the forkserver defined above */
static afl_forkserver_t *fsrv_init(char *target_path, char *out_file);
static exit_type_t       fsrv_run_target(afl_forkserver_t *fsrv);
static u8 fsrv_place_inputs(afl_forkserver_t *fsrv, raw_input_t *input);
static u8 fsrv_start(afl_forkserver_t *fsrv);

/* Functions related to the feedback defined above */
static bool fbck_is_interesting(maximize_map_feedback_t *feedback,
                                executor_t *             fsrv);
static maximize_map_feedback_t *map_feedback_init(feedback_queue_t *queue,
                                                  size_t            size);

/* static const u8 count_class_binary[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

}; */

/* Get unix time in microseconds */
#if !defined(__linux__)
static u64 get_cur_time_us(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}

#endif

/* This function uses select calls to wait on a child process for given
 * timeout_ms milliseconds and kills it if it doesn't terminate by that time */
static u32 read_s32_timed(s32 fd, s32 *buf, u32 timeout_ms) {

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  struct timeval timeout;
  int            sret;
  ssize_t        len_read;

  timeout.tv_sec = (timeout_ms / 1000);
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
#if !defined(__linux__)
  u64 read_start = get_cur_time_us();
#endif

  /* set exceptfds as well to return when a child exited/closed the pipe. */
restart_select:
  sret = select(fd + 1, &readfds, NULL, NULL, &timeout);

  if (likely(sret > 0)) {

  restart_read:
    len_read = read(fd, (u8 *)buf, 4);

    if (likely(len_read == 4)) {  // for speed we put this first

#if defined(__linux__)
      u32 exec_ms = MIN(
          timeout_ms,
          ((u64)timeout_ms - (timeout.tv_sec * 1000 + timeout.tv_usec / 1000)));
#else
      u32 exec_ms = MIN(timeout_ms, get_cur_time_us() - read_start);
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

    if (likely(errno == EINTR)) goto restart_select;

    *buf = -1;
    return 0;

  }

  return 0;  // not reached

}

/* Function to simple initialize the forkserver */
afl_forkserver_t *fsrv_init(char *target_path, char *out_file) {

  afl_forkserver_t *fsrv = calloc(1, sizeof(afl_forkserver_t));
  if (!fsrv) { return NULL; }

  if (!afl_executor_init(&(fsrv->base))) {

    free(fsrv);
    return NULL;

  }

  /* defining standard functions for the forkserver vtable */
  fsrv->base.funcs.init_cb = fsrv_start;
  fsrv->base.funcs.place_inputs_cb = fsrv_place_inputs;
  fsrv->base.funcs.run_target_cb = fsrv_run_target;

  fsrv->target_path = target_path;
  fsrv->out_file = out_file;

  /* FD for the stdin of the child process */
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

  fsrv->out_dir_fd = -1;

  fsrv->dev_null_fd = open("/dev/null", O_WRONLY);
  if (!fsrv->dev_null_fd) {

    close(fsrv->out_fd);
    afl_executor_deinit(&fsrv->base);
    free(fsrv);
    return NULL;

  }

  /* Settings */
  fsrv->use_stdin = 1;

  /* exec related stuff */
  fsrv->child_pid = -1;
  fsrv->exec_tmout = 0;                          /* Default exec time in ms */

  return fsrv;

}

/* This function starts up the forkserver for further process requests */
static u8 fsrv_start(afl_forkserver_t *fsrv) {

  int st_pipe[2], ctl_pipe[2];
  s32 status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) { PFATAL("pipe() failed"); }

  fsrv->last_run_timed_out = 0;
  fsrv->fsrv_pid = fork();

  if (fsrv->fsrv_pid < 0) { PFATAL("fork() failed"); }

  if (!fsrv->fsrv_pid) {

    /* CHILD PROCESS */

    setsid();

    fsrv->out_fd = open((char *)fsrv->out_file, O_RDONLY | O_CREAT, 0600);

    dup2(fsrv->out_fd, 0);
    close(fsrv->out_fd);

    dup2(fsrv->dev_null_fd, 1);
    dup2(fsrv->dev_null_fd, 2);

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) { PFATAL("dup2() failed"); }
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) { PFATAL("dup2() failed"); }

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    execv((char *)fsrv->target_path, fsrv->extra_args);

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

    u32 time_ms = read_s32_timed(fsrv->fsrv_st_fd, &status,
                                 fsrv->exec_tmout * FORK_WAIT_MULT);

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

    return 0;

  }

  if (fsrv->trace_bits == (u8 *)0xdeadbeef) {

    FATAL("Unable to execute target application ('%s')", fsrv->extra_args[0]);

  }

  FATAL("Fork server handshake failed");

}

/* Places input in the executor for the target */
u8 fsrv_place_inputs(afl_forkserver_t *fsrv, raw_input_t *input) {

  ssize_t write_len = write(fsrv->out_fd, input->bytes, input->len);

  if (write_len < 0 || (size_t)write_len != input->len) {

    FATAL("Short Write");

  }

  fsrv->base.current_input = input;

  return write_len;

}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */
static exit_type_t fsrv_run_target(afl_forkserver_t *fsrv) {

  s32 res;
  u32 exec_ms;
  u32 write_value = fsrv->last_run_timed_out;

  /* After this memset, fsrv->trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(fsrv->trace_bits, 0, fsrv->map_size);

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

  exec_ms =
      read_s32_timed(fsrv->fsrv_st_fd, &fsrv->child_status, fsrv->exec_tmout);

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

  /* Any subsequent operations on fsrv->trace_bits must not be moved by the
     compiler below this point. Past this location, fsrv->trace_bits[]
     behave very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  /* Report outcome to caller. */

  if (WIFSIGNALED(fsrv->child_status)) {

    fsrv->last_kill_signal = WTERMSIG(fsrv->child_status);

    if (fsrv->last_run_timed_out && fsrv->last_kill_signal == SIGKILL) {

      return TIMEOUT;

    }

    return CRASH;

  }

  return NORMAL;

}

/* Init function for the feedback */
static maximize_map_feedback_t *map_feedback_init(feedback_queue_t *queue,
                                                  size_t            size) {

  maximize_map_feedback_t *feedback =
      calloc(1, sizeof(maximize_map_feedback_t));
  if (!feedback) { return NULL; }
  afl_feedback_init(feedback, queue);

  feedback->base.funcs.is_interesting = fbck_is_interesting;

  feedback->virgin_bits = calloc(1, size);
  if (!feedback->virgin_bits) {

    free(feedback);
    return NULL;

  }

  feedback->size = size;

  return feedback;

}

/* We'll implement a simple is_interesting function for the feedback, which
 * checks if new tuples have been hit in the map */
static bool fbck_is_interesting(maximize_map_feedback_t *feedback,
                                executor_t *             fsrv) {

  /* First get the observation channel */

  map_based_channel_t *obs_channel =
      fsrv->funcs.get_observation_channels(fsrv, 0);
  bool found = false;

  u8 *   trace_bits = obs_channel->shared_map->map;
  size_t map_size = obs_channel->shared_map->map_size;

  for (size_t i = 0; i < map_size; ++i) {

    if (trace_bits[i] > feedback->virgin_bits[i]) { found = true; }

  }

  if (found && feedback->base.queue) {

    queue_entry_t *new_entry = afl_queue_entry_init(NULL, fsrv->current_input);
    // An incompatible ptr type warning has been suppresed here. We pass the
    // feedback queue to the add_to_queue rather than the base_queue
    feedback->base.queue->base.funcs.add_to_queue(feedback->base.queue,
                                                  new_entry);

  }

  return found;

}

/* Main entry point function */
int main(int argc, char **argv) {

  if (argc < 3) {

    FATAL(
        "Usage: ./executor /target/path /input/directory "
        "/out/file/path ");

  }

  char *in_dir = (char *)argv[2];

  /* Let's now create a simple map-based observation channel */
  map_based_channel_t *trace_bits_channel = afl_map_channel_init(MAP_SIZE);

  /* We initialize the forkserver we want to use here. */
  afl_forkserver_t *fsrv = fsrv_init((char *)argv[1], (char *)argv[3]);
  if (!fsrv) { FATAL("Could not initialize forkserver!"); }
  fsrv->exec_tmout = 10000;
  fsrv->extra_args = argv;

  fsrv->base.funcs.add_observation_channel(fsrv, trace_bits_channel);

  char *shm_str = alloc_printf("%d", trace_bits_channel->shared_map->shm_id);
  if (!shm_str) { PFATAL("alloc_printf failed."); }
  setenv("__AFL_SHM_ID", (char *)shm_str, 1);
  fsrv->trace_bits = trace_bits_channel->shared_map->map;

  /* We create a simple feedback queue here*/
  feedback_queue_t *queue =
      afl_feedback_queue_init(NULL, NULL, (char *)"fbck queue");
  if (!queue) { FATAL("Error initializing queue"); }

  /* Feedback initialization */
  maximize_map_feedback_t *feedback =
      map_feedback_init(queue, trace_bits_channel->shared_map->map_size);
  if (!feedback) { FATAL("Error initializing feedback"); }
  queue->feedback = feedback;

  /* Let's build an engine now */
  engine_t *engine = afl_engine_init(NULL, (executor_t *)fsrv, NULL, NULL);
  if (!engine) { FATAL("Error initializing Engine"); }
  engine->funcs.add_feedback(engine, (feedback_t *)feedback);

  fuzz_one_t *fuzz_one = afl_fuzz_one_init(NULL, engine);
  if (!fuzz_one) { FATAL("Error initializing fuzz_one"); }

  // We also add the fuzzone to the engine here.
  engine->fuzz_one = fuzz_one;

  scheduled_mutator_t *mutators_havoc = afl_scheduled_mutator_init(NULL, 0);
  if (!mutators_havoc) { FATAL("Error initializing Mutators"); }

  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, flip_byte_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_2_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_4_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          random_byte_add_sub_mutation);

  fuzzing_stage_t *stage = afl_fuzz_stage_init(engine);
  if (!stage) { FATAL("Error initializing fuzz stage"); }
  stage->funcs.add_mutator_to_stage(stage, mutators_havoc);

  /* Now we can simply load the testcases from the directory given */
  afl_ret_t ret = engine->funcs.load_testcases_from_dir(engine, in_dir, NULL);
  if (ret != AFL_RET_SUCCESS) {

    PFATAL("Error loading testcase dir: %s", afl_ret_stringify(ret));

  }

  OKF("Processed %llu input files.", fsrv->total_execs);

  /* Let's free everything now. Note that if you've extended any structure,
   * which now contains pointers to any dynamically allocated region, you have
   * to free them yourselves, but the extended structure itself can be de
   * initialized using the deinit functions provided */

  free(feedback->virgin_bits);
  free(shm_str);

  AFL_ENGINE_DEINIT(engine);
  afl_map_channel_deinit(trace_bits_channel);

  AFL_FEEDBACK_QUEUE_DEINIT(queue);

  return 0;

}

