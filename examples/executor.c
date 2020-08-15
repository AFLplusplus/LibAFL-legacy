#define AFL_MAIN

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>

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
#include "xxh3.h"
#include "alloc-inl.h"
#include "libaflpp.h"
#include "libos.h"
#include "libfeedback.h"
#include "libengine.h"
#include "libmutator.h"
#include "libfuzzone.h"
#include "libstage.h"

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

typedef struct timeout_obs_channel {

  observation_channel_t base;

  u32 last_run_time;
  u32 avg_exec_time;

} timeout_obs_channel_t;

typedef struct thread_instance_args {
  engine_t * engine;
  char *in_dir;
} thread_instance_args_t;

/* Helper functions here */
static u32 read_s32_timed(s32 fd, s32 *buf, u32 timeout_ms);

/* Functions related to the forkserver defined above */
static afl_forkserver_t *fsrv_init(char *target_path, char *out_file);
static exit_type_t       fsrv_run_target(executor_t *fsrv_executor);
static u8 fsrv_place_input(executor_t *fsrv_executor, raw_input_t *input);
static afl_ret_t fsrv_start(executor_t *fsrv_executor);

/* Functions related to the feedback defined above */
static float coverage_fbck_is_interesting(feedback_t *feedback,
                                          executor_t *fsrv);
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

  if (afl_executor_init(&(fsrv->base))) {

    free(fsrv);
    return NULL;

  }

  /* defining standard functions for the forkserver vtable */
  fsrv->base.funcs.init_cb = fsrv_start;
  fsrv->base.funcs.place_input_cb = fsrv_place_input;
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
static afl_ret_t fsrv_start(executor_t *fsrv_executor) {

  afl_forkserver_t *fsrv = (afl_forkserver_t *)fsrv_executor;

  int st_pipe[2], ctl_pipe[2];
  s32 status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) { return AFL_RET_ERRNO; }

  fsrv->last_run_timed_out = 0;
  fsrv->fsrv_pid = fork();

  if (fsrv->fsrv_pid < 0) { return AFL_RET_ERRNO; }

  if (!fsrv->fsrv_pid) {

    /* CHILD PROCESS */

    setsid();

    fsrv->out_fd = open((char *)fsrv->out_file, O_RDONLY | O_CREAT, 0600);
    if (!fsrv->out_fd) { PFATAL("Could not open outfile in child"); }

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

    execv(fsrv->target_path, fsrv->extra_args);

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
    return AFL_RET_SUCCESS;

  }

  if (fsrv->trace_bits == (u8 *)0xdeadbeef) {

    WARNF("Unable to execute target application ('%s')", fsrv->extra_args[0]);
    return AFL_RET_EXEC_ERROR;

  }

  WARNF("Fork server handshake failed");
  return AFL_RET_BROKEN_TARGET;

}

/* Places input in the executor for the target */
u8 fsrv_place_input(executor_t *fsrv_executor, raw_input_t *input) {

  afl_forkserver_t *fsrv = (afl_forkserver_t *)fsrv_executor;

  ssize_t write_len = write(fsrv->out_fd, input->bytes, input->len);

  if (write_len < 0 || (size_t)write_len != input->len) {

    FATAL("Short Write");

  }

  fsrv->base.current_input = input;

  return write_len;

}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */
static exit_type_t fsrv_run_target(executor_t *fsrv_executor) {

  afl_forkserver_t *fsrv = (afl_forkserver_t *)fsrv_executor;

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

  /* Update the timeout observation channel */
  timeout_obs_channel_t *timeout_channel =
      (timeout_obs_channel_t *)fsrv->base.funcs.get_observation_channels(
          &fsrv->base, 1);
  timeout_channel->last_run_time = exec_ms;

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
  afl_feedback_init(&feedback->base, queue);

  feedback->base.funcs.is_interesting = coverage_fbck_is_interesting;

  feedback->virgin_bits = calloc(1, size);
  if (!feedback->virgin_bits) {

    free(feedback);
    return NULL;

  }

  feedback->size = size;

  return feedback;

}

void timeout_channel_reset(observation_channel_t *obs_channel) {

  timeout_obs_channel_t *timeout_channel = (timeout_obs_channel_t *)obs_channel;

  timeout_channel->last_run_time = 0;

}

void timeout_channel_post_exec(observation_channel_t *obs_channel,
                               engine_t *             engine) {

  timeout_obs_channel_t *timeout_channel = (timeout_obs_channel_t *)obs_channel;

  timeout_channel->avg_exec_time =
      (timeout_channel->avg_exec_time + timeout_channel->last_run_time) /
      (engine->executions);

}

/* We'll implement a simple is_interesting function for the feedback, which
 * checks if new tuples have been hit in the map */
static float coverage_fbck_is_interesting(feedback_t *feedback,
                                          executor_t *fsrv) {

  maximize_map_feedback_t *map_feedback = (maximize_map_feedback_t *)feedback;

  /* First get the observation channel */

  map_based_channel_t *obs_channel =
      (map_based_channel_t *)fsrv->funcs.get_observation_channels(fsrv, 0);
  bool found = false;

  u8 *   trace_bits = obs_channel->shared_map.map;
  size_t map_size = obs_channel->shared_map.map_size;

  for (size_t i = 0; i < map_size; ++i) {

    if (trace_bits[i] > map_feedback->virgin_bits[i]) { found = true; }

  }

  if (found && feedback->queue) {

    raw_input_t *input = fsrv->current_input->funcs.copy(fsrv->current_input);

    queue_entry_t *new_entry = afl_queue_entry_create(input);
    // An incompatible ptr type warning has been suppresed here. We pass the
    // feedback queue to the add_to_queue rather than the base_queue
    feedback->queue->base.funcs.add_to_queue(&feedback->queue->base, new_entry);

    // Put the entry in the feedback queue and return 0.0 so that it isn't added
    // to the global queue too
    return 0.0;

  }

  return found ? 1.0 : 0.0;

}

/* Another feedback based on the exec time */

static float timeout_fbck_is_interesting(feedback_t *feedback,
                                         executor_t *executor) {

  afl_forkserver_t *fsrv = (afl_forkserver_t *)executor;
  u32               exec_timeout = fsrv->exec_tmout;

  timeout_obs_channel_t *timeout_channel =
      (timeout_obs_channel_t *)fsrv->base.funcs.get_observation_channels(
          &fsrv->base, 1);

  u32 last_run_time = timeout_channel->last_run_time;

  if (last_run_time == exec_timeout) {

    queue_entry_t *new_entry = afl_queue_entry_create(
        fsrv->base.current_input->funcs.copy(fsrv->base.current_input));
    feedback->queue->base.funcs.add_to_queue(&feedback->queue->base, new_entry);
    return 0.0;

  } else if (last_run_time >

             (exec_timeout + timeout_channel->avg_exec_time) / 2) {

    /* The run is good enough for the global queue */
    return 1.0;

  }

  else {

    return 0.0;

  }

}

engine_t * initialize_engine_instance(char * target_path, char * out_file, char **extra_args) {

  /* Let's now create a simple map-based observation channel */
  map_based_channel_t *trace_bits_channel = afl_map_channel_create(MAP_SIZE);

  /* Another timing based observation channel */
  timeout_obs_channel_t *timeout_channel =
      calloc(1, sizeof(timeout_obs_channel_t));
  if (!timeout_channel) { FATAL("Error initializing observation channel"); }
  afl_observation_channel_init(&timeout_channel->base);
  timeout_channel->base.funcs.post_exec = timeout_channel_post_exec;
  timeout_channel->base.funcs.reset = timeout_channel_reset;

  /* We initialize the forkserver we want to use here. */
  afl_forkserver_t *fsrv = fsrv_init(target_path, out_file);
  if (!fsrv) { FATAL("Could not initialize forkserver!"); }
  fsrv->exec_tmout = 10000;
  fsrv->extra_args = extra_args;

  fsrv->base.funcs.add_observation_channel(&fsrv->base,
                                           &trace_bits_channel->base);
  fsrv->base.funcs.add_observation_channel(&fsrv->base, &timeout_channel->base);

  char shm_str[256];
  snprintf(shm_str, sizeof(shm_str), "%d",
           trace_bits_channel->shared_map.shm_id);
  setenv("__AFL_SHM_ID", (char *)shm_str, 1);
  fsrv->trace_bits = trace_bits_channel->shared_map.map;

  /* We create a simple feedback queue for coverage here*/
  feedback_queue_t *coverage_feedback_queue =
      afl_feedback_queue_create(NULL, (char *)"Coverage feedback queue");
  if (!coverage_feedback_queue) { FATAL("Error initializing feedback queue"); }

  /* Another feedback queue for timeout entries here */
  feedback_queue_t *timeout_feedback_queue =
      afl_feedback_queue_create(NULL, "Timeout feedback queue");
  if (!timeout_feedback_queue) { FATAL("Error initializing feedback queue"); }

  /* Global queue creation */
  global_queue_t *global_queue = afl_global_queue_create(NULL);
  if (!global_queue) { FATAL("Error initializing global queue"); }
  global_queue->extra_funcs.add_feedback_queue(global_queue,
                                               coverage_feedback_queue);
  global_queue->extra_funcs.add_feedback_queue(global_queue,
                                               timeout_feedback_queue);

  /* Coverage Feedback initialization */
  maximize_map_feedback_t *coverage_feedback = map_feedback_init(
      coverage_feedback_queue, trace_bits_channel->shared_map.map_size);
  if (!coverage_feedback) { FATAL("Error initializing feedback"); }
  coverage_feedback_queue->feedback = &coverage_feedback->base;

  /* Timeout Feedback initialization */
  feedback_t *timeout_feedback = afl_feedback_create(timeout_feedback_queue);
  if (!timeout_feedback) { FATAL("Error initializing feedback"); }
  timeout_feedback_queue->feedback = timeout_feedback;
  timeout_feedback->funcs.is_interesting = timeout_fbck_is_interesting;

  /* Let's build an engine now */
  engine_t *engine = afl_engine_create((executor_t *)fsrv, NULL, global_queue);
  if (!engine) { FATAL("Error initializing Engine"); }
  engine->funcs.add_feedback(engine, (feedback_t *)coverage_feedback);
  engine->funcs.add_feedback(engine, timeout_feedback);

  fuzz_one_t *fuzz_one = afl_fuzz_one_create(engine);
  if (!fuzz_one) { FATAL("Error initializing fuzz_one"); }

  // We also add the fuzzone to the engine here.
  engine->fuzz_one = fuzz_one;

  scheduled_mutator_t *mutators_havoc = afl_scheduled_mutator_create(NULL, 8);
  if (!mutators_havoc) { FATAL("Error initializing Mutators"); }

  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, flip_byte_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_2_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_4_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          delete_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          clone_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_bit_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_2_bits_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_4_bits_mutation);                                          
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          random_byte_add_sub_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          random_byte_mutation);                                          

  fuzzing_stage_t *stage = afl_fuzz_stage_create(engine);
  if (!stage) { FATAL("Error creating fuzzing stage"); }
  stage->funcs.add_mutator_to_stage(stage, &mutators_havoc->base);

  return engine;

}

void * thread_run_instance(void * thread_args) {

  thread_instance_args_t * thread_instance_args = (thread_instance_args_t *)thread_args;

  engine_t * engine = (engine_t *)thread_instance_args->engine;

  afl_forkserver_t * fsrv = (afl_forkserver_t *)engine->executor;
  map_based_channel_t * trace_bits_channel = (map_based_channel_t *)fsrv->base.observors[0];
  timeout_obs_channel_t * timeout_channel = (timeout_obs_channel_t *)fsrv->base.observors[1];

  fuzzing_stage_t * stage = (fuzzing_stage_t *)engine->fuzz_one->stages[0];
  scheduled_mutator_t * mutators_havoc = (scheduled_mutator_t *)stage->mutators[0];

  maximize_map_feedback_t * coverage_feedback = (maximize_map_feedback_t *)(engine->feedbacks[0]);

  /* Seeding the random generator */
  pthread_t self_id = pthread_self();
  u32 random_seed = XXH32(&self_id, sizeof(pthread_t), rand_below(0xffff));
  srand(random_seed);

  /* Let's reduce the timeout initially to fill the queue */
  fsrv->exec_tmout = 20;
  /* Now we can simply load the testcases from the directory given */
  afl_ret_t ret = engine->funcs.load_testcases_from_dir(engine, thread_instance_args->in_dir, NULL);
  if (ret != AFL_RET_SUCCESS) {

    PFATAL("Error loading testcase dir: %s", afl_ret_stringify(ret));

  }

  OKF("Processed %llu input files.", fsrv->total_execs);

  engine->funcs.loop(engine);

  SAYF(
      "Fuzzing ends with all the queue entries fuzzed. No of executions %llu\n",
      engine->executions);

  /* Let's free everything now. Note that if you've extended any structure,
   * which now contains pointers to any dynamically allocated region, you have
   * to free them yourselves, but the extended structure itself can be de
   * initialized using the deleted functions provided */

  afl_executor_delete(&fsrv->base);
  afl_map_channel_delete(trace_bits_channel);
  afl_observation_channel_delete(&timeout_channel->base);
  afl_scheduled_mutator_delete(mutators_havoc);
  afl_fuzz_stage_delete(stage);
  afl_fuzz_one_delete(engine->fuzz_one);
  free(coverage_feedback->virgin_bits);
  for (size_t i = 0; i < engine->feedbacks_num; ++i) {
    afl_feedback_delete((feedback_t *)engine->feedbacks[i]);
  }
  for (size_t i = 0; i < engine->global_queue->feedback_queues_num; ++i) {
    afl_feedback_queue_delete(engine->global_queue->feedback_queues[i]);
  }
  afl_global_queue_delete(engine->global_queue);
  afl_engine_delete(engine);
  return 0;
}


/* Main entry point function */
int main(int argc, char **argv) {

  if (argc < 3) {

    FATAL(
        "Usage: ./executor /input/directory "
        "/out/file/path target [target_args]");

  }

  char *in_dir = argv[1];
  char *target_path = argv[3];
  char *out_file = argv[2];

  engine_t * engine_instance = initialize_engine_instance(target_path, out_file, NULL);
  thread_instance_args_t * thread_args = calloc(1, sizeof(thread_instance_args_t));
  thread_args->engine = engine_instance;
  thread_args->in_dir = in_dir;
  pthread_t t1;
  int s = pthread_create(&t1, NULL, thread_run_instance, thread_args);
  if (!s) { OKF("Thread created with thread id %lu", t1); }

  engine_t * engine_instance_two = initialize_engine_instance(target_path, out_file, NULL);
  thread_args = calloc(1, sizeof(thread_instance_args_t));
  thread_args->engine = engine_instance_two;
  thread_args->in_dir = in_dir;
  pthread_t t2;
  s = pthread_create(&t2, NULL, thread_run_instance, thread_args);
  if (!s) { OKF("Thread created with thread id %lu", t2); }


  while(true) {
    sleep(1);
    u64 execs = engine_instance->executions + engine_instance_two->executions;
    u64 crashes = engine_instance->crashes + engine_instance_two->crashes;
    printf("Execs: %llu\tCrashes: %llu\r", execs, crashes);
    fflush(0);
  }

}

