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
#include "aflpp.h"

#define SUPER_INTERESTING 0.5
#define VERY_INTERESTING 0.4
#define INTERESTING 0.3
#define MAP_CHANNEL_ID 0x1
#define TIMEOUT_CHANNEL_ID 0x2

typedef struct timeout_obs_channel {

  afl_observer_t base;

  u32 last_run_time;
  u32 avg_exec_time;

} timeout_obs_channel_t;

llmp_broker_t *llmp_broker;
int                  broker_port;

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */
static afl_exit_t fsrv_run_target_custom(afl_executor_t *fsrv_executor) {

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

  exec_ms = afl_read_s32_timed(fsrv->fsrv_st_fd, &fsrv->child_status, fsrv->exec_tmout);

  /* Update the timeout observation channel */
  timeout_obs_channel_t *timeout_channel = (timeout_obs_channel_t *)fsrv->base.funcs.observers_get(&fsrv->base, 1);
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
  if (!fsrv->use_stdin) { unlink(fsrv->out_file); }

  /* Any subsequent operations on fsrv->trace_bits must not be moved by the
     compiler below this point. Past this location, fsrv->trace_bits[]
     behave very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  /* Report outcome to caller. */

  if (WIFSIGNALED(fsrv->child_status)) {

    fsrv->last_kill_signal = WTERMSIG(fsrv->child_status);

    if (fsrv->last_run_timed_out && fsrv->last_kill_signal == SIGKILL) { return AFL_EXIT_TIMEOUT; }

    return AFL_EXIT_CRASH;

  }

  return AFL_EXIT_OK;

}

void timeout_channel_reset(afl_observer_t *obs_channel) {

  timeout_obs_channel_t *timeout_channel = (timeout_obs_channel_t *)obs_channel;

  timeout_channel->last_run_time = 0;

}

void timeout_channel_post_exec(afl_observer_t *obs_channel, afl_engine_t *engine) {

  timeout_obs_channel_t *timeout_channel = (timeout_obs_channel_t *)obs_channel;

  timeout_channel->avg_exec_time =
      (timeout_channel->avg_exec_time + timeout_channel->last_run_time) / (engine->executions);

}

/* Another feedback based on the exec time */

static float timeout_fbck_is_interesting(afl_feedback_t *feedback, afl_executor_t *executor) {

  afl_forkserver_t *fsrv = (afl_forkserver_t *)executor;
  u32               exec_timeout = fsrv->exec_tmout;

  if (!feedback->channel) { feedback->channel = executor->funcs.observers_get(executor, feedback->channel_id); }

  timeout_obs_channel_t *timeout_channel = (timeout_obs_channel_t *)feedback->channel;

  u32 last_run_time = timeout_channel->last_run_time;

  if (last_run_time == exec_timeout) {

    afl_input_t *input = fsrv->base.current_input->funcs.copy(fsrv->base.current_input);
    if (!input) { FATAL("Error creating a copy of input"); }

    afl_entry_t *new_entry = afl_entry_new(input);
    feedback->queue->base.funcs.insert(&feedback->queue->base, new_entry);
    return 0.0;

  }

  else {

    return 0.0;

  }

}

afl_engine_t *initialize_engine_instance(char *target_path, char *in_dir, char **target_args) {

  /* Let's now create a simple map-based observation channel */
  afl_map_based_channel_t *trace_bits_channel = afl_map_channel_new(MAP_SIZE, MAP_CHANNEL_ID);

  /* Another timing based observation channel */
  timeout_obs_channel_t *timeout_channel = calloc(1, sizeof(timeout_obs_channel_t));
  if (!timeout_channel) { FATAL("Error initializing observation channel"); }
  afl_observer_init(&timeout_channel->base, TIMEOUT_CHANNEL_ID);
  timeout_channel->base.funcs.post_exec = timeout_channel_post_exec;
  timeout_channel->base.funcs.reset = timeout_channel_reset;

  /* We initialize the forkserver we want to use here. */

  afl_forkserver_t *fsrv = fsrv_init(target_path, target_args);
  fsrv->base.funcs.run_target_cb = fsrv_run_target_custom;
  if (!fsrv) { FATAL("Could not initialize forkserver!"); }
  fsrv->exec_tmout = 10000;
  fsrv->target_args = target_args;

  fsrv->base.funcs.observer_add(&fsrv->base, &trace_bits_channel->base);
  fsrv->base.funcs.observer_add(&fsrv->base, &timeout_channel->base);

  char shm_str[256];
  snprintf(shm_str, sizeof(shm_str), "%d", trace_bits_channel->shared_map.shm_id);
  setenv("__AFL_SHM_ID", (char *)shm_str, 1);
  fsrv->trace_bits = trace_bits_channel->shared_map.map;

  /* We create a simple feedback queue for coverage here*/
  afl_queue_feedback_t *coverage_feedback_queue = afl_feedback_queue_new(NULL, (char *)"Coverage feedback queue");
  if (!coverage_feedback_queue) { FATAL("Error initializing feedback queue"); }

  /* Another feedback queue for timeout entries here */
  afl_queue_feedback_t *timeout_feedback_queue = afl_feedback_queue_new(NULL, "Timeout feedback queue");
  if (!timeout_feedback_queue) { FATAL("Error initializing feedback queue"); }

  /* Global queue creation */
  afl_queue_global_t *global_queue = afl_global_queue_new();
  if (!global_queue) { FATAL("Error initializing global queue"); }
  global_queue->extra_funcs.add_feedback_queue(global_queue, coverage_feedback_queue);
  global_queue->extra_funcs.add_feedback_queue(global_queue, timeout_feedback_queue);

  /* Coverage Feedback initialization */
  afl_feedback_cov_t *coverage_feedback =
      afl_feedback_cov_new(coverage_feedback_queue, trace_bits_channel->shared_map.map_size, MAP_CHANNEL_ID);
  if (!coverage_feedback) { FATAL("Error initializing feedback"); }
  coverage_feedback_queue->feedback = &coverage_feedback->base;

  /* Timeout Feedback initialization */
  afl_feedback_t *timeout_feedback = afl_feedback_new(timeout_feedback_queue, TIMEOUT_CHANNEL_ID);
  if (!timeout_feedback) { FATAL("Error initializing feedback"); }
  timeout_feedback_queue->feedback = timeout_feedback;
  timeout_feedback->funcs.is_interesting = timeout_fbck_is_interesting;

  /* Let's build an engine now */
  afl_engine_t *engine = afl_engine_new((afl_executor_t *)fsrv, NULL, global_queue);
  engine->in_dir = in_dir;
  if (!engine) { FATAL("Error initializing Engine"); }
  engine->funcs.add_feedback(engine, (afl_feedback_t *)coverage_feedback);
  engine->funcs.add_feedback(engine, timeout_feedback);

  afl_fuzz_one_t *fuzz_one = afl_fuzz_one_new(engine);
  if (!fuzz_one) { FATAL("Error initializing fuzz_one"); }

  afl_mutator_scheduled_t *mutators_havoc = afl_mutator_scheduled_new(NULL, 8);
  if (!mutators_havoc) { FATAL("Error initializing Mutators"); }

  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_flip_byte);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_flip_2_bytes);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_flip_4_bytes);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_delete_bytes);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_clone_bytes);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_flip_bit);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_flip_2_bits);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_flip_4_bits);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_random_byte_add_sub);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_random_byte);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, mutator_splice);

  afl_fuzzing_stage_t *stage = afl_fuzzing_stage_new(engine);
  if (!stage) { FATAL("Error creating fuzzing stage"); }
  stage->funcs.add_mutator_to_stage(stage, &mutators_havoc->base);

  return engine;

}

void fuzzer_process_main(llmp_client_state_t *client, void *data) {

  afl_engine_t *engine = (afl_engine_t *)data;

  engine->llmp_client = client;

  afl_forkserver_t *       fsrv = (afl_forkserver_t *)engine->executor;
  afl_map_based_channel_t *trace_bits_channel = (afl_map_based_channel_t *)fsrv->base.observors[0];
  timeout_obs_channel_t *  timeout_channel = (timeout_obs_channel_t *)fsrv->base.observors[1];

  afl_fuzzing_stage_t *    stage = (afl_fuzzing_stage_t *)engine->fuzz_one->stages[0];
  afl_mutator_scheduled_t *mutators_havoc = (afl_mutator_scheduled_t *)stage->mutators[0];

  afl_feedback_cov_t *coverage_feedback = (afl_feedback_cov_t *)(engine->feedbacks[0]);

  /* Let's reduce the timeout initially to fill the queue */
  fsrv->exec_tmout = 20;
  /* Now we can simply load the testcases from the directory given */
  AFL_TRY(engine->funcs.load_testcases_from_dir(engine, engine->in_dir, NULL), {
    PFATAL("Error loading testcase dir: %s", afl_ret_stringify(err)); 
  });

  OKF("Processed %llu input files.", engine->executions);

  AFL_TRY(engine->funcs.loop(engine), {
    PFATAL("Error fuzzing the target: %s", afl_ret_stringify(err));
  });

  SAYF("Fuzzing ends with all the queue entries fuzzed. No of executions %llu\n", engine->executions);

  /* Let's free everything now. Note that if you've extended any structure,
   * which now contains pointers to any dynamically allocated region, you have
   * to free them yourselves, but the extended structure itself can be de
   * initialized using the deleted functions provided */

  afl_executor_delete(&fsrv->base);
  afl_map_channel_delete(trace_bits_channel);
  afl_observer_delete(&timeout_channel->base);
  afl_mutator_scheduled_delete(mutators_havoc);
  afl_fuzzing_stage_delete(stage);
  afl_fuzz_one_delete(engine->fuzz_one);
  afl_feedback_cov_delete(coverage_feedback);
  for (size_t i = 0; i < engine->feedbacks_count; ++i) {

    afl_feedback_delete((afl_feedback_t *)engine->feedbacks[i]);

  }

  for (size_t i = 0; i < engine->global_queue->feedback_queues_count; ++i) {

    afl_feedback_queue_delete(engine->global_queue->feedback_queues[i]);

  }

  afl_global_queue_delete(engine->global_queue);
  afl_engine_delete(engine);
  return;

}

void *run_broker_thread(void *data) {

  (void)data;
  llmp_broker_run(llmp_broker);
  return 0;

}

/* Main entry point function */
int main(int argc, char **argv) {

  if (argc < 4) {

    FATAL(
        "Usage: ./forking-fuzzer /input/directory number_of_threads "
        "target [target_args]");

  }

  char *in_dir = argv[1];
  char *target_path = argv[3];
  int   thread_count = atoi(argv[2]);

  /* A global array of all the registered engines */
  afl_engine_t **registered_fuzz_workers = NULL;
  u64            fuzz_workers_count = 0;

  if (thread_count <= 0) { FATAL("Number of threads should be greater than 0"); }

  // Time for llmp POC :)
  broker_port = 0XAF1;
  llmp_broker = llmp_broker_new();
  if (!llmp_broker) { FATAL("Broker creation failed"); }
  if (!llmp_broker_register_local_server(llmp_broker, broker_port)) { FATAL("Broker register failed"); }

  OKF("Broker created now");

  for (int i = 0; i < thread_count; ++i) {

    char **target_args = afl_argv_cpy_dup(argc, argv);
    if (!target_args) { PFATAL("Error allocating args"); }

    afl_engine_t *engine = initialize_engine_instance(target_path, in_dir, target_args);

    if (!llmp_broker_register_threaded_clientloop(llmp_broker, fuzzer_process_main, engine)) {

      FATAL("Error registering client");

    };

    fuzz_workers_count++;
    registered_fuzz_workers = afl_realloc(registered_fuzz_workers, fuzz_workers_count * sizeof(afl_engine_t *));
    if (!registered_fuzz_workers) { PFATAL("Could not allocated mem for fuzzer"); }
    registered_fuzz_workers[fuzz_workers_count - 1] = engine;

  }

  u64 time_elapsed = 1;

  if (!llmp_broker_launch_clientloops(llmp_broker)) { FATAL("Error running broker clientloops"); }

  OKF("Broker started running");

  while (true) {

    llmp_broker_once(llmp_broker);

    usleep(500);
    u64 execs = 0;
    u64 crashes = 0;
    for (size_t i = 0; i < fuzz_workers_count; ++i) {

      // TODO: As in-mem-fuzzer
      execs += registered_fuzz_workers[i]->executions;
      crashes += registered_fuzz_workers[i]->crashes;

    }

    SAYF(
        "Execs: %8llu\tCrashes: %4llu\tExecs per second: %5llu  time elapsed: "
        "%8llu\r",
        execs, crashes, execs / time_elapsed, time_elapsed);
    time_elapsed++;
    fflush(0);

  }

}

