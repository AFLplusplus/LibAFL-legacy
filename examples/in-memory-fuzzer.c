/* An in mmeory fuzzing example. Fuzzer for libpng library */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "aflpp.h"
#include "png.h"

#define LLMP_TAG_EXEC_STATS 0x30

typedef struct client_stats {

  u64 total_execs;

} client_stats_t;

/* stats about the current run */
typedef struct fuzzer_stats {

  u64                   queue_entry_count;
  struct client_stats   *clients;

} fuzzer_stats_t;

extern u8 *__afl_area_ptr;

afl_exit_t harness_func(afl_executor_t *executor, u8 *input, size_t len) {

  (void) executor;

  png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

  png_set_user_limits(png_ptr, 65535, 65535);
  png_infop info_ptr = png_create_info_struct(png_ptr);
  png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

  if (setjmp(png_jmpbuf(png_ptr))) { return AFL_EXIT_OK; }

  png_set_progressive_read_fn(png_ptr, NULL, NULL, NULL, NULL);
  png_process_data(png_ptr, info_ptr, input, len);

  return AFL_EXIT_OK;

}

u8 execute(afl_engine_t *engine, afl_input_t *input) {

  size_t      i;
  afl_executor_t *executor = engine->executor;

  executor->funcs.observers_reset(executor);
  executor->funcs.place_input_cb(executor, input);

  // TODO move to execute_init()
  if (unlikely(engine->start_time == 0)) {

    engine->start_time = afl_get_cur_time();
    engine->last_update = afl_get_cur_time_s();

  }

  afl_exit_t run_result = executor->funcs.run_target_cb(executor);

  engine->executions++;

  /* We've run the target with the executor, we can now simply postExec call the
   * observation channels*/

  if (engine->executions % 12345 && engine->last_update < afl_get_cur_time_s()) {

    llmp_client_state_t *llmp_client = engine->llmp_client;
    llmp_message_t *     msg = llmp_client_alloc_next(llmp_client, sizeof(u64));
    msg->tag = LLMP_TAG_EXEC_STATS;
    u64 *x = (u64 *)msg->buf;
    *x = engine->executions;
    llmp_client_send(llmp_client, msg);
    engine->last_update = afl_get_cur_time_s();

  }

  for (i = 0; i < executor->observors_count; ++i) {

    afl_observer_t *obs_channel = executor->observors[i];
    if (obs_channel->funcs.post_exec) { obs_channel->funcs.post_exec(executor->observors[i], engine); }

  }

  // Now based on the return of executor's run target, we basically return an
  // afl_ret_t type to the callee

  switch (run_result) {

    case AFL_EXIT_OK:
    case AFL_EXIT_TIMEOUT:
      return AFL_RET_SUCCESS;
    default: {

      engine->crashes++;
      dump_crash_to_file(executor->current_input, engine);  // Crash written
      return AFL_RET_WRITE_TO_CRASH;

    }

  }

}

/* This initializeds the fuzzer */ 
afl_engine_t *initialize_fuzzer(char *in_dir, char *queue_dirpath) {

  /* Let's create an in-memory executor */
  in_memory_executor_t *in_memory_executor = calloc(1, sizeof(in_memory_executor_t));
  if (!in_memory_executor) { PFATAL("Unable to allocate mem."); }
  in_memory_executor_init(in_memory_executor, harness_func);

  /* Observation channel, map based, we initialize this ourselves since we don't
   * actually create a shared map */
  afl_map_based_channel_t *trace_bits_channel = calloc(1, sizeof(afl_map_based_channel_t));
  afl_observer_init(&trace_bits_channel->base, MAP_CHANNEL_ID);
  if (!trace_bits_channel) { FATAL("Trace bits channel error %s", afl_ret_stringify(AFL_RET_ALLOC)); }

  /* Since we don't use map_channel_create function, we have to add reset
   * function manually */
  trace_bits_channel->base.funcs.reset = afl_map_channel_reset;

  trace_bits_channel->shared_map.map = __afl_area_ptr;  // Coverage "Map" we have
  trace_bits_channel->shared_map.map_size = MAP_SIZE;
  trace_bits_channel->shared_map.shm_id = -1;  // Just a simple erronous value :)
  in_memory_executor->base.funcs.observer_add(&in_memory_executor->base, &trace_bits_channel->base);

  /* We create a simple feedback queue for coverage here*/
  afl_queue_feedback_t *coverage_feedback_queue = afl_feedback_queue_new(NULL, (char *)"Coverage feedback queue");
  if (!coverage_feedback_queue) { FATAL("Error initializing feedback queue"); }
  coverage_feedback_queue->base.funcs.set_dirpath(&coverage_feedback_queue->base, queue_dirpath);

  /* Global queue creation */
  afl_queue_global_t *global_queue = afl_global_queue_new();
  if (!global_queue) { FATAL("Error initializing global queue"); }
  global_queue->extra_funcs.add_feedback_queue(global_queue, coverage_feedback_queue);
  global_queue->base.funcs.set_dirpath(&global_queue->base, queue_dirpath);

  /* Coverage Feedback initialization */
  afl_feedback_cov_t *coverage_feedback =
      afl_feedback_cov_new(coverage_feedback_queue, trace_bits_channel->shared_map.map_size, MAP_CHANNEL_ID);
  if (!coverage_feedback) { FATAL("Error initializing feedback"); }

  /* Let's build an engine now */
  afl_engine_t *engine = afl_engine_new(&in_memory_executor->base, NULL, global_queue);
  if (!engine) { FATAL("Error initializing Engine"); }
  engine->funcs.add_feedback(engine, &coverage_feedback->base);
  engine->funcs.set_global_queue(engine, global_queue);
  engine->in_dir = in_dir;
  engine->funcs.execute = execute;

  afl_fuzz_one_t *fuzz_one = afl_fuzz_one_new(engine);
  if (!fuzz_one) { FATAL("Error initializing fuzz_one"); }

  // We also add the fuzzone to the engine here.
  engine->funcs.set_fuzz_one(engine, fuzz_one);

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

  afl_fuzzing_stage_t *stage = afl_fuzzing_stage_new(engine);
  if (!stage) { FATAL("Error creating fuzzing stage"); }
  stage->funcs.add_mutator_to_stage(stage, &mutators_havoc->base);

  return engine;

}

void fuzzer_process_main(llmp_client_state_t *llmp_client, void *data) {

  afl_engine_t *engine = (afl_engine_t *)data;
  engine->llmp_client = llmp_client;

  afl_map_based_channel_t *trace_bits_channel = (afl_map_based_channel_t *)engine->executor->observors[0];

  afl_fuzzing_stage_t *    stage = (afl_fuzzing_stage_t *)engine->fuzz_one->stages[0];
  afl_mutator_scheduled_t *mutators_havoc = (afl_mutator_scheduled_t *)stage->mutators[0];

  afl_feedback_cov_t *coverage_feedback = (afl_feedback_cov_t *)(engine->feedbacks[0]);

  /* Now we can simply load the testcases from the directory given */
  AFL_TRY(engine->funcs.load_testcases_from_dir(engine, engine->in_dir, NULL), {
    PFATAL("Error loading testcase dir: %s", afl_ret_stringify(err)); 
  });

  AFL_TRY(engine->funcs.loop(engine), {
    PFATAL("Error fuzzing the target: %s", afl_ret_stringify(err));
  });

  SAYF("Fuzzing ends with all the queue entries fuzzed. No of executions %llu\n", engine->executions);

  /* Let's free everything now. Note that if you've extended any structure,
   * which now contains pointers to any dynamically allocated region, you have
   * to free them yourselves, but the extended structure itself can be de
   * initialized using the deleted functions provided */

  afl_executor_delete(engine->executor);
  afl_map_channel_delete(trace_bits_channel);
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

}

/* A hook to keep stats in the broker thread */
bool message_hook(llmp_broker_t *broker, llmp_client_state_t *client, llmp_message_t *msg, void *data) {

  (void)broker;
  if (msg->tag == LLMP_TAG_NEW_QUEUE_ENTRY) {

    ((fuzzer_stats_t *)data)->queue_entry_count++;

  } else if (msg->tag == LLMP_TAG_EXEC_STATS) {

    ((fuzzer_stats_t *)data)->clients[client->id - 1].total_execs = *(u64 *)msg->buf;

  }

  return true;

}

int main(int argc, char **argv) {

  if (argc < 4) {

    FATAL("Usage: ./in-memory-fuzzer number_of_threads /path/to/input/dir /path/to/queue/dir");

  }

  s32 i = 0;
  int status = 0;
  int pid = 0;

  char *in_dir = argv[2];
  int   thread_count = atoi(argv[1]);
  char *queue_dirpath = argv[3];

  if (thread_count <= 0) { FATAL("Number of threads should be greater than 0"); }

  int broker_port = 0xAF1;

  llmp_broker_t *llmp_broker = llmp_broker_new();
  if (!llmp_broker) { FATAL("Broker creation failed"); }
  /* This is not necessary but gives us the option to add additional processes to the fuzzer at runtime. */
  if (!llmp_broker_register_local_server(llmp_broker, broker_port)) { FATAL("Broker register failed"); }

  OKF("Broker created now");

  /* The message hook will intercept all messages from all clients - and listen for stats. */
  fuzzer_stats_t fuzzer_stats = {0};
  llmp_broker_add_message_hook(llmp_broker, message_hook, &fuzzer_stats);
  fuzzer_stats.clients = malloc(thread_count * sizeof(client_stats_t));
  if (!fuzzer_stats.clients) { PFATAL("Unable to alloc memory"); }

  for (i = 0; i < thread_count; i++) {

    afl_engine_t *engine = initialize_fuzzer(in_dir, queue_dirpath);

    /* All fuzzers get their own process.
    This call only allocs the data structures, but not fork yet. */
    if (!llmp_broker_register_childprocess_clientloop(llmp_broker, fuzzer_process_main, engine)) {

      FATAL("Error registering client");

    }

    fuzzer_stats.clients[i].total_execs = 0;

  }

  // Before we start the broker, we close the stderr file. Since the in-mem
  // fuzzer runs in the same process, this is necessary for stats collection.

  s32 dev_null_fd = open("/dev/null", O_WRONLY);

  if (!getenv("DEBUG") && !getenv("AFL_DEBUG")) { dup2(dev_null_fd, 2); }

  u64 time_prev = 0;
  u64 time_initial = afl_get_cur_time_s();
  u64 time_cur = time_initial;

  /* This spawns all registered clientloops:
  - The tcp server to add more clients (pthreads)
  - all fuzzer instances (using fork()) */
  llmp_broker_launch_clientloops(llmp_broker);

  OKF("Clients started running");
  sleep(1);

  while (1) {

    /* Forward all messages that arrived in the meantime */
    llmp_broker_once(llmp_broker);
    usleep(100);

    /* Paint ui every second */
    if ((time_cur = afl_get_cur_time_s()) > time_prev) {

      u64 time_elapsed = (time_cur - time_initial);
      time_prev = time_cur;
      u64 total_execs = 0;
      for (i = 0; i < thread_count; i++) {
        total_execs += fuzzer_stats.clients[i].total_execs;
      }

      /* TODO: Send heartbeat messages from clients for more stats :) */

      SAYF("threads=%u  paths=%llu  elapsed=%llu  execs=%llu  exec/s=%llu\r", thread_count,
           fuzzer_stats.queue_entry_count, time_elapsed, total_execs, total_execs / time_elapsed);

      fflush(stdout);

      if ((pid = waitpid(-1, &status, WNOHANG)) > 0) {

        // this pid is gone
        // restart it
        // clean shm?

        // TODO
        fprintf(stderr, "TODO: implement child re-fork\n");

      }

    }

  }

  return 0;

}

