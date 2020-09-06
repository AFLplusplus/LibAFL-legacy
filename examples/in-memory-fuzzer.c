/* An in mmeory fuzzing example. Fuzzer for libpng library */

#include <stdio.h>
#include "aflpp.h"
#include "png.h"

/* stats about the current run */
typedef struct fuzzer_stats {

  u64 queue_entry_count;

} fuzzer_stats_t;

extern u8 *__afl_area_ptr;

llmp_broker_state_t *llmp_broker;
int                  broker_port;

/* A global array of all the registered engines */
pthread_mutex_t fuzz_worker_array_lock;
engine_t *      registered_fuzz_workers[MAX_WORKERS];
u64             fuzz_workers_count;

/* Function to register/add a fuzz worker (engine). To avoid race condition, add
 * mutex here(Won't be performance problem). */
static inline afl_ret_t afl_register_fuzz_worker(engine_t *engine) {

  // Critical section. Needs a lock. Called very rarely, thus won't affect perf.
  pthread_mutex_lock(&fuzz_worker_array_lock);

  if (fuzz_workers_count >= MAX_WORKERS) {

    pthread_mutex_unlock(&fuzz_worker_array_lock);
    return AFL_RET_ARRAY_END;

  }

  registered_fuzz_workers[fuzz_workers_count] = engine;
  fuzz_workers_count++;
  // Unlock the mutex
  pthread_mutex_unlock(&fuzz_worker_array_lock);
  return AFL_RET_SUCCESS;

}

exit_type_t harness_func(u8 *input, size_t len) {

  png_structp png_ptr =
      png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

  png_set_user_limits(png_ptr, 65535, 65535);
  png_infop info_ptr = png_create_info_struct(png_ptr);
  png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

  if (setjmp(png_jmpbuf(png_ptr))) { return NORMAL; }

  png_set_progressive_read_fn(png_ptr, NULL, NULL, NULL, NULL);
  png_process_data(png_ptr, info_ptr, input, len);

  return NORMAL;

}

engine_t *initialize_fuzz_instance(char *in_dir, char *queue_dirpath) {

  /* Let's create an in-memory executor */
  in_memory_executor_t *in_memory_executor =
      calloc(1, sizeof(in_memory_executor_t));
  if (!in_memory_executor) { FATAL("%s", afl_ret_stringify(AFL_RET_ALLOC)); }
  in_memory_executor_init(in_memory_executor, harness_func);

  /* Observation channel, map based, we initialize this ourselves since we don't
   * actually create a shared map */
  map_based_channel_t *trace_bits_channel =
      calloc(1, sizeof(map_based_channel_t));
  afl_observation_channel_init(&trace_bits_channel->base, MAP_CHANNEL_ID);
  if (!trace_bits_channel) {

    FATAL("Trace bits channel error %s", afl_ret_stringify(AFL_RET_ALLOC));

  }

  /* Since we don't use map_channel_create function, we have to add reset
   * function manually */
  trace_bits_channel->base.funcs.reset = afl_map_channel_reset;

  trace_bits_channel->shared_map.map =
      __afl_area_ptr;  // Coverage "Map" we have
  trace_bits_channel->shared_map.map_size = MAP_SIZE;
  trace_bits_channel->shared_map.shm_id =
      -1;  // Just a simple erronous value :)
  in_memory_executor->base.funcs.add_observation_channel(
      &in_memory_executor->base, &trace_bits_channel->base);

  /* We create a simple feedback queue for coverage here*/
  feedback_queue_t *coverage_feedback_queue =
      afl_feedback_queue_create(NULL, (char *)"Coverage feedback queue");
  if (!coverage_feedback_queue) { FATAL("Error initializing feedback queue"); }
  coverage_feedback_queue->base.funcs.set_dirpath(
      &coverage_feedback_queue->base, queue_dirpath);

  /* Global queue creation */
  global_queue_t *global_queue = afl_global_queue_create();
  if (!global_queue) { FATAL("Error initializing global queue"); }
  global_queue->extra_funcs.add_feedback_queue(global_queue,
                                               coverage_feedback_queue);
  global_queue->base.funcs.set_dirpath(&global_queue->base, queue_dirpath);

  /* Coverage Feedback initialization */
  maximize_map_feedback_t *coverage_feedback = map_feedback_init(
      coverage_feedback_queue, trace_bits_channel->shared_map.map_size,
      MAP_CHANNEL_ID);
  if (!coverage_feedback) { FATAL("Error initializing feedback"); }

  /* Let's build an engine now */
  engine_t *engine =
      afl_engine_create(&in_memory_executor->base, NULL, global_queue);
  if (!engine) { FATAL("Error initializing Engine"); }
  engine->funcs.add_feedback(engine, (feedback_t *)coverage_feedback);
  engine->funcs.set_global_queue(engine, global_queue);
  engine->in_dir = in_dir;

  fuzz_one_t *fuzz_one = afl_fuzz_one_create(engine);
  if (!fuzz_one) { FATAL("Error initializing fuzz_one"); }

  // We also add the fuzzone to the engine here.
  engine->funcs.set_fuzz_one(engine, fuzz_one);

  scheduled_mutator_t *mutators_havoc = afl_scheduled_mutator_create(NULL, 8);
  if (!mutators_havoc) { FATAL("Error initializing Mutators"); }

  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, flip_byte_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_2_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          flip_4_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          delete_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, clone_bytes_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, flip_bit_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, flip_2_bits_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, flip_4_bits_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc,
                                          random_byte_add_sub_mutation);
  mutators_havoc->extra_funcs.add_mutator(mutators_havoc, random_byte_mutation);

  fuzzing_stage_t *stage = afl_fuzzing_stage_create(engine);
  if (!stage) { FATAL("Error creating fuzzing stage"); }
  stage->funcs.add_mutator_to_stage(stage, &mutators_havoc->base);

  return engine;

}

void thread_run_instance(llmp_client_state_t *llmp_client, void *data) {

  engine_t *engine = (engine_t *)data;
  engine->llmp_client = llmp_client;

  map_based_channel_t *trace_bits_channel =
      (map_based_channel_t *)engine->executor->observors[0];

  fuzzing_stage_t *    stage = (fuzzing_stage_t *)engine->fuzz_one->stages[0];
  scheduled_mutator_t *mutators_havoc =
      (scheduled_mutator_t *)stage->mutators[0];

  maximize_map_feedback_t *coverage_feedback =
      (maximize_map_feedback_t *)(engine->feedbacks[0]);

  /* Now we can simply load the testcases from the directory given */
  afl_ret_t ret =
      engine->funcs.load_testcases_from_dir(engine, engine->in_dir, NULL);
  if (ret != AFL_RET_SUCCESS) {

    PFATAL("Error loading testcase dir: %s", afl_ret_stringify(ret));

  }

  afl_ret_t fuzz_ret = engine->funcs.loop(engine);

  if (fuzz_ret != AFL_RET_SUCCESS) {

    PFATAL("Error fuzzing the target: %s", afl_ret_stringify(fuzz_ret));

  }

  SAYF(
      "Fuzzing ends with all the queue entries fuzzed. No of executions %llu\n",
      engine->executions);

  /* Let's free everything now. Note that if you've extended any structure,
   * which now contains pointers to any dynamically allocated region, you have
   * to free them yourselves, but the extended structure itself can be de
   * initialized using the deleted functions provided */

  afl_executor_delete(engine->executor);
  afl_map_channel_delete(trace_bits_channel);
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

}

/* A hook to keep stats in the broker thread */
bool message_hook(llmp_broker_state_t *broker, llmp_message_t *msg, void *data) {

  (void)broker;
  if (msg->tag == LLMP_TAG_NEW_QUEUE_ENTRY) {
    ((fuzzer_stats_t *)data)->queue_entry_count++;
  }
  return true;

}



int main(int argc, char **argv) {

  if (argc < 4) {

    FATAL(
        "Usage: ./in-memory-fuzzer  number_of_threads /path/to/input/dir "
        "/path/to/queue/dir");

  }

  char *in_dir = argv[2];
  int   thread_count = atoi(argv[1]);
  char *queue_dirpath = argv[3];

  if (thread_count <= 0) {

    FATAL("Number of threads should be greater than 0");

  }

  broker_port = 0xAF1;
  llmp_broker = llmp_broker_new();
  if (!llmp_broker) { FATAL("Broker creation failed"); }
  if (!llmp_broker_register_local_server(llmp_broker, broker_port)) {

    FATAL("Broker register failed");

  }

  OKF("Broker created now");

  fuzzer_stats_t fuzzer_stats = {0};
  llmp_broker_add_message_hook(llmp_broker, message_hook, &fuzzer_stats);

  for (int i = 0; i < thread_count; ++i) {

    engine_t *engine = initialize_fuzz_instance(in_dir, queue_dirpath);

    if (!llmp_broker_register_threaded_clientloop(
            llmp_broker, thread_run_instance, engine)) {

      FATAL("Error registering client");

    }

    if (afl_register_fuzz_worker(engine) != AFL_RET_SUCCESS) {

      FATAL("Error registering fuzzing instance");

    }

  }

  // Before we start the broker, we close the stderr file. Since the in-mem
  // fuzzer runs in the same process, this is necessary for stats collection.

  s32 dev_null_fd = open("/dev/null", O_WRONLY);

  dup2(dev_null_fd, 2);

  u64 time_prev = 0;
  u64 time_initial = afl_get_cur_time();
  u64 time_cur = time_initial;

  llmp_broker_launch_clientloops(llmp_broker);

  OKF("Clients started running");

  while (1) {

    /* Forward all messages that arrived in the meantime */
    llmp_broker_once(llmp_broker);
    usleep(50);

    /* Paint ui every few seconds */
    if ((time_cur = afl_get_cur_time()) > time_prev + 3) {

      u64 time_elapsed = time_cur - time_initial;

      /* TODO: Send heartbeat messages from clients for more stats :) */

      SAYF("Paths: %llu, time elapsed: %8llu\r", fuzzer_stats.queue_entry_count, time_elapsed / 1000);

      fflush(stdout);

    }

  }

  return 0;

}

