/* An in mmeory fuzzing example. Fuzzer for libpng library */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "aflpp.h"
#include "llmp.h"
#include "shmem.h"
#include "afl-returns.h"

/* Time after which we kill the clients */
#define KILL_IDLE_CLIENT_MS (10000)

/* Heartbeat message subprocesses send to the main broker every few secs */
#define LLMP_TAG_EXEC_STATS_V1 (0xEC574751)
/* Ooops! we found a crash :) - Let's hope it was in the target... */
#define LLMP_TAG_CRASH_V1 (0x101DEAD1)
#define LLMP_TAG_TIMEOUT_V1 (0xA51EE851)

int                       LLVMFuzzerTestOneInput(const uint8_t *, size_t);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

/* That's where the target's intrumentation feedback gets reported to */
extern u8 *__afl_area_ptr;
extern u32 __afl_map_size;

/* pointer to the bitmap used by map-absed feedback, we'll report it if we crash. */
static u8 *virgin_bits;
/* The current client this process works on. We need this for our segfault handler */
static llmp_client_t *current_client = NULL;
/* Ptr to the message we're trying to fuzz right now - in case we crash... */
static llmp_message_t *    current_fuzz_input_msg = NULL;
static afl_queue_global_t *global_queue;
static afl_input_t *       current_input = NULL;
static int                 debug = 0;
static char *              queue_dirpath;
static ssize_t             calibration_idx = -1;

typedef struct cur_state {

  ssize_t calibration_idx;
  u64     new_execs;
  size_t  map_size;
  size_t  current_input_len;
  u8      payload[];

} cur_state_t;

/* Stats message the client will send every once in a while */
typedef struct broker_client_stats {

  u64 total_execs;
  u64 crashes;
  u32 last_msg_time;

} broker_client_stats_t;

/* all stats about the current run */
typedef struct fuzzer_stats {

  u64                         queue_entry_count;
  u64                         crashes;
  u64                         timeouts;
  struct broker_client_stats *clients;

} fuzzer_stats_t;

int debug_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  u32 i;
  fprintf(stderr, "Enter harness function %p %lu\n", data, size);
  for (i = 0; i < __afl_map_size; i++)
    if (__afl_area_ptr[i])
      fprintf(stderr, "Error: map unclean before harness: map[%04x]=0x%02x\n", i, __afl_area_ptr[i]);

  int ret = LLVMFuzzerTestOneInput(data, size);

  fprintf(stderr, "MAP:");
  for (i = 0; i < __afl_map_size; i++)
    if (__afl_area_ptr[i]) fprintf(stderr, " map[%04x]=0x%02x", i, __afl_area_ptr[i]);
  fprintf(stderr, "\n");

  return ret;

}

/* The actual harness call: LLVMFuzzerTestOneInput */
afl_exit_t harness_func(afl_executor_t *executor, u8 *input, size_t len) {

  (void)executor;

  LLVMFuzzerTestOneInput(input, len);

  return AFL_EXIT_OK;

}

/* The actual harness call: LLVMFuzzerTestOneInput */
afl_exit_t debug_harness_func(afl_executor_t *executor, u8 *input, size_t len) {

  (void)executor;

  debug_LLVMFuzzerTestOneInput(input, len);

  return AFL_EXIT_OK;

}

/* Initializer: run initial seeds and run LLVMFuzzerInitialize */
static afl_ret_t in_memory_fuzzer_initialize(afl_executor_t *executor) {

  in_memory_executor_t *in_memory_fuzzer = (in_memory_executor_t *)executor;

  if (LLVMFuzzerInitialize) { LLVMFuzzerInitialize(&in_memory_fuzzer->argc, &in_memory_fuzzer->argv); }

  global_queue = in_memory_fuzzer->global_queue;

  fprintf(stderr, "Calibration todo %ld\n", calibration_idx);
  sleep(1);
  while (calibration_idx > 0) {

    --calibration_idx;
    fprintf(stderr, "Seed %ld\n", calibration_idx);
    afl_entry_t *queue_entry = in_memory_fuzzer->global_queue->base.funcs.get_queue_entry(
        (afl_queue_t *)in_memory_fuzzer->global_queue, calibration_idx);
    if (queue_entry && !queue_entry->info->skip_entry) {

      fprintf(stderr, "Seed %ld testing ...\n", calibration_idx);
      if (afl_stage_run(in_memory_fuzzer->stage, queue_entry->input, false) != AFL_RET_SUCCESS) {

        WARNF("Queue entry %ld misbehaved, disabling...", calibration_idx);
        queue_entry->info->skip_entry = 1;

      }

    }

  }

  calibration_idx = -1;  // we are done

  return AFL_RET_SUCCESS;

}

void write_cur_state(llmp_message_t *out_msg) {

  if (out_msg->buf_len < sizeof(cur_state_t) + __afl_map_size + current_input->len) {

    FATAL("Message not large enough for our state!");

  }

  /* first virgin bits[map_size], then the crasing/timeouting input buf */
  cur_state_t *state = LLMP_MSG_BUF_AS(out_msg, cur_state_t);
  state->map_size = __afl_map_size;
  memcpy(state->payload, virgin_bits, state->map_size);
  state->current_input_len = current_input->len;
  state->calibration_idx = calibration_idx;
  memcpy(state->payload + state->map_size, current_input->bytes, current_input->len);

}

static void handle_timeout(int sig, siginfo_t *info, void *ucontext) {

  (void)sig;
  (void)info;
  (void)ucontext;

  DBG("TIMEOUT/SIGUSR2 received.");

  if (!current_fuzz_input_msg) {

    if (debug) WARNF("SIGUSR/timeout happened, but not currently fuzzing!");
    return;

  }

  if (current_fuzz_input_msg->buf_len != sizeof(cur_state_t) + __afl_map_size + current_input->len) {

    FATAL("Unexpected current_fuzz_input_msg length during timeout handling!");

  }

  if (calibration_idx && global_queue) {

    afl_entry_t *queue_entry = global_queue->base.funcs.get_queue_entry((afl_queue_t *)global_queue, calibration_idx);

    if (queue_entry && !queue_entry->info->skip_entry) {

      WARNF("Seed entry %ld timed out, disabling...", calibration_idx);
      queue_entry->info->skip_entry = 1;

    }

  }

  write_cur_state(current_fuzz_input_msg);
  current_fuzz_input_msg->tag = LLMP_TAG_TIMEOUT_V1;
  if (!llmp_client_send(current_client, current_fuzz_input_msg)) { FATAL("Error sending timeout info!"); }
  DBG("We sent off the timeout at %p. Now waiting for broker to kill us :)", info->si_addr);

  llmp_page_t *current_out_map = shmem2page(&current_client->out_maps[current_client->out_map_count - 1]);

  /* Wait for broker to map this page, so our work is done. Broker will restart this fuzzer */
  while (!current_out_map->save_to_unmap) {

    usleep(10);

  }

  DBG("Exiting client.");
  FATAL("TIMOUT");

}

static void handle_crash(int sig, siginfo_t *info, void *ucontext) {

  (void)sig;
  (void)ucontext;

  /* TODO: write info and ucontext to sharedmap */

  if (!current_client) {

    WARNF("We died accessing addr %p, but are not in a client...", info->si_addr);
    fflush(stdout);
    /* let's crash */
    return;

  }

  if (calibration_idx && global_queue) {

    afl_entry_t *queue_entry = global_queue->base.funcs.get_queue_entry((afl_queue_t *)global_queue, calibration_idx);

    if (queue_entry && !queue_entry->info->skip_entry) {

      WARNF("Seed entry %ld crashed, disabling...", calibration_idx);
      queue_entry->info->skip_entry = 1;

    }

  }

  llmp_page_t *current_out_map = shmem2page(&current_client->out_maps[current_client->out_map_count - 1]);
  /* TODO: Broker should probably check for sender_dead and restart us? */
  current_out_map->sender_dead = true;

  if (current_fuzz_input_msg) {

    if (!current_input ||
        current_fuzz_input_msg->buf_len != sizeof(cur_state_t) + __afl_map_size + current_input->len) {

      FATAL("Unexpected current_fuzz_input_msg length during crash handling!");

    }

    write_cur_state(current_fuzz_input_msg);
    llmp_client_send(current_client, current_fuzz_input_msg);
    DBG("We sent off the crash at %p. Now waiting for broker...", info->si_addr);

  } else {

    DBG("We died at %p, but didn't crash in the target :( - Waiting for the broker.", info->si_addr);

  }

  /* Wait for broker to map this page, so our work is done. Broker will restart this fuzzer */
  while (!current_out_map->save_to_unmap) {

    usleep(10);

  }

  DBG("Returning from crash handler.");
  /* let's crash */

}

static void setup_signal_handlers(void) {

  struct sigaction sa = {0};

  memset(&sa, 0, sizeof(sigaction));
  sigemptyset(&sa.sa_mask);

  sa.sa_flags = SA_NODEFER | SA_SIGINFO;
  sa.sa_sigaction = handle_crash;

  /* Handle segfaults by writing the crashing input to the shared map, then exiting */
  if (sigaction(SIGSEGV, &sa, NULL) < 0) { PFATAL("Could not set segfault handler"); }
  if (sigaction(SIGBUS, &sa, NULL) < 0) { PFATAL("Could not set sigbus handler"); }
  if (sigaction(SIGABRT, &sa, NULL) < 0) { PFATAL("Could not set abort handler"); }
  if (sigaction(SIGILL, &sa, NULL) < 0) { PFATAL("Could not set illegal instruction handler"); }
  if (sigaction(SIGFPE, &sa, NULL) < 0) { PFATAL("Could not set fp exception handler"); }

  /* If the broker notices we didn't send anything for a long time, it kills us using SIGUSR2 */
  sa.sa_sigaction = handle_timeout;
  if (sigaction(SIGUSR2, &sa, NULL) < 0) { PFATAL("Could not set sigusr handler"); }

}

void client_send_stats(afl_engine_t *engine) {

  llmp_client_t * llmp_client = engine->llmp_client;
  llmp_message_t *msg = llmp_client_alloc_next(llmp_client, sizeof(u64));
  msg->tag = LLMP_TAG_EXEC_STATS_V1;
  u64 *x = (u64 *)msg->buf;
  *x = engine->executions;
  engine->executions = 0;
  llmp_client_send(llmp_client, msg);
  engine->last_update = afl_get_cur_time_s();

}

u8 execute(afl_engine_t *engine, afl_input_t *input) {

  size_t          i;
  afl_executor_t *executor = engine->executor;

  /* Check for engine to be configured properly. Only to check setup in newly forked threads so debug only */
  // AFL_TRY(afl_engine_check_configuration(engine), { FATAL("Engine configured incompletely"); });

  executor->funcs.observers_reset(executor);
  executor->funcs.place_input_cb(executor, input);

  // TODO move to execute_init()
  if (unlikely(engine->start_time == 0)) {

    engine->executions = 0;
    engine->start_time = afl_get_cur_time();
    engine->last_update = afl_get_cur_time_s();
    client_send_stats(engine);

  }

  /* TODO: use the msg buf in input directly */
  current_input = input;
  current_fuzz_input_msg =
      llmp_client_alloc_next(engine->llmp_client, sizeof(cur_state_t) + __afl_map_size + input->len);
  if (!current_fuzz_input_msg) { FATAL("Could not allocate crash message. Quitting!"); }

  /* we may crash, who knows.
  TODO: Actually use this buffer to mutate and fuzz, saves us copy time. */
  current_fuzz_input_msg->tag = LLMP_TAG_CRASH_V1;

  afl_exit_t run_result = executor->funcs.run_target_cb(executor);
  engine->executions++;

  /* we didn't crash. Cancle msg sending.
  TODO: Reuse this msg in case the testacse is interesting! */
  llmp_client_cancel(engine->llmp_client, current_fuzz_input_msg);
  current_fuzz_input_msg = NULL;

  /* We've run the target with the executor, we can now simply postExec call the
   * observation channels*/
  for (i = 0; i < executor->observors_count; ++i) {

    afl_observer_t *obs_channel = executor->observors[i];
    if (obs_channel->funcs.post_exec) { obs_channel->funcs.post_exec(executor->observors[i], engine); }

  }

  // Now based on the return of executor's run target, we basically return an
  // afl_ret_t type to the callee

  /* Gather some stats */
  if (unlikely(engine->executions % 123 && engine->last_update < afl_get_cur_time_s())) { client_send_stats(engine); }

  switch (run_result) {

    case AFL_EXIT_OK:
    case AFL_EXIT_TIMEOUT:
      return AFL_RET_SUCCESS;
    default: {

      /* TODO: We'll never reach this, actually... */
      if (afl_input_dump_to_crashfile(executor->current_input, queue_dirpath) == AFL_RET_SUCCESS) engine->crashes++;
      return AFL_RET_WRITE_TO_CRASH;

    }

  }

}

/* This initializes the fuzzer */
afl_engine_t *initialize_fuzzer(char *in_dir, char *queue_dir, int argc, char *argv[], u32 instance) {

  (void)(instance);

  /* Let's create an in-memory executor */
  in_memory_executor_t *in_memory_executor = calloc(1, sizeof(in_memory_executor_t));
  if (!in_memory_executor) { PFATAL("Unable to allocate mem."); }
  if (debug == 1234) {  // TODO FIXME

    in_memory_executor_init(in_memory_executor, debug_harness_func);

  } else {

    in_memory_executor_init(in_memory_executor, harness_func);

  }

  in_memory_executor->argc = argc;
  in_memory_executor->argv = afl_argv_cpy_dup(argc, argv);
  // in_memory_executor->base.funcs.init_cb = in_memory_fuzzer_initialize;

  /* Observation channel, map based, we initialize this ourselves since we don't
   * actually create a shared map */
  afl_observer_covmap_t *observer_covmap = afl_observer_covmap_new(__afl_map_size);
  if (!observer_covmap) { PFATAL("Trace bits channel error"); }

  /* covmap new creates a covmap automatically. deinit here. */
  afl_shmem_deinit(&observer_covmap->shared_map);

  observer_covmap->shared_map.map = __afl_area_ptr;  // Coverage "Map" we have
  observer_covmap->shared_map.map_size = __afl_map_size;
  observer_covmap->shared_map.shm_id = -1;
  in_memory_executor->base.funcs.observer_add(&in_memory_executor->base, &observer_covmap->base);

  /* We create a simple feedback queue for coverage here*/
  afl_queue_feedback_t *coverage_feedback_queue = afl_queue_feedback_new(NULL, (char *)"Coverage feedback queue");
  if (!coverage_feedback_queue) { FATAL("Error initializing feedback queue"); }
  coverage_feedback_queue->base.funcs.set_dirpath(&coverage_feedback_queue->base, queue_dir);

  /* Global queue creation */
  afl_queue_global_t *new_global_queue = afl_queue_global_new();
  if (!new_global_queue) { FATAL("Error initializing global queue"); }
  new_global_queue->funcs.add_feedback_queue(new_global_queue, coverage_feedback_queue);
  new_global_queue->base.funcs.set_dirpath(&new_global_queue->base, queue_dir);

  /* Coverage Feedback initialization */
  afl_feedback_cov_t *coverage_feedback = afl_feedback_cov_new(coverage_feedback_queue, observer_covmap);
  if (!coverage_feedback) { FATAL("Error initializing feedback"); }

  /* Let's build an engine now */
  afl_engine_t *engine = afl_engine_new(&in_memory_executor->base, NULL, new_global_queue);
  if (!engine) { FATAL("Error initializing Engine"); }
  engine->verbose = 1;
  engine->funcs.add_feedback(engine, &coverage_feedback->base);
  engine->funcs.set_global_queue(engine, new_global_queue);
  engine->in_dir = in_dir;
  engine->funcs.execute = execute;

  afl_fuzz_one_t *fuzz_one = afl_fuzz_one_new(engine);
  if (!fuzz_one) { FATAL("Error initializing fuzz_one"); }

  // We also add the fuzzone to the engine here.
  engine->funcs.set_fuzz_one(engine, fuzz_one);

  afl_mutator_scheduled_t *mutators_havoc = afl_mutator_scheduled_new(engine, 8);
  if (!mutators_havoc) { FATAL("Error initializing Mutators"); }

  AFL_TRY(afl_mutator_scheduled_add_havoc_funcs(mutators_havoc),
          { FATAL("Error adding mutators: %s", afl_ret_stringify(err)); });

  afl_stage_t *stage = afl_stage_new(engine);
  if (!stage) { FATAL("Error creating fuzzing stage"); }
  AFL_TRY(stage->funcs.add_mutator_to_stage(stage, &mutators_havoc->base),
          { FATAL("Error adding mutator: %s", afl_ret_stringify(err)); });
  in_memory_executor->stage = stage;
  in_memory_executor->global_queue = new_global_queue;

  /* Now add the testcases */
  /* first we want to support restarts and read the queue */
  if (queue_dirpath && queue_dirpath[0] != 0)
    engine->funcs.load_testcases_from_dir(engine, queue_dirpath);  // ignore if it fails.
  /* Now we read the seeds from an input directory */
  if (engine->in_dir && engine->in_dir[0] != 0)
    AFL_TRY(engine->funcs.load_testcases_from_dir(engine, engine->in_dir),
            { WARNF("Error loading testcase dir: %s", afl_ret_stringify(err)); });

  // no seeds? add a dummy one
  if (((afl_queue_t *)engine->global_queue)->entries_count == 0) {

    afl_input_t *input = afl_input_new();
    if (!input) { FATAL("Could not create input"); }
    u32 cnt;
    u32 input_len = 64;
    input->len = input_len;
    input->bytes = calloc(input_len + 1, 1);
    if (!input->bytes) { PFATAL("Could not allocate input bytes"); }

    for (cnt = 0; cnt < input_len; cnt++) {

      input->bytes[cnt] = ' ' + cnt;  // values: 0x20 ... 0x60

    }

    input->bytes[input_len] = 0;

    afl_entry_t *new_entry = afl_entry_new(input, NULL);
    if (!new_entry) { FATAL("Could not create new entry"); }
    engine->global_queue->base.funcs.insert(&engine->global_queue->base, new_entry);

  }

  calibration_idx = (ssize_t)((afl_queue_t *)engine->global_queue)->entries_count;
  OKF("Starting seed count: %lu", calibration_idx);

  return engine;

}

void fuzzer_process_main(llmp_client_t *llmp_client, void *data) {

  size_t i;

  /* global variable (ugh) for our signal handler */
  current_client = llmp_client;

  /* We're in the child, capture segfaults and SIGUSR2 from here on.
  (We SIGUSR2 = timeout, delived by the broker when no new messages reached him for a while) */
  setup_signal_handlers();

  afl_engine_t *engine = (afl_engine_t *)data;
  engine->llmp_client = llmp_client;

  afl_observer_covmap_t *observer_covmap = NULL;
  for (i = 0; i < engine->executor->observors_count; i++) {

    if (engine->executor->observors[i]->tag == AFL_OBSERVER_TAG_COVMAP) {

      observer_covmap = (afl_observer_covmap_t *)engine->executor->observors[0];

    }

  }

  if (!observer_covmap) { FATAL("Got no covmap observer"); }

  /* set the global virgin_bits for error handlers, so we can restore them after a crash */
  virgin_bits = observer_covmap->shared_map.map;

  afl_stage_t *            stage = engine->fuzz_one->stages[0];
  afl_mutator_scheduled_t *mutators_havoc = (afl_mutator_scheduled_t *)stage->mutators[0];
  afl_feedback_cov_t *     coverage_feedback = NULL;
  for (i = 0; i < engine->feedbacks_count; i++) {

    if (engine->feedbacks[i]->tag == AFL_FEEDBACK_TAG_COV) {

      coverage_feedback = (afl_feedback_cov_t *)(engine->feedbacks[i]);
      break;

    }

  }

  if (!coverage_feedback) { FATAL("No coverage feedback added to engine"); }

  in_memory_fuzzer_initialize(engine->executor);

  /* The actual fuzzing */
  AFL_TRY(engine->funcs.loop(engine), { PFATAL("Error fuzzing the target: %s", afl_ret_stringify(err)); });

  SAYF("Fuzzing ends with all the queue entries fuzzed. No of executions %llu\n", engine->executions);

  /* Let's free everything now. Note that if you've extended any structure,
   * which now contains pointers to any dynamically allocated region, you have
   * to free them yourselves, but the extended structure itself can be de
   * initialized using the deleted functions provided */

  afl_executor_delete(engine->executor);
  afl_feedback_cov_delete(coverage_feedback);
  afl_observer_covmap_delete(observer_covmap);
  afl_mutator_scheduled_delete(mutators_havoc);
  afl_stage_delete(stage);
  afl_fuzz_one_delete(engine->fuzz_one);

  for (i = 0; i < engine->feedbacks_count; ++i) {

    afl_feedback_delete((afl_feedback_t *)engine->feedbacks[i]);

  }

  for (i = 0; i < engine->global_queue->feedback_queues_count; ++i) {

    afl_queue_feedback_delete(engine->global_queue->feedback_queues[i]);

  }

  afl_queue_global_delete(engine->global_queue);
  afl_engine_delete(engine);

}

/* In the broker, if we find out a client crashed, write the crashing testcase and respawn the child */
bool broker_handle_client_restart(llmp_broker_t *broker, llmp_broker_clientdata_t *clientdata, cur_state_t *state) {

  u32 client_id = clientdata->client_state->id;
  if (!state) {

    WARNF("Illegal state received during crash");
    return false;  // don't forward

  }

  /* Remove this client, then spawn a new client with the current state.*/
  DBG("Removing old/crashed client");

  /* TODO: We should probably waite for the old client pid to finish (or kill it?) before creating a new one */
  clientdata->client_state->current_broadcast_map = NULL;  // Don't kill our map :)
  llmp_client_delete(clientdata->client_state);
  afl_shmem_deinit(clientdata->cur_client_map);

  DBG("Creating new client #phoenix");
  clientdata->client_state = llmp_client_new_unconnected();
  if (!clientdata->client_state) { PFATAL("Error allocating replacement client after crash"); }
  /* restore old client id */
  clientdata->client_state->id = client_id;
  /* link the new broker to the client at the position of the old client by connecting shmems. */
  /* TODO: Do this inside the forked thread instead? Right now, we're mapping it twice... */
  afl_shmem_t *broadcast_map = calloc(1, sizeof(afl_shmem_t));
  if (!broadcast_map) { PFATAL("Could not alloc mem for broadcast map"); }
  afl_shmem_by_str(broadcast_map, broker->broadcast_maps[0].shm_str, broker->broadcast_maps[0].map_size);
  clientdata->client_state->current_broadcast_map = broadcast_map;

  afl_shmem_by_str(clientdata->cur_client_map, clientdata->client_state->out_maps[0].shm_str,
                   clientdata->client_state->out_maps[0].map_size);

  /* restore the old virgin_bits for this fuzzer before reforking */
  afl_engine_t *engine = (afl_engine_t *)clientdata->data;
  size_t        i;
  for (i = 0; i < engine->feedbacks_count; i++) {

    if (engine->feedbacks[i]->tag == AFL_FEEDBACK_TAG_COV) {

      afl_feedback_cov_set_virgin_bits((afl_feedback_cov_t *)engine->feedbacks[i], state->payload, state->map_size);

    }

  }

  clientdata->last_msg_broker_read = NULL;
  /* Get ready for a new child. TODO: Collect old ones... */
  clientdata->pid = 0;

  /* Make sure the next fork won't start in the same rnd state as the last... */
  afl_rand_next(&engine->rand);

  /* fork off the new child */
  if (!llmp_broker_launch_client(broker, clientdata)) { FATAL("Error spawning new client after crash"); }

  return true;

}

/* A hook to keep stats in the broker thread */
bool broker_message_hook(llmp_broker_t *broker, llmp_broker_clientdata_t *clientdata, llmp_message_t *msg, void *data) {

  fuzzer_stats_t *       fuzzer_stats = ((fuzzer_stats_t *)data);
  broker_client_stats_t *client_stats = &fuzzer_stats->clients[clientdata->client_state->id - 1];
  client_stats->last_msg_time = afl_get_cur_time();

  DBG("Broker: msg hook called with msg tag %X", msg->tag);
  cur_state_t *state = NULL;

  (void)broker;
  switch (msg->tag) {

    case LLMP_TAG_NEW_QUEUE_ENTRY_V1:
      fuzzer_stats->queue_entry_count++;
      return true;  // Forward this to the clients
    case LLMP_TAG_EXEC_STATS_V1:
      client_stats->total_execs += *(LLMP_MSG_BUF_AS(msg, u64));
      return false;  // don't forward this to the clients
    case LLMP_TAG_TIMEOUT_V1:
      DBG("We found a timeout...");
      /* write timeout output */
      state = LLMP_MSG_BUF_AS(msg, cur_state_t);

      if (state->calibration_idx < calibration_idx) { calibration_idx = state->calibration_idx; }
      if (state->calibration_idx >= 0) {

        afl_entry_t *queue_entry =
            global_queue->base.funcs.get_queue_entry((afl_queue_t *)global_queue, state->calibration_idx);

        if (queue_entry && !queue_entry->info->skip_entry) {

          WARNF("Seed entry %ld timed out, disabling...", state->calibration_idx);
          queue_entry->info->skip_entry = 1;

        }

      }

      afl_input_t timeout_input = {0};
      AFL_TRY(afl_input_init(&timeout_input),
              { FATAL("Error initializing input for crash: %s", afl_ret_stringify(err)); });

      timeout_input.bytes = state->payload + state->map_size;
      timeout_input.len = state->current_input_len;

      if (timeout_input.len) {

        if (afl_input_dump_to_timeoutfile(&timeout_input, queue_dirpath) == AFL_RET_SUCCESS) fuzzer_stats->timeouts++;

      } else {

        WARNF("Crash input has zero length, this cannot happen.");

      }

      broker_handle_client_restart(broker, clientdata, state);

      client_stats->total_execs += state->new_execs;
      // Reset timeout
      client_stats->last_msg_time = 0;

      return false;  // Don't foward this msg to clients.

    case LLMP_TAG_CRASH_V1:

      DBG("We found a crash!");
      /* write crash output */
      state = LLMP_MSG_BUF_AS(msg, cur_state_t);

      if (state->calibration_idx < calibration_idx) calibration_idx = state->calibration_idx;
      if (state->calibration_idx >= 0) {

        afl_entry_t *queue_entry =
            global_queue->base.funcs.get_queue_entry((afl_queue_t *)global_queue, state->calibration_idx);

        if (queue_entry && !queue_entry->info->skip_entry) {

          WARNF("Seed entry %ld crashed, disabling...", state->calibration_idx);
          queue_entry->info->skip_entry = 1;

        }

      }

      afl_input_t crashing_input = {0};
      AFL_TRY(afl_input_init(&crashing_input),
              { FATAL("Error initializing input for crash: %s", afl_ret_stringify(err)); });

      crashing_input.bytes = state->payload + state->map_size;
      crashing_input.len = state->current_input_len;

      if (crashing_input.len) {

        if (afl_input_dump_to_crashfile(&crashing_input, queue_dirpath) == AFL_RET_SUCCESS) fuzzer_stats->crashes++;

      } else {

        WARNF("Crash input has zero length, this cannot happen.");

      }

      broker_handle_client_restart(broker, clientdata, state);

      client_stats->total_execs += state->new_execs;
      // Reset timeout
      client_stats->last_msg_time = 0;

      return false;  // no need to foward this to clients.
    default:
      /* We'll foward anything else we don't know. */
      DBG("Unknown message id: %X", msg->tag);
      return true;

  }

}

/*
 ****************
 ***** MAIN *****
 ****************
 */

int main(int argc, char **argv) {

  if (argc < 4) {

    SAYF("Usage: %s number_of_threads /path/to/input/dir /path/to/queue/dir", argv[0]);
    exit(0);

  }

  s32   i = 0;
  int   status = 0;
  int   pid = 0;
  int   thread_count = atoi(argv[1]);
  char *in_dir = argv[2];
  queue_dirpath = argv[3];

  if (getenv("DEBUG") || getenv("AFL_DEBUG")) debug = 1;

  if (debug) {

    SAYF("libaflfuzzer running as:");
    for (i = 0; i < argc; i++)
      SAYF(" %s", argv[i]);
    SAYF("\n");

  }

  OKF("Target coverage map size: %u", __afl_map_size);

  if (thread_count <= 0) {

    // we cannot use FATAL because some build scripts fail otherwise
    SAYF(bSTOP RESET_G1 CURSOR_SHOW cRST cLRD "\n[-] ERROR : " cRST
                                              "Number of threads should be greater than 0, exiting gracefully.");
    SAYF(cLRD "\n         Location : " cRST "%s(), %s:%u\n\n", __func__, __FILE__, __LINE__);
    exit(0);

  }

  int broker_port = 0xAF1;

  if (!afl_dir_exists(in_dir)) { FATAL("Oops, seed input directory %s does not seem to be valid.", in_dir); }

  afl_engine_t **engines = malloc(sizeof(afl_engine_t *) * thread_count);
  if (!engines) { PFATAL("Could not allocate engine buffer!"); }

  llmp_broker_t *llmp_broker = llmp_broker_new();
  if (!llmp_broker) { FATAL("Broker creation failed"); }

  /* This is not necessary but gives us the option to add additional processes to the fuzzer at runtime. */
  if (!llmp_broker_register_local_server(llmp_broker, broker_port)) { FATAL("Broker register failed"); }

  OKF("Created broker.");

  /* The message hook will intercept all messages from all clients - and listen for stats. */
  fuzzer_stats_t fuzzer_stats = {0};
  llmp_broker_add_message_hook(llmp_broker, broker_message_hook, &fuzzer_stats);
  fuzzer_stats.clients = malloc(thread_count * sizeof(broker_client_stats_t));
  if (!fuzzer_stats.clients) { PFATAL("Unable to alloc memory"); }

  for (i = 0; i < thread_count; i++) {

    afl_engine_t *engine = initialize_fuzzer(in_dir, queue_dirpath, argc, argv, thread_count);
    if (!engine) { FATAL("Error initializing fuzzing engine"); }
    engines[i] = engine;

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

  global_queue = afl_queue_global_new();
  OKF("%u client%s started running.", thread_count, thread_count == 1 ? "" : "s");
  sleep(1);

  while (1) {

    /* Chill a bit */
    usleep(175);

    /* Forward all messages that arrived in the meantime */
    llmp_broker_once(llmp_broker);

    /* Paint ui every second */
    if ((time_cur = afl_get_cur_time_s()) > time_prev) {

      u32 time_cur_ms = afl_get_cur_time();

      u64 time_elapsed = (time_cur - time_initial);
      time_prev = time_cur;
      u64 total_execs = 0;
      for (i = 0; i < thread_count; i++) {

        broker_client_stats_t *client_status = &fuzzer_stats.clients[i];

        total_execs += client_status->total_execs;

        if (client_status->last_msg_time && time_cur_ms - client_status->last_msg_time > KILL_IDLE_CLIENT_MS) {

          /* Note that the interesting client_ids start with 1 as 0 is the broker tcp server. */
          DBG("Detected timeout for client %d", i + 1);
          kill(llmp_broker->llmp_clients[i + 1].pid, SIGUSR2);

        }

      }

      SAYF("paths=%llu crashes=%llu timeouts=%llu elapsed=%llu execs=%llu exec/s=%llu\r",
           fuzzer_stats.queue_entry_count, fuzzer_stats.crashes, fuzzer_stats.timeouts, time_elapsed, total_execs,
           total_execs / time_elapsed);

      fflush(stdout);

      if ((pid = waitpid(-1, &status, WNOHANG)) > 0) {

        // this pid is gone
        // TODO: Check if we missed a crash via llmp?
        DBG("Child with pid %d is gone.", pid);

      }

    }

  }

  return 0;

}

