/* An in mmeory fuzzing example. Fuzzer for libpng library */

#include <stdio.h>
#include "inmemory-executor.h"
#include "map-coverage-feedback.h"
#include <png.h>

typedef struct thread_instance_args {

  engine_t *engine;
  char *    in_dir;

} thread_instance_args_t;

extern u8 * __afl_area_ptr;

exit_type_t harness_func(u8 * input, size_t len) {

    /* Setting up trace bits to zero before running the target */
    memset(__afl_area_ptr, 0, MAP_SIZE);

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

    png_set_user_limits(png_ptr, 65535, 65535);
    png_infop info_ptr = png_create_info_struct(png_ptr);
    png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
    
    if (setjmp(png_jmpbuf(png_ptr))) {
        return NORMAL;
    }

    png_set_progressive_read_fn(png_ptr, NULL, NULL, NULL, NULL);
    png_process_data(png_ptr, info_ptr, input, len);

    return NORMAL;

}

engine_t * initialize_fuzz_instance() {
        /* Let's create an in-memory executor */
    in_memeory_executor_t * in_memory_executor = calloc(1, sizeof(in_memeory_executor_t));
    if (!in_memory_executor)    { FATAL("%s", afl_ret_stringify(AFL_RET_ALLOC)); }
    in_memory_exeutor_init(in_memory_executor, harness_func);


    /* Observation channel, map based, we initialize this ourselves since we don't actually create a shared map */
    map_based_channel_t *trace_bits_channel = calloc(1, sizeof(map_based_channel_t));
    if (!trace_bits_channel) { FATAL("Trace bits channel error %s", afl_ret_stringify(AFL_RET_ALLOC)); }
    trace_bits_channel->shared_map.map = __afl_area_ptr;    // Coverage "Map" we have
    trace_bits_channel->shared_map.map_size = MAP_SIZE;
    trace_bits_channel->shared_map.shm_id = -1; // Just a simple erronous value :)
    in_memory_executor->base.funcs.add_observation_channel(&in_memory_executor->base, &trace_bits_channel->base);

    /* We create a simple feedback queue for coverage here*/
    feedback_queue_t *coverage_feedback_queue =
        afl_feedback_queue_create(NULL, (char *)"Coverage feedback queue");
    if (!coverage_feedback_queue) { FATAL("Error initializing feedback queue"); }

      /* Global queue creation */
    global_queue_t *global_queue = afl_global_queue_create();
    if (!global_queue) { FATAL("Error initializing global queue"); }
    global_queue->extra_funcs.add_feedback_queue(global_queue,
                                                coverage_feedback_queue);

    /* Coverage Feedback initialization */
    maximize_map_feedback_t *coverage_feedback = map_feedback_init(
        coverage_feedback_queue, trace_bits_channel->shared_map.map_size);
    if (!coverage_feedback) { FATAL("Error initializing feedback"); }

    /* Let's build an engine now */
    engine_t *engine = afl_engine_create(&in_memory_executor->base, NULL, global_queue);
    if (!engine) { FATAL("Error initializing Engine"); }
    engine->funcs.add_feedback(engine, (feedback_t *)coverage_feedback);
    engine->funcs.set_global_queue(engine, global_queue);

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

void *thread_run_instance(void *thread_args) {

  thread_instance_args_t *thread_instance_args =
      (thread_instance_args_t *)thread_args;

  engine_t *engine = (engine_t *)thread_instance_args->engine;

  map_based_channel_t *trace_bits_channel =
      (map_based_channel_t *)engine->executor->observors[0];

  fuzzing_stage_t *    stage = (fuzzing_stage_t *)engine->fuzz_one->stages[0];
  scheduled_mutator_t *mutators_havoc =
      (scheduled_mutator_t *)stage->mutators[0];

  maximize_map_feedback_t *coverage_feedback =
      (maximize_map_feedback_t *)(engine->feedbacks[0]);


  /* Now we can simply load the testcases from the directory given */
  afl_ret_t ret = engine->funcs.load_testcases_from_dir(
      engine, thread_instance_args->in_dir, NULL);
  if (ret != AFL_RET_SUCCESS) {

    PFATAL("Error loading testcase dir: %s", afl_ret_stringify(ret));

  }

  OKF("Processed %llu input files.", engine->executions);

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
  return 0;

}

int main(int argc, char ** argv) {
    
    (void)  argc;
    (void)  argv;

    engine_t * engine = initialize_fuzz_instance();

    raw_input_t * input = afl_input_create();

    input->bytes = (u8*) "\x89PNG\r\n\x1a\nBBBBBBBBBBBBBBBBBBBBB";
    input->len = 29;
    engine->executor->funcs.place_input_cb(engine->executor, input);
    engine->executor->funcs.run_target_cb(engine->executor);

    return 0;

}

