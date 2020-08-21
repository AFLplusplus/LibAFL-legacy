#include "aflpp.h"

/* Function ptr for the harness */
typedef exit_type_t (*harness_function_type)(u8* data, size_t size);

typedef struct in_memeory_executor {
    
    executor_t base;
    harness_function_type harness;

}   in_memeory_executor_t;

static u8 in_mem_executor_place_input (executor_t * executor, raw_input_t * input) {

    executor->current_input = input;
    return 0;

}

exit_type_t in_memory_run_target(executor_t * executor) {

    in_memeory_executor_t * in_memeory_executor = (in_memeory_executor_t *)executor;

    raw_input_t * input = in_memeory_executor->base.current_input;

    u8 * data = (input->funcs.serialize) ? (input->funcs.serialize(input)) : input->bytes;

    exit_type_t run_result = in_memeory_executor->harness(data, input->len);

    return run_result;

}

static in_memeory_executor_t * in_memory_exeutor_init(in_memeory_executor_t * in_memeory_executor, harness_function_type harness) {
    
    afl_executor_init(&in_memeory_executor->base);
    in_memeory_executor->harness = harness;
    in_memeory_executor->base.funcs.run_target_cb = in_memory_run_target;
    in_memeory_executor->base.funcs.place_input_cb = in_mem_executor_place_input;
    return in_memeory_executor;
    
}

