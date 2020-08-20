/* An in mmeory fuzzing example */

#include "inmemory-executor.h"
#include <png.h>

extern uint8_t * __lafl_map;

exit_type_t harness_func(u8 * input, size_t len) {

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

int main(int argc, char ** argv) {

    afl_sharedmem_t afl_sharedmem;
    u8 * __afl_area_ptr = afl_sharedmem_init(&afl_sharedmem, MAP_SIZE);

    /* Let's create an in-memory executor */

    in_memeory_executor_t * in_memory_executor = calloc(1, sizeof(in_memeory_executor_t));

    if (!in_memory_executor)    { FATAL("%s", afl_ret_stringify(AFL_RET_ALLOC)); }

    in_memory_exeutor_init(in_memory_executor, harness_func);

    raw_input_t * input = afl_input_create();

    input->bytes = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    input->len = 37;
    
    harness_func(input->bytes, input->len);

    input->bytes = "\x89PNG\r\n\x1a\nBBBBBBBBBBBBBBBBBBBBB";
    input->len = 29;

    harness_func(input->bytes, input->len);

    return 0;

}

