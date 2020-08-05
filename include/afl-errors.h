#ifndef AFL_ERRORS_H
#define AFL_ERRORS_H

typedef enum afl_ret {

  AFL_RET_SUCCESS,
  AFL_RET_ALLOC,
  AFL_RET_FILE_OPEN,
  AFL_RET_FILE_SIZE,
  AFL_RET_SHORT_READ,
  AFL_RET_ARRAY_END,

} afl_ret_t;

#endif

