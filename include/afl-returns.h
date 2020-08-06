#ifndef AFL_RETURNS_H
#define AFL_RETURNS_H

typedef enum afl_ret {

  AFL_RET_SUCCESS,
  AFL_RET_ALLOC,
  AFL_RET_FILE_OPEN,
  AFL_RET_FILE_SIZE,
  AFL_RET_SHORT_READ,
  AFL_RET_ARRAY_END,

} afl_ret_t;

static inline char *afl_ret_stringify(afl_ret_t afl_ret) {
  
  switch(afl_ret) {
    case AFL_RET_SUCCESS:
      return "Success";
    case AFL_RET_ALLOC:
      return "Allocation failed";
    case AFL_RET_FILE_OPEN:
      return "Error opening file";
    case AFL_RET_SHORT_READ:
      return "Got less bytes than expected";
    case AFL_RET_ARRAY_END:
      return "No more elements in array";
    default:
      return "Unknown error. Please report this bug.";
  }

}

#endif
