#ifndef AFL_RETURNS_H
#define AFL_RETURNS_H

#include <errno.h>
#include <string.h>

typedef enum afl_ret {

  AFL_RET_SUCCESS,
  AFL_RET_ALLOC,
  AFL_RET_FILE_OPEN,
  AFL_RET_FILE_SIZE,
  AFL_RET_SHORT_READ,
  AFL_RET_ARRAY_END,
  AFL_RET_EXEC_ERROR,
  AFL_RET_BROKEN_TARGET,
  AFL_RET_NULL_PTR,
  AFL_RET_ERRNO,
  AFL_RET_NULL_QUEUE_ENTRY,
  AFL_RET_WRITE_TO_CRASH,

} afl_ret_t;

/* Returns a string representation of afl_ret_t or of the errno if applicable */
static inline char *afl_ret_stringify(afl_ret_t afl_ret) {

  switch (afl_ret) {

    case AFL_RET_SUCCESS:
      return "Success";
    case AFL_RET_ARRAY_END:
      return "No more elements in array";
    case AFL_RET_EXEC_ERROR:
      return "Could not execute target";
    case AFL_RET_BROKEN_TARGET:
      return "Target did not behave as expected";
    case AFL_RET_ALLOC:
      if (!errno) { return "Allocation failed"; }
      /* fall-through */
    case AFL_RET_FILE_OPEN:
      if (!errno) { return "Error opening file"; }
      /* fall-through */
    case AFL_RET_SHORT_READ:
      if (!errno) { return "Got less bytes than expected"; }
      /* fall-through */
    case AFL_RET_ERRNO:
      return strerror(errno);
    default:
      return "Unknown error. Please report this bug!";

  }

}

#endif

