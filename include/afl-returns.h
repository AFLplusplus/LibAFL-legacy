/* This file includes return codes for libafl. */

#ifndef AFL_RETURNS_H
#define AFL_RETURNS_H

#include <errno.h>
#include <string.h>

#include "debug.h"

/* Shorthand to check for RET_SUCCESS */
#define AFL_OK(expr) ((expr) == AFL_RET_SUCCESS)

/* If expr != AFL_RET_SUCCESS, run block, error is in err. Return from here will return the parent func */
#define AFL_TRY(expr, block)                                      \
  do {                                                            \
                                                                  \
    afl_ret_t err = (expr);                                       \
    if (err != AFL_RET_SUCCESS) {                                 \
                                                                  \
      DBG("AFL_TRY returning error: %s", afl_ret_stringify(err)); \
      block                                                       \
                                                                  \
    }                                                             \
                                                                  \
  } while (0);

/* Shorthand to check for RET_SUCCESS and assign to ret */
#define AFL_OK_RET(expr, ret) ((ret = (expr)) == AFL_RET_SUCCESS)

typedef enum afl_ret {

  AFL_RET_SUCCESS = 0,
  AFL_RET_UNKNOWN_ERROR,
  AFL_RET_ALLOC,
  AFL_RET_FILE_OPEN_ERROR,
  AFL_RET_FILE_SIZE,
  AFL_RET_SHORT_READ,
  AFL_RET_SHORT_WRITE,
  AFL_RET_ARRAY_END,
  AFL_RET_EXEC_ERROR,
  AFL_RET_BROKEN_TARGET,
  AFL_RET_NULL_PTR,
  AFL_RET_ERRNO,
  AFL_RET_NULL_QUEUE_ENTRY,
  AFL_RET_WRITE_TO_CRASH,
  AFL_RET_QUEUE_ENDS,
  AFL_RET_ERROR_INITIALIZE,
  AFL_RET_NO_FUZZ_WORKERS,
  AFL_RET_TRIM_FAIL,
  AFL_RET_ERROR_INPUT_COPY,
  AFL_RET_EMPTY,

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
    case AFL_RET_ERROR_INPUT_COPY:
      return "Error creating input copy";
    case AFL_RET_EMPTY:
      return "Empty data";
    case AFL_RET_ALLOC:
      if (!errno) { return "Allocation failed"; }
      /* fall-through */
    case AFL_RET_FILE_OPEN_ERROR:
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

