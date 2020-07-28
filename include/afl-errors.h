#ifndef AFL_ERRORS_H
#define AFL_ERRORS_H

typedef enum afl_error { 
    AFL_ALL_OK,
    AFL_ERROR_ALLOC, 
    AFL_ERROR_FILE_OPEN, 
    AFL_ERROR_FILE_SIZE,
    AFL_ERROR_SHORT_READ,
} afl_error_t;

#endif

