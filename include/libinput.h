#include "lib-common.h"

#define DEFAULT_INPUT_LEN 100

typedef struct raw_input {

  u8 *   bytes;  // Raw input bytes
  size_t len;  // Length of the input field. C++ had strings, we have to make do
               // with storing the lengths :/

  struct raw_input_operations *operations;

} raw_input_t;

typedef struct raw_input_operations {

  void (*deserialize)(raw_input_t *, u8 *, size_t);
  u8 *(*serialize)(raw_input_t *);
  raw_input_t *(*copy)(raw_input_t *);
  raw_input_t *(*empty)(raw_input_t *);
  void (*restore)(raw_input_t *, raw_input_t *);
  u8 (*load_from_file)(raw_input_t *, u8 *);
  u8 (*save_to_file)(raw_input_t *, u8 *);
  void (*clear)(raw_input_t *);
  u8 *(*get_bytes)(raw_input_t *);

} raw_input_operations_t;

raw_input_t *afl_input_init();
void         afl_input_deinit(raw_input_t *);

// Default implementations of the functions for raw input vtable
void         afl_inp_deserialize(raw_input_t *, u8 *, size_t);
u8 *         afl_inp_serialize(raw_input_t *);
raw_input_t *afl_inp_copy(raw_input_t *);
raw_input_t *afl_inp_empty(raw_input_t *);
void         afl_inp_restore(raw_input_t *, raw_input_t *);
u8           afl_inp_load_from_file(raw_input_t *, u8 *);
u8           afl_inp_save_to_file(raw_input_t *, u8 *);
void         afl_inp_clear(raw_input_t *);
u8 *         afl_inp_get_bytes(raw_input_t *);

// input_clear and empty functions... difference??
// serializing and deserializing would be done on the basis of some structure
// right??

