#include <fcntl.h>

#include "libinput.h"

raw_input_t *afl_input_init() {

  raw_input_t *input = ck_alloc(sizeof(raw_input_t));

  input->operations = ck_alloc(sizeof(raw_input_operations_t));

  input->operations->clear = afl_inp_clear;
  input->operations->copy = afl_inp_copy;
  input->operations->deserialize = afl_inp_deserialize;
  input->operations->empty = afl_inp_empty;
  input->operations->get_bytes = afl_inp_get_bytes;
  input->operations->load_from_file = afl_inp_load_from_file;
  input->operations->restore = afl_inp_restore;
  input->operations->save_to_file = afl_inp_save_to_file;
  input->operations->serialize = afl_inp_serialize;

}

// default implemenatations for the vtable functions for the raw_input type

void afl_inp_clear(raw_input_t *input) {

  memset(input->bytes, 0x0, input->len);

}

raw_input_t *afl_inp_copy(raw_input_t *orig_inp) {

  raw_input_t *copy_inp = afl_input_init();
  copy_inp->bytes = ck_alloc(orig_inp->len);
  memcpy(copy_inp->bytes, orig_inp->bytes, orig_inp->len);

}

void afl_inp_deserialize(raw_input_t *input, u8 *bytes, size_t len) {

  ck_free(input->bytes);
  input->bytes = bytes;
  input->len = len;

}

u8 *afl_inp_get_bytes(raw_input_t *input) {

  return input->bytes;

}

u8 afl_inp_load_from_file(raw_input_t *input, u8 *fname) {

  if (!input->len) input->len = DEFAULT_INPUT_LEN;

  FILE *f = fopen(fname, "r");
  input->bytes = ck_alloc(sizeof(input->len));

  if (!f) return 1;

  int  i = 0;
  char c = NULL;

  while (c != EOF) {

    c = fgetc(f);
    input->bytes[i] = c;

    i++;

    if (i >= input->len) {

      input->bytes = ck_realloc(input->bytes, 2 * input->len);
      input->len = input->len * 2;

    }

  }

  fclose(f);

  return 0;

}

u8 afl_inp_save_to_file(raw_input_t *input, u8 *fname) {

  FILE *f = fopen(fname, "w+");

  if (!f) return 1;

  fwrite(input->bytes, 1, input->len, f);

  fclose(f);
  return 0;

}

void afl_inp_restore(raw_input_t *input, raw_input_t *new_inp) {

  ck_free(input->bytes);
  input->bytes = new_inp->bytes;

}

