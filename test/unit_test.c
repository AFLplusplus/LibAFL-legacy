#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <assert.h>
#include <cmocka.h>
#include <unistd.h>
#include <fcntl.h>
/* cmocka < 1.0 didn't support these features we need */
#ifndef assert_ptr_equal
  #define assert_ptr_equal(a, b)                                      \
    _assert_int_equal(cast_ptr_to_largest_integral_type(a),           \
                      cast_ptr_to_largest_integral_type(b), __FILE__, \
                      __LINE__)
  #define CMUnitTest UnitTest
  #define cmocka_unit_test unit_test
  #define cmocka_run_group_tests(t, setup, teardown) run_tests(t)
#endif

extern void mock_assert(const int result, const char *const expression,
                        const char *const file, const int line);
#undef assert
#define assert(expression) \
  mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#include "libcommon.h"

/* remap exit -> assert, then use cmocka's mock_assert
    (compile with `--wrap=exit`) */
extern void exit(int status);
extern void __real_exit(int status);
void        __wrap_exit(int status);
void        __wrap_exit(int status) {

  assert(0);

}

/* ignore all printfs */
#undef printf
extern int printf(const char *format, ...);
extern int __real_printf(const char *format, ...);
int        __wrap_printf(const char *format, ...);
int        __wrap_printf(const char *format, ...) {

  return 1;

}

/* Testing libcommon string based functions */

static void test_insert_substring(void **state) {

  (void)state;

  char *      test_token = "test_token ";
  const char *test_string = "This is a test_token string";

  u8 s[100];
  strcpy((char *)s, "This is a string");

  u8 *new_string = insert_substring(s, strlen((char *)s), test_token,
                                    strlen(test_token), 10);

  assert_string_equal(new_string, test_string);
  free(new_string);

}

static void test_insert_bytes(void **state) {

  (void)state;

  u8 s[100];
  strcpy((char *)s, "This is a string");

  u8          test_byte = 0x41;
  const char *test_string = "This is a AAAAAAAstring";

  u8 *new_string = insert_bytes(s, strlen((char *)s), test_byte, 7, 10);

  assert_string_equal(new_string, test_string);
  free(new_string);

}

static void test_erase_bytes(void **state) {

  (void)state;
  u8 s[100];
  strcpy((char *)s, "This is a string");

  const char *test_string = "This string";

  erase_bytes(s, strlen((char *)s), 5, 5);

  assert_string_equal(s, test_string);

}

/* Unittests for libinput based default functions */

#include "libinput.h"

void test_input_copy(void ** state) {

  raw_input_t input;
  afl_input_init(&input);

  u8 s[100] = {0};
  memcpy(s, "AAAAAAAAAAAAA", 13);

  input.bytes = s;
  input.len = 14;

  raw_input_t * copy = input.funcs.copy(&input);

  assert_string_equal(copy->bytes, input.bytes);
  assert_int_equal(input.len, copy->len);

  afl_input_delete(copy);

}

void test_input_load_from_file(void **state) {

  (void)state;
  /* We first write some string to a file */
  char *fname = "./test_input_file";
  char *test_string = "This is a test string";
  int   fd = open(fname, O_RDWR | O_CREAT, 0600);

  int write_len = write(fd, test_string, 22);

  /* Create an input now and test it */
  raw_input_t input;
  afl_input_init(&input);

  /* We just have to test the default func, we don't use the vtable here */
  raw_inp_load_from_file_default(&input, fname);

  assert_string_equal(input.bytes, test_string);
  assert_int_equal(input.len, write_len);

  free(input.bytes);
  unlink(fname);

}

void test_input_save_to_file(void **state) {

  (void)state;
  /* We first write some string to a file */
  char *fname = "test_output_file";
  char *test_string = "This is a test string";

  u8 read_string[100];

  /* Create an input now and test it */
  raw_input_t input;
  afl_input_init(&input);

  input.bytes = (u8 *)test_string;
  input.len = strlen(test_string);

  /* We just have to test the default func, we don't use the vtable here */
  raw_inp_save_to_file_default(&input, fname);

  int fd = open(fname, O_RDONLY);

  int read_len = read(fd, read_string, 22);

  assert_string_equal(input.bytes, read_string);
  assert_int_equal(input.len, read_len);

  close(fd);
  unlink(fname);

}

/* Unittest for default engine functions */

#include "libengine.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

raw_input_t *input[2];  // We'll need a global input being filled everytime to
                        // work with this
int counter = 0;

u8 engine_mock_execute(engine_t *engine, raw_input_t *input) {

  return AFL_RET_SUCCESS;

}

static raw_input_t *custom_input_create() {

  input[counter] = afl_input_create();

  input[counter]->funcs.clear(input[counter]);

  raw_input_t *current_input = input[counter];
  counter++;

  return current_input;

}

void test_engine_load_testcase_from_dir_default(void **state) {

  (void)state;

  char *corpus_one = "This is a test corpus";
  char *corpus_two = "This is the second test corpus";

  executor_t executor;
  afl_executor_init(&executor);

  engine_t engine;
  afl_engine_init(&engine, &executor, NULL, NULL);
  engine.funcs.execute = engine_mock_execute;

  // Let's create a test directory now.
  struct stat st = {0};

  if (stat("testcases", &st) != -1) { rmdir("testcases"); }

  if (mkdir("testcases", 0700) != 0) {

    WARNF("Error creating directory");
    assert_true(0);  // The test failed

  }

  // Let's first test for empty directory
  engine.funcs.load_testcases_from_dir(&engine, "testcases",
                                       custom_input_create);

  assert_null(input[0]);

  // Let's test it with a few files in the directory
  int fd = open("testcases/test1", O_RDWR | O_CREAT, 0600);
  int write_len = write(fd, corpus_one, 21);

  if (write_len != 21) {

    WARNF("Short write");
    assert_true(0);

  }

  close(fd);
  fd = open("testcases/test2", O_RDWR | O_CREAT, 0600);
  write_len = write(fd, corpus_two, 30);

  if (write_len != 30) {

    WARNF("Short write");
    assert_true(0);

  }

  close(fd);
  engine.funcs.load_testcases_from_dir(&engine, "testcases",
                                       custom_input_create);

  /* Let's test the inputs now */
  assert_non_null(input[0]->bytes);
  assert_non_null(input[1]->bytes);
  assert_string_equal(input[1]->bytes, corpus_one);
  assert_string_equal(input[0]->bytes, corpus_two);

  /* Freeing up resources now */
  afl_input_delete(input[0]);
  afl_input_delete(input[1]);

  /* Let's now remove the directory */
  if (unlink("testcases/test1") || unlink("testcases/test2")) {

    FATAL("Error removing corpus files");

  }

  if (rmdir("testcases")) { FATAL("Error removing directory"); }

}

/* Unittests for the basic mutators and mutator functions we added */

#include "libmutator.h"
#include <time.h>

void test_basic_mutator_functions(void ** state){

  (void)  state;

  /* First let's create a basic inputs */
  raw_input_t input;
  raw_input_t * copy = NULL;
  afl_input_init(&input);

  char * test_string = "AAAAAAAAAAAAA";
  input.bytes = calloc(strlen(test_string), 1);
  memcpy(input.bytes, test_string, strlen(test_string));
  input.len = 13;

  srand(time(NULL));

  /* We test the different mutation functions now */
  flip_bit_mutation(&input);
  assert_string_not_equal(input.bytes, test_string );

  copy = input.funcs.copy(&input);

  flip_2_bits_mutation(&input);
  assert_string_not_equal(input.bytes, copy->bytes);
  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  flip_4_bits_mutation(&input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);

  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  flip_byte_mutation(&input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);

  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  flip_2_bytes_mutation(&input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);

  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  flip_4_bytes_mutation(&input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);

  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  random_byte_add_sub_mutation(&input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);

  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  random_byte_mutation(&input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);

  afl_input_delete(copy);
  
  copy = input.funcs.copy(&input);
  delete_bytes_mutation(&input);
  assert_string_not_equal(input.bytes, copy->bytes);

  afl_input_delete(copy);
  
  copy = input.funcs.copy(&input);
  clone_bytes_mutation(&input);
  assert_string_not_equal(input.bytes, copy->bytes);

  afl_input_delete(copy);
  afl_input_deinit(&input);
}

/* Unittests for queue and queue entry based stuff */

#include "libqueue.h"

void test_queue_set_directory(void ** state) {

  base_queue_t queue;
  afl_base_queue_init(&queue);

  /* Testing for an empty dirpath */
  queue.funcs.set_directory(&queue, NULL);
  
  assert_string_equal(queue.dirpath, "");

  /* Testing for normal directory */
  char  * new_dirpath = "/some/dir";
  queue.funcs.set_directory(&queue, new_dirpath);

  assert_string_equal(queue.dirpath, new_dirpath);

}

void test_base_queue_get_next(void ** state) {

  (void)  state;

  base_queue_t queue;
  afl_base_queue_init(&queue);

  /* When queue is empty we should get NULL */
  assert_null(queue.funcs.get_next_in_queue(&queue));

  queue_entry_t first_entry;
  afl_queue_entry_init(&first_entry, NULL);

  queue.funcs.add_to_queue(&queue, &first_entry);

  queue_entry_t second_entry;
  afl_queue_entry_init(&second_entry, NULL);

  queue.funcs.add_to_queue(&queue, &second_entry);

  /* Let's tell the queue with two entries now */
  assert_ptr_equal(queue.funcs.get_next_in_queue(&queue), &second_entry);

  assert_ptr_equal(queue.funcs.get_next_in_queue(&queue), &first_entry);

  assert_int_equal(queue.size, 2);

}

void test_global_queue_get_next(void ** state) {

  (void)  state;

  global_queue_t global_queue;
  afl_global_queue_init(&global_queue);

  queue_entry_t first_entry;
  afl_queue_entry_init(&first_entry, NULL);

  global_queue.base.funcs.add_to_queue(&global_queue.base, &first_entry);

  /* Since this global queue doesn't have any feedback queue, we should get the queue entry we just added*/

  assert_ptr_equal(global_queue.base.funcs.get_next_in_queue(&global_queue.base), &first_entry);

  /* We add a feedback queue with an entry and check if the queue returns that */

  feedback_queue_t feedback_queue;
  afl_feedback_queue_init(&feedback_queue, NULL, NULL);

  queue_entry_t second_entry;
  afl_queue_entry_init(&second_entry, NULL);

  feedback_queue.base.funcs.add_to_queue(&feedback_queue.base, &second_entry);

  global_queue.extra_funcs.add_feedback_queue(&global_queue, &feedback_queue);

  assert_ptr_equal(global_queue.base.funcs.get_next_in_queue(&global_queue.base), &second_entry);

}

int main(int argc, char **argv) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_insert_substring),
      cmocka_unit_test(test_insert_bytes),
      cmocka_unit_test(test_erase_bytes),

      cmocka_unit_test(test_input_load_from_file),
      cmocka_unit_test(test_input_save_to_file),
      cmocka_unit_test(test_input_copy),
      
      cmocka_unit_test(test_engine_load_testcase_from_dir_default),
      
      cmocka_unit_test(test_basic_mutator_functions),

      cmocka_unit_test(test_queue_set_directory),
      cmocka_unit_test(test_base_queue_get_next),
      cmocka_unit_test(test_global_queue_get_next),
  };

  // return cmocka_run_group_tests (tests, setup, teardown);
  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));

  // fake return for dumb compilers
  return 0;

}

