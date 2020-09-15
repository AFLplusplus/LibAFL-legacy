#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <assert.h>
#include <cmocka.h>
#include <unistd.h>
#include <fcntl.h>
/* cmocka < 1.0 didn't support these features we need */
#ifndef assert_ptr_equal
  #define assert_ptr_equal(a, b) \
    _assert_int_equal(cast_ptr_to_largest_integral_type(a), cast_ptr_to_largest_integral_type(b), __FILE__, __LINE__)
  #define CMUnitTest UnitTest
  #define cmocka_unit_test unit_test
  #define cmocka_run_group_tests(t, setup, teardown) run_tests(t)
#endif

extern void mock_assert(const int result, const char *const expression, const char *const file, const int line);
#undef assert
#define assert(expression) mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#include "common.h"
#include "shmem.h"
#include "aflpp.h"
#include "afl-returns.h"

/* remap exit -> assert, then use cmocka's mock_assert
    (compile with `--wrap=exit`) */
extern void exit(int status);
extern void __real_exit(int status);
void        __wrap_exit(int status);
void        __wrap_exit(int status) {

  (void)status;
  assert(0);

}

/* ignore all printfs */
#undef printf
extern int printf(const char *format, ...);
extern int __real_printf(const char *format, ...);
int        __wrap_printf(const char *format, ...);
int        __wrap_printf(const char *format, ...) {

  (void)format;
  return 1;

}

/* Testing libcommon string based functions */

static void test_insert_substring(void **state) {

  (void)state;

  char *      test_token = "test_token ";
  const char *test_string = "This is a test_token string";

  u8 s[100];
  strcpy((char *)s, "This is a string");

  u8 *new_string = afl_insert_substring(s, strlen((char *)s), test_token, strlen(test_token), 10);

  assert_string_equal(new_string, test_string);
  free(new_string);

}

static void test_insert_bytes(void **state) {

  (void)state;

  u8 s[100];
  strcpy((char *)s, "This is a string");

  u8          test_byte = 0x41;
  const char *test_string = "This is a AAAAAAAstring";

  u8 *new_string = afl_insert_bytes(s, strlen((char *)s), test_byte, 7, 10);

  assert_string_equal(new_string, test_string);
  free(new_string);

}

static void test_erase_bytes(void **state) {

  (void)state;
  u8 s[100];
  strcpy((char *)s, "This is a string");

  const char *test_string = "This string";

  afl_erase_bytes(s, strlen((char *)s), 5, 5);

  assert_string_equal(s, test_string);

}

/* Unittests for libinput based default functions */

#include "input.h"

void test_input_copy(void **state) {

  (void)state;

  afl_input_t input;
  afl_input_init(&input);

  u8 s[100] = {0};
  memcpy(s, "AAAAAAAAAAAAA", 13);

  input.bytes = s;
  input.len = 14;

  afl_input_t *copy = input.funcs.copy(&input);

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
  afl_input_t input;
  afl_input_init(&input);

  /* We just have to test the default func, we don't use the vtable here */
  afl_input_load_from_file(&input, fname);

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
  afl_input_t input;
  afl_input_init(&input);

  input.bytes = (u8 *)test_string;
  input.len = strlen(test_string);

  /* We just have to test the default func, we don't use the vtable here */
  afl_input_save_to_file(&input, fname);

  int fd = open(fname, O_RDONLY);

  int read_len = read(fd, &read_string, strlen(test_string));
  assert_int_equal(read_len, strlen(test_string));
  read_string[strlen(test_string)] = '\0';

  assert_string_equal(input.bytes, &read_string);
  assert_int_equal(input.len, read_len);

  close(fd);
  unlink(fname);

}

/* Unittest for default engine functions */

#include "engine.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

u8 engine_mock_execute(afl_engine_t *engine, afl_input_t *input) {

  (void)engine;
  (void)input;

  return AFL_RET_SUCCESS;

}

typedef struct my_input_custom {

  afl_input_t base;
  int         customness;

} my_input_custom_t;

/* forwad decl for autogenerated delete by AFL_NEW_AND_DELETE_FOR */
static void my_input_custom_delete(my_input_custom_t *myinput);
/* wrapper to cast the base class to our input func */
static void my_input_custom_delete_base(afl_input_t *input) {

  my_input_custom_delete((my_input_custom_t *)input);

}

afl_ret_t my_input_custom_init(my_input_custom_t *myinput) {

  AFL_TRY(afl_input_init(&myinput->base), {

    DBG("Error creating custom input");
    return err;

  });

  myinput->customness = 9001;  // over 9k
  myinput->base.funcs.delete = my_input_custom_delete_base;

  return AFL_RET_SUCCESS;

}

void my_input_custom_deinit(my_input_custom_t *myinput) {

  afl_input_deinit(&myinput->base);

}

AFL_NEW_AND_DELETE_FOR(my_input_custom)

afl_input_t *my_input_custom_new_as_base(void) {

  my_input_custom_t *ret = my_input_custom_new();
  return ret ? &ret->base : NULL;

}

void test_engine_load_testcase_from_dir(void **state) {

  (void)state;

  char *corpus_one = "This is a test corpus";
  char *corpus_two = "This is the second test corpus";

  afl_executor_t executor;
  afl_executor_init(&executor);

  afl_queue_global_t queue;
  afl_queue_global_init(&queue);

  afl_engine_t engine;
  afl_engine_init(&engine, &executor, NULL, &queue);  // no need for a fuzz_one in our test-case

  engine.funcs.execute = engine_mock_execute;

  // Let's create a test directory now.
  struct stat st = {0};

  if (stat("testcases", &st) != -1) { rmdir("testcases"); }

  if (mkdir("testcases", 0700) != 0) {

    WARNF("Error creating directory");
    assert_true(0);  // The test failed

  }

  // Let's first test for empty directory
  AFL_TRY(engine.funcs.load_testcases_from_dir(&engine, "testcases", my_input_custom_new_as_base),
          { assert_true(0 && "Could not load testcase"); });

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
  afl_ret_t result = engine.funcs.load_testcases_from_dir(&engine, "testcases", NULL);

  assert_int_equal(result, AFL_RET_SUCCESS);

  /* Let's now remove the directory */
  if (unlink("testcases/test1") || unlink("testcases/test2")) { FATAL("Error removing corpus files"); }

  if (rmdir("testcases")) { FATAL("Error removing directory"); }

  afl_engine_deinit(&engine);

  /* this also implicitly frees the inputs atm. TODO: Explicit free? */
  afl_queue_global_deinit(&queue);
  afl_executor_deinit(&executor);

}

/* Unittests for the basic mutators and mutator functions we added */

#include <time.h>
#include "mutator.h"
#include "stage.h"
#include "fuzzone.h"

// We will need a global engine to work with this

void test_basic_mutator_functions(void **state) {

  (void)state;

  afl_engine_t   engine = {0};
  afl_stage_t    stage = {0};
  afl_fuzz_one_t fuzz_one = {0};
  afl_engine_init(&engine, NULL, NULL, NULL);
  afl_fuzz_one_init(&fuzz_one, &engine);
  afl_stage_init(&stage, &engine);

  afl_mutator_t mutator = {0};
  afl_mutator_init(&mutator, &engine);

  /* First let's create a basic inputs */
  afl_input_t  input = {0};
  afl_input_t *copy = NULL;
  afl_input_init(&input);

  char *test_string = "AAAAAAAAAAAAA";
  input.bytes = calloc(strlen(test_string), 1);
  memcpy(input.bytes, test_string, strlen(test_string));
  input.len = 13;

  /* We test the different mutation functions now */
  afl_mutfunc_flip_bit(&mutator, &input);
  assert_string_not_equal(input.bytes, test_string);

  copy = input.funcs.copy(&input);
  afl_mutfunc_flip_2_bits(&mutator, &input);
  assert_string_not_equal(input.bytes, copy->bytes);
  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  afl_mutfunc_flip_4_bits(&mutator, &input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);
  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  afl_mutfunc_flip_byte(&mutator, &input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);
  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  afl_mutfunc_flip_2_bytes(&mutator, &input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);
  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  afl_mutfunc_flip_4_bytes(&mutator, &input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);
  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  afl_mutfunc_random_byte_add_sub(&mutator, &input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);
  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  afl_mutfunc_random_byte(&mutator, &input);
  assert_memory_not_equal(input.bytes, copy->bytes, input.len);
  afl_input_delete(copy);

  /* Make sure this is an actual string */
  input.bytes[input.len - 1] = '\0';
  copy = input.funcs.copy(&input);
  afl_mutfunc_delete_bytes(&mutator, &input);
  assert_string_not_equal(input.bytes, copy->bytes);
  afl_input_delete(copy);

  copy = input.funcs.copy(&input);
  afl_mutfunc_clone_bytes(&mutator, &input);
  input.bytes[copy->len - 1] = '\0';
  assert_string_not_equal(input.bytes, copy->bytes);
  afl_input_delete(copy);

  afl_input_deinit(&input);

  afl_mutator_deinit(&mutator);
  afl_stage_deinit(&stage);
  afl_fuzz_one_deinit(&fuzz_one);
  afl_engine_deinit(&engine);

}

/* Unittests for queue and queue entry based stuff */

#include "queue.h"

void test_queue_set_directory(void **state) {

  (void)state;

  afl_queue_t queue = {0};
  AFL_TRY(afl_queue_init(&queue), {

    WARNF("Could not init queue: %s", afl_ret_stringify(err));
    assert(0 && "COULD_NOT_INIT_QUEUE");

  });

  /* Testing for an empty dirpath */
  queue.funcs.set_dirpath(&queue, NULL);

  assert_string_equal(queue.dirpath, "");

  /* Testing for normal directory */
  char *new_dirpath = "/some/dir";
  queue.funcs.set_dirpath(&queue, new_dirpath);

  assert_string_equal(queue.dirpath, new_dirpath);

}

void test_base_queue_get_next(void **state) {

  (void)state;

  afl_engine_t engine = {0};
  afl_engine_init(&engine, NULL, NULL, NULL);
  llmp_client_state_t *client = llmp_client_new_unconnected();
  engine.llmp_client = client;
  afl_queue_t queue = {0};
  afl_queue_init(&queue);
  queue.engine = &engine;
  queue.engine_id = engine.id;

  /* When queue is empty we should get NULL */
  assert_null(queue.funcs.get_next_in_queue(&queue, engine.id));

  afl_input_t input = {0};

  afl_entry_t first_entry = {0};
  afl_entry_init(&first_entry, &input);

  queue.funcs.insert(&queue, &first_entry);

  afl_entry_t second_entry = {0};
  afl_entry_init(&second_entry, &input);

  queue.funcs.insert(&queue, &second_entry);

  /* Let's tell the queue with two entries now */
  assert_ptr_equal(queue.funcs.get_next_in_queue(&queue, engine.id), &first_entry);

  assert_ptr_equal(queue.funcs.get_next_in_queue(&queue, engine.id), &second_entry);

  assert_int_equal(queue.entries_count, 2);

  afl_queue_deinit(&queue);
  llmp_client_destroy(client);

}

int main(int argc, char **argv) {

  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_insert_substring),
      cmocka_unit_test(test_insert_bytes),
      cmocka_unit_test(test_erase_bytes),

      cmocka_unit_test(test_input_load_from_file),
      cmocka_unit_test(test_input_save_to_file),
      cmocka_unit_test(test_input_copy),

      cmocka_unit_test(test_engine_load_testcase_from_dir),

      cmocka_unit_test(test_basic_mutator_functions),

      cmocka_unit_test(test_queue_set_directory),
      cmocka_unit_test(test_base_queue_get_next),

  };

  // return cmocka_run_group_tests (tests, setup, teardown);
  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));

  // fake return for dumb compilers
  return 0;

}

