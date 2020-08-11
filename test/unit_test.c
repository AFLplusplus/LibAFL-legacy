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

int main(int argc, char **argv) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_insert_substring),
      cmocka_unit_test(test_insert_bytes),
      cmocka_unit_test(test_erase_bytes),
      cmocka_unit_test(test_input_load_from_file),
      cmocka_unit_test(test_input_save_to_file),
      cmocka_unit_test(test_engine_load_testcase_from_dir_default),

  };

  // return cmocka_run_group_tests (tests, setup, teardown);
  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));

  // fake return for dumb compilers
  return 0;

}

