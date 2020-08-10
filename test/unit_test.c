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

  char s[100];
  memcpy(s, "This is a string", 17);

  char *new_string =
      insert_substring(s, strlen(s), test_token, strlen(test_token), 10);

  assert_string_equal(new_string, test_string);
  free(new_string);

}

static void test_insert_bytes(void **state) {

  (void)state;
  char s[100];
  memcpy(s, "This is a string", 17);

  u8          test_byte = 0x41;
  const char *test_string = "This is a AAAAAAAstring";

  char *new_string = insert_bytes(s, strlen(s), test_byte, 7, 10);

  assert_string_equal(new_string, test_string);
  free(new_string);

}

static void test_erase_bytes(void **state) {

  (void)state;
  char s[100];
  memcpy(s, "This is a string", 17);

  const char *test_string = "This string";

  erase_bytes(s, strlen(s), 5, 5);

  assert_string_equal(s, test_string);

}

/* Let's test libinput based default functions */

#include "libinput.h"

void test_input_load_from_file(void ** state) {
    
    (void) state;
    /* We first write some string to a file */
    char * fname = "./test_input_file";
    char *test_string = "This is a test string";
    int fd = open(fname, O_RDWR | O_CREAT, 0600);

    int write_len = write(fd, test_string, 22);

    /* Create an input now and test it */
    raw_input_t input;

    /* We just have to test the default func, we don't use the vtable here */
    raw_inp_load_from_file_default(&input,fname);

    assert_string_equal(input.bytes, test_string);
    assert_int_equal(input.len, write_len);

    free(input.bytes);
    unlink(fname);

}

void test_input_save_to_file(void ** state) {
    
    (void) state;
    /* We first write some string to a file */
    char * fname = "test_output_file";
    char *test_string = "This is a test string";

    char read_string[100];

    /* Create an input now and test it */
    raw_input_t input;
    input.bytes = (u8 *)test_string;
    input.len = strlen(test_string);

    /* We just have to test the default func, we don't use the vtable here */
    raw_inp_save_to_file_default(&input,fname);

    int fd = open(fname, O_RDONLY);

    int read_len = read(fd, read_string, 22);

    assert_string_equal(input.bytes, read_string);
    assert_int_equal(input.len, read_len);

    close(fd);
    unlink(fname);

}

int main(int argc, char **argv) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_insert_substring),
      cmocka_unit_test(test_insert_bytes),
      cmocka_unit_test(test_erase_bytes),
      cmocka_unit_test(test_input_load_from_file),
      cmocka_unit_test(test_input_save_to_file),
  };

  // return cmocka_run_group_tests (tests, setup, teardown);
  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));



  // fake return for dumb compilers
  return 0;

}

