
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

#include "llmp.h"

static inline void test_llmp_client(void **state) {

  (void)state;

  llmp_client_state_t *client = llmp_client_new_unconnected();
  llmp_client_alloc_next(client, LLMP_INITIAL_MAP_SIZE + 10);

  // Make sure larger allocations work and create a new map :)
  assert_int_equal(client->out_map_count, 2);
  llmp_client_destroy(client);

}

static void test_client_eop(void **state) {

  (void)state;

  llmp_client_state_t *client = llmp_client_new_unconnected();

  u32 i;
  for (i = 0; i < 150000; i++) {

    llmp_message_t *last_msg = llmp_client_alloc_next(client, i);
    assert(last_msg && "Last_msg was null :(");
    last_msg->tag = 0x7357;
    llmp_client_send(client, last_msg);

  }

  llmp_client_destroy(client);

}

int main(int argc, char **argv) {

  (void)argc;
  (void)argv;
  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_llmp_client),
      cmocka_unit_test(test_client_eop),

  };

  // return cmocka_run_group_tests (tests, setup, teardown);
  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));

  // fake return for dumb compilers
  return 0;

}

