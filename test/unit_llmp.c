
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

  llmp_client_t *client = llmp_client_new_unconnected();
  /* Make sure we can allocate something that's too big for our current map */
  assert_non_null(llmp_client_alloc_next(client, LLMP_INITIAL_MAP_SIZE + 10));

  // Make sure larger allocations work and create a new map :)
  assert_int_equal(client->out_map_count, 2);
  llmp_client_delete(client);

}

#define CORRECT_DATA_TAG (0xC088EC7)
static void eop_hook(llmp_client_t *state, llmp_page_t *page, void *data) {

  OKF("Hook triggered! :)\n");

  /* make sure we get the latest page in the stage */
  assert_ptr_equal((u8 *)page, state->out_maps[state->out_map_count - 1].map);

  /* make sure data contains what we put in */
  assert_int_equal(((u32 *)data)[0], CORRECT_DATA_TAG);
  ((u32 *)data)[1]++;

}

static void test_client_eop(void **state) {

  (void)state;

  llmp_client_t *client = llmp_client_new_unconnected();

  /* loc 1 = tag, loc2 = eop count */
  u32 infos[2];
  infos[0] = CORRECT_DATA_TAG;
  infos[1] = 0;

  llmp_client_add_new_out_page_hook(client, eop_hook, (void *)&infos);

  assert_int_equal(client->new_out_page_hook_count, 1);

  u32 i;
  for (i = 0; i < 15000; i++) {

    llmp_message_t *last_msg = llmp_client_alloc_next(client, i * 10);
    assert(last_msg && "Last_msg was null :(");
    last_msg->tag = 0x7357;
    llmp_client_send(client, last_msg);

  }

  llmp_client_delete(client);

  assert_int_not_equal(infos[1], 0);
  assert_int_not_equal(infos[1], 1);

}

static inline void test_llmp_client_message_cancel(void **state) {

  (void)state;

  llmp_client_t *client = llmp_client_new_unconnected();
  llmp_message_t *old_msg = llmp_client_alloc_next(client, 10);

  llmp_client_cancel(client, old_msg);
  llmp_message_t *new_msg = llmp_client_alloc_next(client, 100);

  assert_ptr_equal(old_msg, new_msg);
  assert_true(llmp_client_send(client, new_msg));

  llmp_message_t *old_msg2 = llmp_client_alloc_next(client, 10);

  llmp_client_cancel(client, old_msg2);
  llmp_message_t *new_msg2 = llmp_client_alloc_next(client, 100);

  assert_ptr_not_equal(old_msg, old_msg2);
  assert_ptr_not_equal(new_msg, new_msg2);

  assert_ptr_equal(old_msg2, new_msg2);

  assert_true(llmp_client_send(client, new_msg2));

  llmp_client_delete(client);

}


int main(int argc, char **argv) {

  (void)argc;
  (void)argv;
  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_llmp_client),
      cmocka_unit_test(test_client_eop),
      cmocka_unit_test(test_llmp_client_message_cancel),

  };

  // return cmocka_run_group_tests (tests, setup, teardown);
  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));

  // fake return for dumb compilers
  return 0;

}

