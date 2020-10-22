/* An in memeory fuzzing example. tests segfault, timeout and abort. */

#include <stdio.h>
#include <stdint.h>
#include "debug.h"

static void force_segfault(void) {

  DBG("Crashing...");
  /* If you don't segfault, what else will? */
  printf("%d", ((int *)1337)[42]);

}

static void force_timeout(void) {

  DBG("Timeouting...");
  static volatile int a = 1337;
  while (a) {}

}

/* c2rust always expects this here */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void) argc;
  (void) argv;
  return 0;
}

/* The actual harness. Using PNG for our example. */
int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {

  if (len < 5) return 0;

  if (input[0] == 'a' && input[1] == 'a' && input[2] == 'a') {

    DBG("Crashing happy");
    force_segfault();

  }

  if (input[0] == 'b' && input[1] == 'b' && input[2] == 'b') {

    DBG("Timeouting happy");
    force_timeout();

  }

  if (input[0] == 'F')
    if (input[1] == 'A')
      if (input[2] == '$')
        if (input[3] == '$')
          if (input[4] == '$') abort();

  return 0;

}

