/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0


 */

#include "libcommon.h"
#include "libinput.h"
#include "list.h"

// Mutator struct will have many internal functions like mutate, trimming etc.
// This is based on both the FFF prototype and the custom mutators that we have
// in AFL++ without the AFL++ specific parts
typedef struct mutator {

  stage_t *stage;

  struct mutator_functions *functions;

} mutator_t;

/* Do we need more functions in the mutator? */
struct mutator_functions {

  void (*init)(mutator_t *);  // Sort of like the afl_custom_init we have for
                              // custom mutators?

  size_t (*trim)(mutator_t *, u8 *,
                 u8 *);  // The params here are in_buf and out_buf.

  size_t (*mutate)(mutator_t *, raw_input_t *, size_t);  // Mutate function

  stage_t *(*get_stage)(mutator_t *);

};

stage_t *_get_mutator_stage_(mutator_t *);

mutator_t *afl_mutator_init(stage_t *);
void       afl_mutator_deinit(mutator_t *);

// A simple scheduled mutator based on the above mutator. Will act something
// similar to the havoc stage

typedef void (*mutator_func_type)(mutator_t *, raw_input_t *);

typedef struct scheduled_mutator {

  mutator_t super;
  list_t    mutations;

  struct scheduled_mutator_functions *extra_functions;

} scheduled_mutator_t;

struct scheduled_mutator_functions {

  int (*schedule)(scheduled_mutator_t *);
  void (*add_mutator)(scheduled_mutator_t *, mutator_func_type);
  int (*iterations)(void);

};

/* TODO add implementation for the _schedule_ and _iterations_ functions, need a
 * random list element pop type implementation for this */
int  _iterations_(scheduled_mutator_t *);
void _add_mutator_(scheduled_mutator_t *, mutator_func_type);
void _schedule_(scheduled_mutator_t *);

scheduled_mutator_t *afl_scheduled_mutator_init(stage_t *);
void                 afl_scheduled_mutator_deinit(scheduled_mutator_t *);

