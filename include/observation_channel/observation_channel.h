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

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */

#ifndef LIBAFL_OBSERVATION_CHANNEL_OBSERVATION_CHANNEL_H
#define LIBAFL_OBSERVATION_CHANNEL_OBSERVATION_CHANNEL_H

#include "object.h"
#include "error.h"

typedef struct afl_observation_channel afl_observation_channel_t;

struct afl_observation_channel_vtable {

  /*
    The deinit() method is optional.
    It is invoked just before the destroy of the object.
  */
  void (*deinit)(afl_observation_channel_t *);

  /*
    The flush() method is optional.
  */
  void (*flush)(afl_observation_channel_t *);
  
  /*
    The reset() method is optional.
  */
  void (*reset)(afl_observation_channel_t *);
  
  /*
    The post_exec() method is optional.
  */
  void (*post_exec)(afl_observation_channel_t *, afl_executor_t *);

};

struct afl_observation_channel {

  INHERITS(afl_object)

  struct afl_observation_channel_vtable *v;

};

/*
  Initialize an empty, just allocated, afl_observation_channel_t object.
  Virtual class, protected init.
*/
afl_ret_t afl_observation_channel_init__protected(afl_observation_channel_t *);

/*
  Deinit the context of an afl_observation_channel_t.
*/
void afl_observation_channel_deinit__nonvirtual(afl_observation_channel_t *self);

/*
  Deinit an afl_observation_channel_t object, you must call this method before releasing
  the memory used by the object.
*/
static inline void afl_observation_channel_deinit(afl_observation_channel_t *self) {

  DCHECK(self);
  if (self->v->deinit) self->v->deinit(self);

}

static inline void afl_observation_channel_flush(afl_observation_channel_t *self) {

  DCHECK(self);
  if (self->v->flush) self->v->flush(self);

}

static inline void afl_observation_channel_reset(afl_observation_channel_t *self) {

  DCHECK(self);
  if (self->v->reset) self->v->reset(self);

}

static inline void afl_observation_channel_post_exec(afl_observation_channel_t *self, afl_executor_t* executor) {

  DCHECK(self);
  if (self->v->post_exec) self->v->post_exec(self, executor);

}

AFL_DELETE_FOR(afl_observation_channel)

#endif

