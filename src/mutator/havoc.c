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

#include "mutator/havoc.h"

struct afl_scheduled_mutator_vtable afl_havoc_mutator_vtable_instance = {

    /* afl_mutator vtable */
    ._base =
        {

            /* afl_object vtable */
            .base =
                {

                    AFL_VTABLE_INIT_BASE_VPTR(afl_scheduled_mutator),

                    .deinit = afl_scheduled_mutator_deinit__nonvirtual

                },

            .mutate = &afl_scheduled_mutator_mutate__nonvirtual

        },

    .iterations = NULL,
    .schedule = NULL

};

