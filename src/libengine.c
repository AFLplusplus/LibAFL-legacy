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

#include "libengine.h"
#include "afl-returns.h"
#include "libfuzzone.h"
#include <dirent.h>
#include <time.h>

void _afl_engine_init_(engine_t *engine, executor_t *executor,
                       fuzz_one_t *fuzz_one, global_queue_t *global_queue) {

  engine->executor = executor;
  engine->fuzz_one = fuzz_one;
  engine->global_queue = global_queue;

  engine->funcs.get_queue = get_queue_default;
  engine->funcs.get_execs = get_execs_defualt;
  engine->funcs.get_fuzz_one = get_fuzz_one_default;
  engine->funcs.get_start_time = get_start_time_default;

  engine->funcs.set_fuzz_one = set_fuzz_one_default;
  engine->funcs.add_feedback = add_feedback_default;

  engine->funcs.execute = execute_default;
  engine->funcs.load_testcases_from_dir = load_testcases_from_dir_default;

}

void afl_engine_deinit(engine_t *engine) {

  /* Let's free everything associated with the engine here, except the queues,
   * should we leave anything else? */

  AFL_EXECUTOR_DEINIT(engine->executor);

  AFL_FUZZ_ONE_DEINIT(engine->fuzz_one);

  for (size_t i = 0; i < engine->feedbacks_num; ++i) {

    AFL_FEEDBACK_DEINIT(engine->feedbacks[i]);

  }

  free(engine);

  /* TODO: Should we free everything else like feedback, etc with engine too */

}

global_queue_t *get_queue_default(engine_t *engine) {

  return engine->global_queue;

}

fuzz_one_t *get_fuzz_one_default(engine_t *engine) {

  return engine->fuzz_one;

}

u64 get_execs_defualt(engine_t *engine) {

  return engine->executions;

}

u64 get_start_time_default(engine_t *engine) {

  return engine->start_time;

}

void set_fuzz_one_default(engine_t *engine, fuzz_one_t *fuzz_one) {

  engine->fuzz_one = fuzz_one;

}

int add_feedback_default(engine_t *engine, feedback_t *feedback) {

  if (engine->feedbacks_num >= MAX_FEEDBACKS) return 1;

  engine->feedbacks_num++;

  engine->feedbacks[(engine->feedbacks_num - 1)] = feedback;

  return 0;

}

afl_ret_t load_testcases_from_dir_default(engine_t *engine, char *dirpath,
                                          raw_input_t *(*custom_input_init)()) {

  DIR *          dir_in;
  struct dirent *dir_ent;
  char             infile[PATH_MAX];

  raw_input_t *input;
  size_t       dir_name_size = strlen(dirpath);

  if (dirpath[dir_name_size - 1] == '/') {

    dirpath[dir_name_size - 1] = '\x00';

  }

  if (!(dir_in = opendir(dirpath))) { return AFL_RET_FILE_OPEN; }

  /* Since, this'll be the first execution, Let's start up the executor here */

  if (engine->executor->funcs.init_cb) {

    engine->executor->funcs.init_cb(engine->executor);

  }

  while ((dir_ent = readdir(dir_in))) {

    if (dir_ent->d_name[0] == '.') {

      continue;  // skip anything that starts with '.'

    }

    if (custom_input_init) {

      input = custom_input_init();

    }

    else {

      input = afl_input_init(NULL);

    }

    snprintf((char *)infile, sizeof(infile), "%s/%s", dirpath, dir_ent->d_name);

    input->funcs.load_from_file(input, infile);

    engine->funcs.execute(engine, input);

  }

  closedir(dir_in);

  return AFL_RET_SUCCESS;

}

u8 execute_default(engine_t *engine, raw_input_t *input) {

  executor_t *executor = engine->executor;

  executor->funcs.reset_observation_channels(executor);

  executor->funcs.place_inputs_cb(executor, input);

  if (engine->start_time == 0) { engine->start_time = time(NULL); }

  exit_type_t run_result = executor->funcs.run_target_cb(executor);

  engine->executions++;

  /* We've run the target with the executor, we can now simply postExec call the
   * observation channels*/

  for (size_t i = 0; i < executor->observors_num; ++i) {

    observation_channel_t *obs_channel = executor->observors[i];
    if (obs_channel->funcs.post_exec) {

      obs_channel->funcs.post_exec(executor->observors[i]);

    }

  }

  /* Let's collect some feedback on the input now */

  bool add_to_queue = false;

  for (size_t i = 0; i < engine->feedbacks_num; ++i) {

    add_to_queue = add_to_queue || engine->feedbacks[i]->funcs.is_interesting(
                                       engine->feedbacks[i], executor);

  }

  /* If the input is interesting and there is a global queue add the input to
   * the queue */
  if (add_to_queue && engine->global_queue) {

    queue_entry_t *entry = afl_queue_entry_init(NULL, input);

    if (!entry) { return AFL_RET_ALLOC; }

    global_queue_t *queue = engine->global_queue;

    queue->base.funcs.add_to_queue((base_queue_t *)queue, entry);

  }

  return run_result;

}

void loop(engine_t *engine) {

  while (true) {

    engine->fuzz_one->funcs.perform(engine->fuzz_one);

  }

}

