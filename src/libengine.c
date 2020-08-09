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

#include <dirent.h>
#include <time.h>

#include "libengine.h"
#include "afl-returns.h"
#include "libfuzzone.h"
#include "libos.h"

afl_ret_t afl_engine_init(engine_t *engine, executor_t *executor,
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
  engine->funcs.loop = loop_default;

  return AFL_RET_SUCCESS;

}

void afl_engine_deinit(engine_t *engine) {

  /* Let's free everything associated with the engine here, except the queues,
   * should we leave anything else? */

  engine->fuzz_one = NULL;
  engine->executor = NULL;
  engine->global_queue = NULL;

  for (size_t i = 0; i < engine->feedbacks_num; ++i) {

    engine->feedbacks[i] = NULL;

  }

  engine->start_time = 0;
  engine->current_feedback_queue = NULL;
  engine->feedbacks_num = 0;
  engine->executions = 0;

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
  char           infile[PATH_MAX];

  raw_input_t *input;
  size_t       dir_name_size = strlen(dirpath);

  if (dirpath[dir_name_size - 1] == '/') {

    dirpath[dir_name_size - 1] = '\x00';

  }

  if (!(dir_in = opendir(dirpath))) { return AFL_RET_FILE_OPEN_ERROR; }

  /* Since, this'll be the first execution, Let's start up the executor here */

  if (engine->executor->funcs.init_cb) {

    afl_ret_t ret = engine->executor->funcs.init_cb(engine->executor);
    if (ret != AFL_RET_SUCCESS) {

      closedir(dir_in);
      return ret;

    }

  }

  while ((dir_ent = readdir(dir_in))) {

    if (dir_ent->d_name[0] == '.') {

      continue;  // skip anything that starts with '.'

    }

    if (custom_input_init) {

      input = custom_input_init();

    }

    else {

      input = afl_input_create();

    }

    if (!input) {

      closedir(dir_in);
      engine->executor->funcs.destroy_cb(engine->executor);
      return AFL_RET_ALLOC;

    }

    snprintf((char *)infile, sizeof(infile), "%s/%s", dirpath, dir_ent->d_name);

    /* TODO: Error handling? */
    input->funcs.load_from_file(input, infile);

    engine->funcs.execute(engine, input);

    input = NULL;

  }

  closedir(dir_in);

  return AFL_RET_SUCCESS;

}

u8 execute_default(engine_t *engine, raw_input_t *input) {

  executor_t *executor = engine->executor;

  executor->funcs.reset_observation_channels(executor);

  executor->funcs.place_input_cb(executor, input);

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

    queue_entry_t *entry = afl_queue_entry_create(input->funcs.copy(input));

    if (!entry) { return AFL_RET_ALLOC; }

    global_queue_t *queue = engine->global_queue;

    queue->base.funcs.add_to_queue((base_queue_t *)queue, entry);

  }

  /* We delete the input now. It is assumed that the iput sent to fuzz was a
     copy of the original one from queue.
     If it had to be added to the queue, a copy of it has been added, */
  afl_input_delete(input);

  // Now based on the return of executor's run target, we basically return an
  // afl_ret_t type to the callee

  switch (run_result) {

    case NORMAL:
    case TIMEOUT:
      return AFL_RET_SUCCESS;
    default:
      return AFL_RET_WRITE_TO_CRASH;

  }

}

afl_ret_t loop_default(engine_t *engine) {

  while (true) {

    afl_ret_t crash_write_return;

    afl_ret_t fuzz_one_ret = engine->fuzz_one->funcs.perform(engine->fuzz_one);

    switch (fuzz_one_ret) {

      case AFL_RET_WRITE_TO_CRASH:

        crash_write_return =
            dump_crash_to_file(engine->executor->current_input);
        if (crash_write_return == AFL_RET_FILE_OPEN_ERROR) {

          return AFL_RET_FILE_OPEN_ERROR;

        }

        break;

      case AFL_RET_NULL_QUEUE_ENTRY:
        return fuzz_one_ret;

      default:
        continue;

    }

  }

}

