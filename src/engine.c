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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>

#include "engine.h"
#include "aflpp.h"
#include "afl-returns.h"
#include "fuzzone.h"
#include "os.h"

afl_ret_t afl_engine_init(engine_t *engine, executor_t *executor,
                          fuzz_one_t *fuzz_one, global_queue_t *global_queue) {

  engine->executor = executor;
  engine->fuzz_one = fuzz_one;
  engine->global_queue = global_queue;

  if (global_queue) {

    global_queue->base.funcs.set_engine(&global_queue->base, engine);

  }

  engine->funcs.get_queue = afl_get_queue_default;
  engine->funcs.get_execs = afl_get_execs_defualt;
  engine->funcs.get_fuzz_one = afl_get_fuzz_one_default;
  engine->funcs.get_start_time = afl_get_start_time_default;

  engine->funcs.set_fuzz_one = afl_set_fuzz_one_default;
  engine->funcs.add_feedback = afl_add_feedback_default;
  engine->funcs.set_global_queue = afl_set_global_queue_default;

  engine->funcs.execute = afl_execute_default;
  engine->funcs.load_testcases_from_dir = afl_load_testcases_from_dir_default;
  engine->funcs.loop = afl_loop_default;
  engine->id = rand();
  engine->dev_urandom_fd = open("/dev/urandom", O_RDONLY);

  if (!engine->dev_urandom_fd) { return AFL_RET_ERROR_INITIALIZE; }

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

global_queue_t *afl_get_queue_default(engine_t *engine) {

  return engine->global_queue;

}

fuzz_one_t *afl_get_fuzz_one_default(engine_t *engine) {

  return engine->fuzz_one;

}

u64 afl_get_execs_defualt(engine_t *engine) {

  return engine->executions;

}

u64 afl_get_start_time_default(engine_t *engine) {

  return engine->start_time;

}

void afl_set_fuzz_one_default(engine_t *engine, fuzz_one_t *fuzz_one) {

  engine->fuzz_one = fuzz_one;

  if (fuzz_one) {

    fuzz_one->funcs.set_engine_default(engine->fuzz_one, engine);

  }

}

void afl_set_global_queue_default(engine_t *      engine,
                                  global_queue_t *global_queue) {

  engine->global_queue = global_queue;

  if (global_queue) {

    global_queue->base.funcs.set_engine(&global_queue->base, engine);

  }

}

int afl_add_feedback_default(engine_t *engine, feedback_t *feedback) {

  if (engine->feedbacks_num >= MAX_FEEDBACKS) return 1;

  engine->feedbacks_num++;

  engine->feedbacks[(engine->feedbacks_num - 1)] = feedback;

  return 0;

}

afl_ret_t afl_load_testcases_from_dir_default(
    engine_t *engine, char *dirpath, raw_input_t *(*custom_input_create)()) {

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

    if (custom_input_create) {

      input = custom_input_create();

    }

    else {

      input = afl_input_create();

    }

    if (!input) {

      closedir(dir_in);
      if (engine->executor->funcs.destroy_cb) {

        engine->executor->funcs.destroy_cb(engine->executor);

      };

      return AFL_RET_ALLOC;

    }

    snprintf((char *)infile, sizeof(infile), "%s/%s", dirpath, dir_ent->d_name);

    /* TODO: Error handling? */
    input->funcs.load_from_file(input, infile);

    afl_ret_t run_result = engine->funcs.execute(engine, input);

    /* We add the corpus to the queue initially for all the feedback queues */

    for (size_t i = 0; i < engine->feedbacks_num; ++i) {

      raw_input_t *copy = input->funcs.copy(input);
      if (!copy) { return AFL_RET_ERROR_INPUT_COPY; }

      queue_entry_t *entry = afl_queue_entry_create(copy);
      engine->feedbacks[i]->queue->base.funcs.add_to_queue(
          &engine->feedbacks[i]->queue->base, entry);

    }

    if (run_result == AFL_RET_WRITE_TO_CRASH) {

      SAYF("Crashing input found in initial corpus\n");

    }

    afl_input_delete(input);
    input = NULL;

  }

  closedir(dir_in);

  return AFL_RET_SUCCESS;

}

u8 afl_execute_default(engine_t *engine, raw_input_t *input) {

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

      obs_channel->funcs.post_exec(executor->observors[i], engine);

    }

  }

  // Now based on the return of executor's run target, we basically return an
  // afl_ret_t type to the callee

  switch (run_result) {

    case NORMAL:
    case TIMEOUT:
      return AFL_RET_SUCCESS;
    default: {

      engine->crashes++;
      dump_crash_to_file(executor->current_input, engine);  // Crash written
      return AFL_RET_WRITE_TO_CRASH;

    }

  }

}

afl_ret_t afl_loop_default(engine_t *engine) {

  while (true) {

    afl_ret_t fuzz_one_ret = engine->fuzz_one->funcs.perform(engine->fuzz_one);

    switch (fuzz_one_ret) {

        // case AFL_RET_WRITE_TO_CRASH:

        //   // crash_write_return =
        //   // dump_crash_to_file(engine->executor->current_input);

        //   return AFL_RET_WRITE_TO_CRASH;

        //   break;

      case AFL_RET_NULL_QUEUE_ENTRY:
        return fuzz_one_ret;
      case AFL_RET_ERROR_INPUT_COPY:
        return fuzz_one_ret;
      default:
        continue;

    }

  }

}

