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
#include <limits.h>

#include "engine.h"
#include "aflpp.h"
#include "afl-returns.h"
#include "fuzzone.h"
#include "os.h"
#include "queue.h"
#include "input.h"

afl_ret_t afl_engine_init(afl_engine_t *engine, afl_executor_t *executor, afl_fuzz_one_t *fuzz_one,
                          afl_queue_global_t *global_queue) {

  engine->executor = executor;
  engine->fuzz_one = fuzz_one;
  engine->global_queue = global_queue;
  engine->feedbacks = NULL;
  engine->feedbacks_count = 0;
  engine->executions = 0;

  if (global_queue) { global_queue->base.funcs.set_engine(&global_queue->base, engine); }

  engine->funcs.get_queue = afl_engine_get_queue;
  engine->funcs.get_execs = afl_get_execs;
  engine->funcs.get_fuzz_one = afl_engine_get_fuzz_one;
  engine->funcs.get_start_time = afl_engine_get_start_time;

  engine->funcs.set_fuzz_one = afl_set_fuzz_one;
  engine->funcs.add_feedback = afl_engine_add_feedback;
  engine->funcs.set_global_queue = afl_set_global_queue;

  engine->funcs.execute = afl_engine_execute;
  engine->funcs.load_testcases_from_dir = afl_engine_load_testcases_from_dir;
  engine->funcs.loop = afl_engine_loop;
  engine->funcs.handle_new_message = afl_engine_handle_new_message;
  afl_ret_t ret = afl_rand_init(&engine->rand);

  engine->buf = NULL;

  if (ret != AFL_RET_SUCCESS) { return ret; }

  engine->id = afl_rand_next(&engine->rand);

  return AFL_RET_SUCCESS;

}

void afl_engine_deinit(afl_engine_t *engine) {

  size_t i;
  /* Let's free everything associated with the engine here, except the queues,
   * should we leave anything else? */

  afl_rand_deinit(&engine->rand);

  engine->fuzz_one = NULL;
  engine->executor = NULL;
  engine->global_queue = NULL;

  for (i = 0; i < engine->feedbacks_count; ++i) {

    engine->feedbacks[i] = NULL;

  }

  afl_free(engine->feedbacks);
  engine->feedbacks = NULL;

  engine->start_time = 0;
  engine->current_feedback_queue = NULL;
  engine->feedbacks_count = 0;
  engine->executions = 0;

}

afl_queue_global_t *afl_engine_get_queue(afl_engine_t *engine) {

  return engine->global_queue;

}

afl_fuzz_one_t *afl_engine_get_fuzz_one(afl_engine_t *engine) {

  return engine->fuzz_one;

}

u64 afl_get_execs(afl_engine_t *engine) {

  return engine->executions;

}

u64 afl_engine_get_start_time(afl_engine_t *engine) {

  return engine->start_time;

}

void afl_set_fuzz_one(afl_engine_t *engine, afl_fuzz_one_t *fuzz_one) {

  engine->fuzz_one = fuzz_one;

  if (fuzz_one) { fuzz_one->funcs.set_engine(engine->fuzz_one, engine); }

}

void afl_set_global_queue(afl_engine_t *engine, afl_queue_global_t *global_queue) {

  engine->global_queue = global_queue;

  if (global_queue) { global_queue->base.funcs.set_engine(&global_queue->base, engine); }

}

afl_ret_t afl_engine_add_feedback(afl_engine_t *engine, afl_feedback_t *feedback) {

  engine->feedbacks_count++;
  engine->feedbacks = afl_realloc(engine->feedbacks, engine->feedbacks_count * sizeof(afl_feedback_t *));
  if (!engine->feedbacks) { return AFL_RET_ALLOC; }

  engine->feedbacks[engine->feedbacks_count - 1] = feedback;

  return AFL_RET_SUCCESS;

}

afl_ret_t afl_engine_load_testcases_from_dir(afl_engine_t *engine, char *dirpath,
                                             afl_input_t *(*custom_input_new)(void)) {

  DIR *          dir_in = NULL;
  struct dirent *dir_ent = NULL;
  char           infile[PATH_MAX];
  size_t         i;

  afl_input_t *input;
  size_t       dir_name_size = strlen(dirpath);

  if (dirpath[dir_name_size - 1] == '/') { dirpath[dir_name_size - 1] = '\x00'; }

  if (!(dir_in = opendir(dirpath))) { return AFL_RET_FILE_OPEN_ERROR; }

  /* Since, this'll be the first execution, Let's start up the executor here */

  if ((engine->executions == 0) && engine->executor->funcs.init_cb) {

    AFL_TRY(engine->executor->funcs.init_cb(engine->executor), {

      closedir(dir_in);
      return err;

    });

  }

  while ((dir_ent = readdir(dir_in))) {

    if (dir_ent->d_name[0] == '.') {

      continue;  // skip anything that starts with '.'

    }

    /* TODO: Not sure if this makes any sense at all? */
    if (custom_input_new) {

      input = custom_input_new();

    }

    else {

      input = afl_input_new();

    }

    if (!input) {

      closedir(dir_in);
      if (engine->executor->funcs.destroy_cb) { engine->executor->funcs.destroy_cb(engine->executor); };

      return AFL_RET_ALLOC;

    }

    snprintf((char *)infile, sizeof(infile), "%s/%s", dirpath, dir_ent->d_name);
    infile[sizeof(infile) - 1] = '\0';

    /* TODO: Error handling? */
    input->funcs.load_from_file(input, infile);

    afl_ret_t run_result = engine->funcs.execute(engine, input);

    /* We add the corpus to the queue initially for all the feedback queues */

    for (i = 0; i < engine->feedbacks_count; ++i) {

      afl_input_t *copy = input->funcs.copy(input);
      if (!copy) { return AFL_RET_ERROR_INPUT_COPY; }

      afl_entry_t *entry = afl_entry_new(copy);
      engine->feedbacks[i]->queue->base.funcs.insert(&engine->feedbacks[i]->queue->base, entry);

    }

    if (run_result == AFL_RET_WRITE_TO_CRASH) { SAYF("Crashing input found in initial corpus\n"); }

    afl_input_delete(input);
    input = NULL;

  }

  closedir(dir_in);

  return AFL_RET_SUCCESS;

}

afl_ret_t afl_engine_handle_new_message(afl_engine_t *engine, llmp_message_t *msg) {

  /* Default implementation, handles only new queue entry messages. Users have
   * liberty with this function */

  if (msg->tag == LLMP_TAG_NEW_QUEUE_ENTRY_V1) {

    afl_input_t *input = afl_input_new();
    if (!input) { return AFL_RET_ALLOC; }

    /* the msg will stick around forever, so this is safe. */
    input->bytes = msg->buf;
    input->len = msg->buf_len;

    if (!input) { FATAL("Error creating a copy of input"); }

    afl_entry_t *new_entry = afl_entry_new(input);

    /* Users can experiment here, adding entries to different queues based on
     * the message tag. Right now, let's just add it to all queues*/
    size_t i = 0;
    engine->global_queue->base.funcs.insert(&engine->global_queue->base, new_entry);
    afl_queue_feedback_t **feedback_queues = engine->global_queue->feedback_queues;
    for (i = 0; i < engine->global_queue->feedback_queues_count; ++i) {

      feedback_queues[i]->base.funcs.insert(&feedback_queues[i]->base, new_entry);

    }

  }

  return AFL_RET_SUCCESS;

}

u8 afl_engine_execute(afl_engine_t *engine, afl_input_t *input) {

  size_t          i;
  afl_executor_t *executor = engine->executor;

  executor->funcs.observers_reset(executor);

  executor->funcs.place_input_cb(executor, input);

  if (engine->start_time == 0) { engine->start_time = time(NULL); }

  afl_exit_t run_result = executor->funcs.run_target_cb(executor);

  engine->executions++;

  /* We've run the target with the executor, we can now simply postExec call the
   * observation channels*/

  for (i = 0; i < executor->observors_count; ++i) {

    afl_observer_t *obs_channel = executor->observors[i];
    if (obs_channel->funcs.post_exec) { obs_channel->funcs.post_exec(executor->observors[i], engine); }

  }

  // Now based on the return of executor's run target, we basically return an
  // afl_ret_t type to the callee

  switch (run_result) {

    case AFL_EXIT_OK:
    case AFL_EXIT_TIMEOUT:
      return AFL_RET_SUCCESS;
    default: {

      engine->crashes++;
      afl_input_dump_to_crashfile(executor->current_input);  // Crash written
      return AFL_RET_WRITE_TO_CRASH;

    }

  }

}

afl_ret_t afl_engine_loop(afl_engine_t *engine) {

  while (true) {

    afl_ret_t fuzz_one_ret = engine->fuzz_one->funcs.perform(engine->fuzz_one);

    /* let's call this engine's message handler */

    if (engine->funcs.handle_new_message) {

      /* Let's read the broadcasted messages now */
      llmp_message_t *msg = NULL;

      while ((msg = llmp_client_recv(engine->llmp_client))) {

        AFL_TRY(engine->funcs.handle_new_message(engine, msg), { return err; });

      }

    }

    switch (fuzz_one_ret) {

        // case AFL_RET_WRITE_TO_CRASH:

        //   // crash_write_return =
        //   // afl_input_dump_to_crashfile(engine->executor->current_input);

        //   return AFL_RET_WRITE_TO_CRASH;

        //   break;

      case AFL_RET_NULL_QUEUE_ENTRY:
        SAYF("NULL QUEUE\n");
        return fuzz_one_ret;
      case AFL_RET_ERROR_INPUT_COPY:
        return fuzz_one_ret;
      default:
        continue;

    }

  }

}

#define AFL_WARN_ENGINE(engine, str)                    \
  WARNF("No %s present in engine-%u", str, engine->id); \
  goto error;

/* A function which can be run just before starting the fuzzing process. This checks if the engine(and all it's
 * components) is initialized or not */

afl_ret_t afl_check_engine_configuration(afl_engine_t *engine) {

  /* Let's start by checking the essential parts of engine, executor, feedback(if available) */

  if (!engine->executor) {

    // WARNF("No executor present in engine-%u", engine->id);
    // goto error;
    AFL_WARN_ENGINE(engine, "executor");

  }

  afl_executor_t *executor = engine->executor;

  if (!engine->global_queue) { AFL_WARN_ENGINE(engine, "global_queue") }
  afl_queue_global_t *global_queue = engine->global_queue;

  if (!engine->fuzz_one) { AFL_WARN_ENGINE(engine, "fuzzone") }
  afl_fuzz_one_t *fuzz_one = engine->fuzz_one;

  for (size_t i = 0; i < engine->feedbacks_count; ++i) {

    if (!engine->feedbacks[i]) {

      WARNF("Feedback is NULL at %lu idx but feedback num is greater than it.", i);
      goto error;

    }

  }

  if (!engine->llmp_client) { AFL_WARN_ENGINE(engine, "llmp client") }

  for (size_t i = 0; i < executor->observors_count; ++i) {

    if (!executor->observors[i]) { AFL_WARN_ENGINE(engine, "observation channel") }

  }

  for (size_t i = 0; i < global_queue->feedback_queues_count; ++i) {

    if (!global_queue->feedback_queues[i]) { AFL_WARN_ENGINE(engine, "Feedback queue") }

  }

  for (size_t i = 0; i < fuzz_one->stages_count; ++i) {

    if (!fuzz_one->stages[i]) { AFL_WARN_ENGINE(engine, "Stage") }
    /* Stage needs to be checked properly */

  }

  return AFL_RET_SUCCESS;

error:
  return AFL_RET_ERROR_INITIALIZE;

}

