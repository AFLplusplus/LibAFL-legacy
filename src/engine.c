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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
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

static bool afl_engine_handle_single_testcase_load(char *infile, void *data) {

  afl_engine_t *engine = (afl_engine_t *)data;

  afl_input_t *input = afl_input_new();

  if (!input) {

    DBG("Error allocating input %s", infile);
    return false;

  }

  AFL_TRY(input->funcs.load_from_file(input, infile), {

    WARNF("Error loading seed %s: %s", infile, afl_ret_stringify(err));
    free(input);
    return false;

  });

  /*
    afl_ret_t run_result = engine->funcs.execute(engine, input);

    if (run_result == AFL_RET_SUCCESS) {

      if (engine->verbose) OKF("Loaded seed %s", infile);

    } else {

      WARNF("Error loading seed %s", infile);
      // free(input); // should we?
      return false;

    }

    // We add the corpus to the queue initially for all the feedback queues

    size_t i;
    for (i = 0; i < engine->feedbacks_count; ++i) {

      afl_entry_t *entry = afl_entry_new(input);
      if (!entry) {

        DBG("Error allocating entry.");
        return false;

      }

      engine->feedbacks[i]->queue->base.funcs.insert(&engine->feedbacks[i]->queue->base, entry);

    }

    //if (run_result == AFL_RET_WRITE_TO_CRASH) { if (engine->verbose) WARNF("Crashing input found in initial corpus,
    this is usually not a good idea.\n"); }
  */
  /* We add the corpus to the global queue */
  afl_entry_t *entry = afl_entry_new(input, NULL);
  if (!entry) {

    DBG("Error allocating entry.");
    return false;

  }

  engine->global_queue->base.funcs.insert(&engine->global_queue->base, entry);
  if (engine->verbose) OKF("Loaded seed %s", infile);

  return true;

}

afl_ret_t afl_engine_load_testcases_from_dir(afl_engine_t *engine, char *dirpath) {

  return afl_for_each_file(dirpath, afl_engine_handle_single_testcase_load, (void *)engine);

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

    afl_entry_info_t *info_ptr = (afl_entry_info_t *)((u8 *)(msg->buf + msg->buf_len));

    afl_entry_t *new_entry = afl_entry_new(input, info_ptr);

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

      afl_queue_global_t *global_queue = afl_engine_get_queue(engine);
      if (afl_input_dump_to_crashfile(executor->current_input, global_queue->base.dirpath) == AFL_RET_SUCCESS)
        engine->crashes++;
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

/* A function which can be run just before starting the fuzzing process. This checks if the engine(and all it's
 * components) is initialized or not */

afl_ret_t afl_engine_check_configuration(afl_engine_t *engine) {

  bool has_warning = false;

#define AFL_WARN_ENGINE(str)                              \
  do {                                                    \
                                                          \
    WARNF("No " str " present in engine-%u", engine->id); \
    has_warning = true;                                   \
                                                          \
  } while (0);

  if (!engine) {

    WARNF("Engine is null");
    return AFL_RET_NULL_PTR;

  }

  /* Let's start by checking the essential parts of engine, executor, feedback(if available) */

  if (!engine->executor) {

    // WARNF("No executor present in engine-%u", engine->id);
    // goto error;
    AFL_WARN_ENGINE("executor");

  }

  afl_executor_t *executor = engine->executor;

  if (!engine->global_queue) { AFL_WARN_ENGINE("global_queue") }
  afl_queue_global_t *global_queue = engine->global_queue;

  if (!engine->fuzz_one) { AFL_WARN_ENGINE("fuzzone") }
  afl_fuzz_one_t *fuzz_one = engine->fuzz_one;

  for (size_t i = 0; i < engine->feedbacks_count; ++i) {

    if (!engine->feedbacks[i]) {

      WARNF("Feedback is NULL at %lu idx but feedback count is greater (%llu).", i, engine->feedbacks_count);
      has_warning = true;
      break;

    }

  }

  if (!engine->llmp_client) { AFL_WARN_ENGINE("llmp client") }

  if (executor) {

    for (size_t i = 0; i < executor->observors_count; ++i) {

      if (!executor->observors[i]) { AFL_WARN_ENGINE("observation channel") }

    }

  }

  if (global_queue) {

    for (size_t i = 0; i < global_queue->feedback_queues_count; ++i) {

      if (!global_queue->feedback_queues[i]) { AFL_WARN_ENGINE("Feedback queue") }

    }

  }

  if (fuzz_one) {

    for (size_t i = 0; i < fuzz_one->stages_count; ++i) {

      if (!fuzz_one->stages[i]) { AFL_WARN_ENGINE("Stage") }
      /* Stage needs to be checked properly */

    }

  }

  if (has_warning) { return AFL_RET_ERROR_INITIALIZE; }

  return AFL_RET_SUCCESS;

#undef AFL_WARN_ENGINE

}

