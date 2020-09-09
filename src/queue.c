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

#include <sys/stat.h>

#include "queue.h"
#include "feedback.h"
#include "engine.h"
#include "fuzzone.h"
#include "stage.h"
#include "mutator.h"

// We start with the implementation of queue_entry functions here.
afl_ret_t afl_queue_entry_init(queue_entry_t *entry, raw_input_t *input) {

  entry->input = input;
  memset(entry->filename, 0, FILENAME_LEN_MAX);

  entry->funcs.get_input = afl_get_input_default;
  entry->funcs.get_next = afl_get_next_default;
  entry->funcs.get_prev = afl_get_prev_default;
  entry->funcs.get_parent = afl_get_parent_default;

  return AFL_RET_SUCCESS;

}

void afl_queue_entry_deinit(queue_entry_t *entry) {

  /* We remove the element from the linked-list */

  if (entry->next) { entry->next->prev = entry->prev; }

  if (entry->prev) { entry->prev->next = entry->next; }

  entry->next = NULL;
  entry->prev = NULL;
  entry->queue = NULL;
  entry->parent = NULL;

  /* we also delete the input associated with it */
  afl_input_delete(entry->input);
  entry->input = NULL;

}

// Default implementations for the queue entry vtable functions
raw_input_t *afl_get_input_default(queue_entry_t *entry) {

  return entry->input;

}

queue_entry_t *afl_get_next_default(queue_entry_t *entry) {

  return entry->next;

}

queue_entry_t *afl_get_prev_default(queue_entry_t *entry) {

  return entry->prev;

}

queue_entry_t *afl_get_parent_default(queue_entry_t *entry) {

  return entry->parent;

}

// We implement the queue based functions now.

afl_ret_t afl_base_queue_init(base_queue_t *queue) {

  queue->save_to_files = false;
  queue->fuzz_started = false;
  queue->size = 0;
  queue->base = NULL;
  queue->current = 0;
  memset(queue->dirpath, 0, PATH_MAX);

  queue->funcs.add_to_queue = afl_add_to_queue_default;
  queue->funcs.get_queue_base = afl_get_queue_base_default;
  queue->funcs.get_size = afl_get_base_queue_size_default;
  queue->funcs.get_dirpath = afl_get_dirpath_default;
  queue->funcs.get_names_id = afl_get_names_id_default;
  queue->funcs.get_save_to_files = afl_get_save_to_files_default;
  queue->funcs.set_dirpath = afl_set_dirpath_default;
  queue->funcs.set_engine = afl_set_engine_base_queue_default;
  queue->funcs.get_next_in_queue = afl_get_next_base_queue_default;

  return AFL_RET_SUCCESS;

}

void afl_base_queue_deinit(base_queue_t *queue) {

  /*TODO: Clear the queue entries too here*/

  queue_entry_t *entry = queue->base;

  while (entry) {

    /* Grab the next entry of queue */
    queue_entry_t *next_entry = entry->next;

    /* We destroy the queue, since none of the entries have references anywhere
     * else anyways */
    afl_queue_entry_delete(entry);

    entry = next_entry;

  }

  queue->base = NULL;
  queue->current = 0;
  queue->size = 0;
  queue->fuzz_started = false;

}

/* *** Possible error cases here? *** */
afl_ret_t afl_add_to_queue_default(base_queue_t *queue, queue_entry_t *entry) {

  if (!entry->input) {

    // Never add an entry with NULL input, something's wrong!
    WARNF("Queue entry with NULL input");
    return AFL_RET_NULL_PTR;

  }

  // Before we add the entry to the queue, we call the custom mutators
  // get_next_in_queue function, so that it can gain some extra info from the
  // fuzzed queue(especially helpful in case of grammar mutator, e.g see hogfuzz
  // mutator AFL++)

  fuzz_one_t *fuzz_one = queue->engine->fuzz_one;

  if (fuzz_one) {

    size_t i;
    for (i = 0; i < fuzz_one->stages_count; ++i) {

      fuzzing_stage_t *stage = (fuzzing_stage_t *)fuzz_one->stages[i];
      size_t           j;
      for (j = 0; j < stage->mutators_count; ++j) {

        if (stage->mutators[j]->funcs.custom_queue_new_entry) {

          stage->mutators[j]->funcs.custom_queue_new_entry(stage->mutators[j],
                                                           entry);

        }

      }

    }

  }

  queue->size++;
  queue->queue_entries = afl_realloc(queue->queue_entries, queue->size * sizeof(queue_entry_t *));
  if (!queue->queue_entries) {
    return AFL_RET_ALLOC;
  }

  queue->queue_entries[queue->size] = entry;

  /* Let's save the entry to disk */
  if (queue->save_to_files && queue->dirpath && !entry->on_disk) {

    u64 input_data_checksum =
        XXH64(entry->input->bytes, entry->input->len, HASH_CONST);

    snprintf(entry->filename, FILENAME_LEN_MAX - 1, "%s/queue-%016llx",
             queue->dirpath, input_data_checksum);

    entry->input->funcs.save_to_file(entry->input, entry->filename);

    entry->on_disk = true;

  }

  return AFL_RET_SUCCESS;

}

queue_entry_t *afl_get_queue_base_default(base_queue_t *queue) {

  return queue->base;

}

size_t afl_get_base_queue_size_default(base_queue_t *queue) {

  return queue->size;

}

char *afl_get_dirpath_default(base_queue_t *queue) {

  return queue->dirpath;

}

size_t afl_get_names_id_default(base_queue_t *queue) {

  return queue->names_id;

}

bool afl_get_save_to_files_default(base_queue_t *queue) {

  return queue->save_to_files;

}

void afl_set_dirpath_default(base_queue_t *queue, char *new_dirpath) {

  if (new_dirpath) {

    strcpy(queue->dirpath, new_dirpath);

    /* Let's create the directory if it's not already created */
    struct stat dir;

    if (!((stat(queue->dirpath, &dir) == 0) && (S_ISDIR(dir.st_mode)))) {

      if (mkdir(queue->dirpath, 0777) != 0) {

        WARNF("Error creating queue directory");

      };

    }

  } else {

    memset(queue->dirpath, 0, PATH_MAX);  // We are unsetting the directory path

  }

  queue->save_to_files = true;
  // If the dirpath is empty, we make the save_to_files bool as false
  if (!queue->dirpath) { queue->save_to_files = false; }

}

void afl_set_engine_base_queue_default(base_queue_t *queue, engine_t *engine) {

  queue->engine = engine;
  if (engine) { queue->engine_id = engine->id; }

}

queue_entry_t *afl_get_next_base_queue_default(base_queue_t *queue,
                                               int           engine_id) {

  if (queue->size) {

    queue_entry_t *current = queue->queue_entries[queue->current];

    if (engine_id != queue->engine_id) {

      return current;

    }  // If some other engine grabs from the queue, don't update the queue's

    // current entry

    // If we reach the end of queue, start from beginning
    if ((queue->current + 1) == queue->size) {

      queue->current = 0;

    } else {

      queue->current++;

    }

    return current;

  } else {

    // Queue empty :(
    return NULL;

  }

}

afl_ret_t afl_feedback_queue_init(feedback_queue_t *feedback_queue,
                                  struct feedback *feedback, char *name) {

  afl_base_queue_init(&(feedback_queue->base));
  feedback_queue->feedback = feedback;

  if (feedback) { feedback->queue = feedback_queue; }

  if (!name) { name = (char *)""; }

  feedback_queue->name = name;

  return AFL_RET_SUCCESS;

}

void afl_feedback_queue_deinit(feedback_queue_t *feedback_queue) {

  feedback_queue->feedback = NULL;

  afl_base_queue_deinit(&feedback_queue->base);
  feedback_queue->name = NULL;

}

afl_ret_t afl_global_queue_init(global_queue_t *global_queue) {

  afl_base_queue_init(&(global_queue->base));

  global_queue->feedback_queues_count = 0;

  global_queue->base.funcs.set_engine = afl_set_engine_global_queue_default;

  global_queue->extra_funcs.add_feedback_queue = afl_add_feedback_queue_default;
  global_queue->extra_funcs.schedule = afl_global_schedule_default;
  global_queue->base.funcs.get_next_in_queue =
      afl_get_next_global_queue_default;

  return AFL_RET_SUCCESS;

}

void afl_global_queue_deinit(global_queue_t *global_queue) {

  /* Should we also deinit the feedback queues?? */
  size_t i;

  afl_base_queue_deinit(&global_queue->base);

  for (i = 0; i < global_queue->feedback_queues_count; ++i) {

    global_queue->feedback_queues[i] = NULL;

  }

  afl_free(global_queue->feedback_queues);
  global_queue->feedback_queues = NULL;
  global_queue->feedback_queues_count = 0;

}

afl_ret_t afl_add_feedback_queue_default(global_queue_t *  global_queue,
                                    feedback_queue_t *feedback_queue) {

  global_queue->feedback_queues_count++;
  global_queue->feedback_queues = afl_realloc(global_queue->feedback_queues, global_queue->feedback_queues_count * sizeof(feedback_queue_t *));
  if (!global_queue->feedback_queues) {
    global_queue->feedback_queues_count = 0;
    return AFL_RET_ALLOC;
  }
  global_queue->feedback_queues[global_queue->feedback_queues_count - 1] =
      feedback_queue;
  engine_t *engine = global_queue->base.engine;
  feedback_queue->base.funcs.set_engine(&feedback_queue->base, engine);
  return AFL_RET_SUCCESS;

}

queue_entry_t *afl_get_next_global_queue_default(base_queue_t *queue,
                                                 int           engine_id) {

  // This is to stop from compiler complaining about the incompatible pointer
  // type for the function ptrs. We need a better solution for this to pass the
  // scheduled_mutator rather than the mutator as an argument.
  global_queue_t *global_queue = (global_queue_t *)queue;

  int fbck_idx = global_queue->extra_funcs.schedule(global_queue);

  if (fbck_idx != -1) {

    feedback_queue_t *feedback_queue = global_queue->feedback_queues[fbck_idx];
    queue_entry_t *   next_entry = feedback_queue->base.funcs.get_next_in_queue(
        &(feedback_queue->base), engine_id);

    if (next_entry) {

      return next_entry;

    }

    else {

      return afl_get_next_base_queue_default(queue, engine_id);

    }

  }

  else {

    // We don't have any more entries feedback queue, so base queue it is.
    return afl_get_next_base_queue_default(queue, engine_id);

  }

}

int afl_global_schedule_default(global_queue_t *queue) {

  return afl_rand_below(&queue->base.engine->rnd, queue->feedback_queues_count);

}

void afl_set_engine_global_queue_default(base_queue_t *global_queue_base,
                                         engine_t *    engine) {

  size_t          i;
  global_queue_t *global_queue = (global_queue_t *)global_queue_base;

  // First add engine to the global queue itself

  afl_set_engine_base_queue_default(&global_queue->base, engine);
  // Set engine's queue to the global queue

  if (engine) { engine->global_queue = global_queue; }

  for (i = 0; i < global_queue->feedback_queues_count; ++i) {

    // Set this engine to every feedback queue in global queue
    global_queue->feedback_queues[i]->base.funcs.set_engine(
        &(global_queue->feedback_queues[i]->base), engine);

  }

}

