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

#include "libqueue.h"
#include "libfeedback.h"
#include "libengine.h"

// We start with the implementation of queue_entry functions here.
afl_ret_t afl_queue_entry_init(queue_entry_t *entry, raw_input_t *input) {

  entry->input = input;

  entry->funcs.get_input = get_input_default;
  entry->funcs.get_next = get_next_default;
  entry->funcs.get_prev = get_prev_default;
  entry->funcs.get_parent = get_parent_default;

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
  entry->filename = NULL;

  /* Clear all the children entries?? */
  if (entry->children_num) {

    LIST_FOREACH_CLEAR(&(entry->children), queue_entry_t,
                       { afl_queue_entry_deinit(el); })

  }

  /* we also delete the input associated with it */
  afl_input_delete(entry->input);
  entry->input = NULL;

}

// Default implementations for the queue entry vtable functions
raw_input_t *get_input_default(queue_entry_t *entry) {

  return entry->input;

}

queue_entry_t *get_next_default(queue_entry_t *entry) {

  return entry->next;

}

queue_entry_t *get_prev_default(queue_entry_t *entry) {

  return entry->prev;

}

queue_entry_t *get_parent_default(queue_entry_t *entry) {

  return entry->parent;

}

// We implement the queue based functions now.

afl_ret_t afl_base_queue_init(base_queue_t *queue) {

  queue->save_to_files = false;
  queue->dirpath = NULL;
  queue->fuzz_started = false;
  queue->size = 0;
  queue->base = NULL;
  queue->current = NULL;

  queue->funcs.add_to_queue = add_to_queue_default;
  queue->funcs.get_queue_base = get_queue_base_default;
  queue->funcs.get_size = get_base_queue_size_default;
  queue->funcs.get_dirpath = get_dirpath_default;
  queue->funcs.get_names_id = get_names_id_default;
  queue->funcs.get_save_to_files = get_save_to_files_default;
  queue->funcs.set_directory = set_directory_default;
  queue->funcs.get_next_in_queue = get_next_base_queue_default;

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
  queue->current = NULL;
  queue->size = 0;
  queue->dirpath = NULL;
  queue->fuzz_started = false;

}

/* *** Possible error cases here? *** */
void add_to_queue_default(base_queue_t *queue, queue_entry_t *entry) {

  /* Add entry to the end of the queue */

  if (!queue->size) {
    queue->base = queue->end = entry;
  } else {
    queue->end->next = entry;
    entry->prev = queue->end;
    queue->end = entry;
  }
  /*TODO: Need to add mutex stuff here. */

  queue->size++;

}

queue_entry_t *get_queue_base_default(base_queue_t *queue) {

  return queue->base;

}

size_t get_base_queue_size_default(base_queue_t *queue) {

  return queue->size;

}

char *get_dirpath_default(base_queue_t *queue) {

  return queue->dirpath;

}

size_t get_names_id_default(base_queue_t *queue) {

  return queue->names_id;

}

bool get_save_to_files_default(base_queue_t *queue) {

  return queue->save_to_files;

}

void set_directory_default(base_queue_t *queue, char *new_dirpath) {

  if (new_dirpath) {

    queue->dirpath = new_dirpath;

  } else {

    queue->dirpath = (char *)"";  // We are unsetting the directory path

  }

  queue->save_to_files = true;
  // If the dirpath is empty, we make the save_to_files bool as false
  if (!strcmp(queue->dirpath, "")) queue->save_to_files = false;

}

queue_entry_t *get_next_base_queue_default(base_queue_t *queue) {

  if (queue->current) {

    queue_entry_t *current = queue->current;
    queue->current = current->next;

    queue->fuzz_started = true;

    return current;

  } else if (!queue->current && queue->base && !(queue->fuzz_started)) {

    // We've just started fuzzing, we start from the base of the queue
    queue->current = queue->base->next;
    queue->fuzz_started = true;
    return queue->base;

  } else {

    // Empty queue :(
    return NULL;

  }

}

afl_ret_t afl_feedback_queue_init(feedback_queue_t *feedback_queue,
                                  struct feedback *feedback, char *name) {

  afl_base_queue_init(&(feedback_queue->base));
  feedback_queue->feedback = feedback;

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

  global_queue->feedback_queues_num = 0;

  global_queue->extra_funcs.add_feedback_queue = add_feedback_queue_default;
  global_queue->extra_funcs.schedule = global_schedule_default;
  global_queue->base.funcs.get_next_in_queue = get_next_global_queue_default;

  return AFL_RET_SUCCESS;

}

void afl_global_queue_deinit(global_queue_t *global_queue) {

  /* Should we also deinit the feedback queues?? */

  afl_base_queue_deinit(&global_queue->base);

  for (size_t i = 0; i < global_queue->feedback_queues_num; ++i) {

    global_queue->feedback_queues[i] = NULL;

  }

  global_queue->feedback_queues_num = 0;

}

void add_feedback_queue_default(global_queue_t *  global_queue,
                                feedback_queue_t *feedback_queue) {

  global_queue->feedback_queues[global_queue->feedback_queues_num] =
      feedback_queue;
  global_queue->feedback_queues_num++;

}

queue_entry_t *get_next_global_queue_default(base_queue_t *queue) {

  // This is to stop from compiler complaining about the incompatible pointer
  // type for the function ptrs. We need a better solution for this to pass the
  // scheduled_mutator rather than the mutator as an argument.
  global_queue_t *global_queue = (global_queue_t *)queue;

  int fbck_idx = global_queue->extra_funcs.schedule(global_queue);

  if (fbck_idx != -1) {

    feedback_queue_t *feedback_queue = global_queue->feedback_queues[fbck_idx];
    queue_entry_t *   next_entry =
        feedback_queue->base.funcs.get_next_in_queue(&(feedback_queue->base));

    if (next_entry) {

      return next_entry;

    }

    else {

      return get_next_base_queue_default(queue);

    }

  }

  else {

    // We don't have any more entries feedback queue, so base queue it is.
    return get_next_base_queue_default(queue);

  }

}

int global_schedule_default(global_queue_t *queue) {

  return rand_below(queue->feedback_queues_num);

}

