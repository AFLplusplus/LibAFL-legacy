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

#define UNUSED(x) (void)(x)

// We start with the implementation of queue_entry functions here.
void _afl_queue_entry_init_(queue_entry_t *entry, raw_input_t *input) {

  entry->input = input;

  entry->funcs.get_input = get_input_default;
  entry->funcs.get_next = get_next_default;
  entry->funcs.get_prev = get_prev_default;
  entry->funcs.get_parent = get_parent_default;

}

void afl_queue_entry_deinit(queue_entry_t *entry) {

  /* We remove the element from the linked-list */

  if (entry->next) { entry->next->prev = entry->prev; }

  if (entry->prev) { entry->prev->next = entry->next; }

  /* Clear all the children entries */
  if (entry->children_num) {

    LIST_FOREACH_CLEAR(&(entry->children), queue_entry_t,
                       { AFL_QUEUE_ENTRY_DEINIT(el); })

  }

  /* we also clear the input associated with it */
  AFL_INPUT_DEINIT(entry->input);

  free(entry);

}

// Default implementations for the queue entry vtable functions
raw_input_t *get_input_default(queue_entry_t *entry) {

  if (entry->on_disk) {

    raw_input_t *load = entry->input->funcs.empty(entry->input);

    if (!load->funcs.load_from_file(load, entry->filename))
      return load;
    else
      return NULL;

  }

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

void _afl_base_queue_init_(base_queue_t *queue) {

  queue->save_to_files = false;

  queue->funcs.add_to_queue = add_to_queue_default;
  queue->funcs.get_queue_base = get_queue_base_default;
  queue->funcs.get_size = get_base_queue_size_default;
  queue->funcs.get_dirpath = get_dirpath_default;
  queue->funcs.get_names_id = get_names_id_default;
  queue->funcs.get_save_to_files = get_save_to_files_default;
  queue->funcs.set_directory = set_directory_default;
  queue->funcs.get_next_in_queue = get_next_base_queue_default;

}

void afl_base_queue_deinit(base_queue_t *queue) {

  /*TODO: Clear the queue entries too here*/

  queue_entry_t *entry = queue->base;

  while (entry) {

    /* Grab the next entry of queue */
    queue_entry_t *next_entry = entry->next;

    AFL_QUEUE_ENTRY_DEINIT(entry);

    entry = next_entry;

  }

  free(queue);

}

/* *** Possible error cases here? *** */
void add_to_queue_default(base_queue_t *queue, queue_entry_t *entry) {

  entry->next = queue->base;
  /*TODO: Need to add mutex stuff here. */
  if (queue->base) queue->base->prev = entry;

  queue->base = entry;
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
  if (!strcmp((char *)queue->dirpath, "")) queue->save_to_files = false;

}

queue_entry_t *get_next_base_queue_default(base_queue_t *queue) {

  if (queue->current) {

    queue_entry_t *current = queue->current;
    queue->current = current->next;

    return current;

  } else if (queue->base) {

    // We've just started fuzzing, we start from the base of the queue
    queue->current = queue->base->next;
    return queue->base;

  } else {

    // Empty queue :(
    return NULL;

  }

}

feedback_queue_t *_afl_feedback_queue_init_(feedback_queue_t *feedback_queue,
                                            struct feedback * feedback,
                                            char *            name) {

  afl_base_queue_init(&(feedback_queue->base));
  feedback_queue->feedback = feedback;

  if (!name) name = (char *)"";

  feedback_queue->name = name;

  return feedback_queue;

}

void afl_feedback_queue_deinit(feedback_queue_t *feedback_queue) {

  if (feedback_queue->feedback) {

    AFL_FEEDBACK_DEINIT(feedback_queue->feedback);

  }

  AFL_BASE_QUEUE_DEINIT((base_queue_t *)feedback_queue);

}

void _afl_global_queue_init_(global_queue_t *global_queue) {

  afl_base_queue_init(&(global_queue->base));

  global_queue->extra_funcs.add_feedback_queue = add_feedback_queue_default;
  global_queue->extra_funcs.schedule = global_schedule_default;
  global_queue->base.funcs.get_next_in_queue = get_next_global_queue_default;

}

void afl_global_queue_deinit(global_queue_t *queue) {

  if (queue->feedback_queues_num) {

    for (size_t i = 0; i < queue->feedback_queues_num; ++i) {

      AFL_FEEDBACK_QUEUE_DEINIT(queue->feedback_queues[i]);

    }

  }

  free(queue);

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
    return feedback_queue->base.funcs.get_next_in_queue(
        &(feedback_queue->base));

  }

  else {

    // We don't have any feedback queue, so base queue it is.
    return get_next_base_queue_default(queue);

  }

}

int global_schedule_default(global_queue_t *queue) {

  return rand_below(queue->feedback_queues_num);

}

