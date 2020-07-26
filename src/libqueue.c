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

// We start with the implementation of queue_entry functions here.
void _afl_queue_entry_init_(queue_entry_t *entry) {

  entry->funcs.get_input = get_input_default;
  entry->funcs.get_next = get_next_default;
  entry->funcs.get_prev = get_prev_default;
  entry->funcs.get_parent = get_parent_default;

}

void afl_queue_entry_deinit(queue_entry_t *entry) {

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

}

void afl_base_queue_deinit(base_queue_t *queue) {

  free(queue);

  /*TODO: Clear the queue entries too here*/

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

u8 *get_dirpath_default(base_queue_t *queue) {

  return queue->dirpath;

}

size_t get_names_id_default(base_queue_t *queue) {

  return queue->names_id;

}

bool get_save_to_files_default(base_queue_t *queue) {

  return queue->save_to_files;

}

void set_directory_default(base_queue_t *queue, u8 *new_dirpath) {

  if (!new_dirpath)
    queue->dirpath = (u8 *)"";  // We are unsetting the directory path
  queue->dirpath = new_dirpath;

  queue->save_to_files = true;
  // If the dirpath is empty, we make the save_to_files bool as false
  if (!strcmp((char *)queue->dirpath, "")) queue->save_to_files = false;

}

feedback_queue_t *afl_feedback_queue_init(struct feedback *feedback, u8 *name) {

  feedback_queue_t *fbck_queue = ck_alloc(sizeof(feedback_queue_t));

  afl_base_queue_init(&(fbck_queue->super));
  fbck_queue->feedback = feedback;

  if (!name) name = (u8 *)"";

  fbck_queue->name = name;

  return fbck_queue;

}

void afl_feedback_queue_deinit(feedback_queue_t *feedback) {

  ck_free(feedback->name);

  ck_free(feedback);

}

void _afl_global_queue_init_(global_queue_t *global_queue) {

  afl_base_queue_init(&(global_queue->super));

  global_queue->extra_funcs.add_feedback_queue = add_feedback_queue_default;
  global_queue->extra_funcs.schedule = global_schedule_default;

}

void afl_global_queue_deinit(global_queue_t *queue) {

  if (queue->feedback_queues_num)
    LIST_FOREACH_CLEAR(&(queue->feedback_queues), feedback_queue_t,
                       { afl_feedback_queue_deinit(el); });

  free(queue);

}

void add_feedback_queue_default(global_queue_t *  global_queue,
                                feedback_queue_t *fbck_queue) {

  list_append(&(global_queue->feedback_queues), fbck_queue);
  global_queue->feedback_queues_num++;

}

int global_schedule_default(global_queue_t *queue) {

  /* TODO: Implementation */
  return 0;

}

