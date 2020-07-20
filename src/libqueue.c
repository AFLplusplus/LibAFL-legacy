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
void afl_queue_entry_init(queue_entry_t *entry) {

  entry->functions = ck_alloc(sizeof(struct queue_entry_functions));

  entry->functions->get_input = _get_input_;
  entry->functions->get_next = _get_next_;
  entry->functions->get_prev = _get_prev_;
  entry->functions->get_parent = _get_parent_;

}

void afl_queue_entry_deinit(queue_entry_t *entry) {

  ck_free(entry->functions);
  ck_free(entry);

}

// Default implementations for the queue entry vtable functions
raw_input_t *_get_input_(queue_entry_t *entry) {

  if (entry->on_disk) {

    raw_input_t *load = entry->input->functions->empty(entry->input);

    if (!load->functions->load_from_file(load, entry->filename))
      return load;
    else
      return NULL;

  }

  return entry->input;

}

queue_entry_t *_get_next_(queue_entry_t *entry) {

  return entry->next;

}

queue_entry_t *_get_prev_(queue_entry_t *entry) {

  return entry->prev;

}

queue_entry_t *_get_parent_(queue_entry_t *entry) {

  return entry->parent;

}

// We implement the queue based functions now.

void afl_base_queue_init(base_queue_t *queue) {

  queue->functions = ck_alloc(sizeof(struct base_queue_functions));

  queue->save_to_files = false;

  queue->functions->add_to_queue = _add_to_queue_;
  queue->functions->get_queue_base = _get_queue_base_;
  queue->functions->get_size = _get_base_queue_size_;
  queue->functions->get_dirpath = _get_dirpath_;
  queue->functions->get_names_id = _get_names_id_;
  queue->functions->get_save_to_files = _get_save_to_files_;
  queue->functions->set_directory = _set_directory_;

}

void afl_base_queue_deinit(base_queue_t *queue) {

  ck_free(queue->functions);
  ck_free(queue);

  /*TODO: Clear the queue entries too here*/

}

/* *** Possible error cases here? *** */
void _add_to_queue_(base_queue_t *queue, queue_entry_t *entry) {

  entry->next = queue->base;
  /*TODO: Need to add mutex stuff here. */
  if (queue->base) queue->base->prev = entry;

  queue->base = entry;
  queue->size++;

}

queue_entry_t *_get_queue_base_(base_queue_t *queue) {

  return queue->base;

}

size_t _get_base_queue_size_(base_queue_t *queue) {

  return queue->size;

}

u8 *_get_dirpath_(base_queue_t *queue) {

  return queue->dirpath;

}

size_t _get_names_id_(base_queue_t *queue) {

  return queue->names_id;

}

bool _get_save_to_files_(base_queue_t *queue) {

  return queue->save_to_files;

}

void _set_directory_(base_queue_t *queue, u8 *new_dirpath) {

  if (!new_dirpath)
    queue->dirpath = (u8 *)"";  // We are unsetting the directory path
  queue->dirpath = new_dirpath;

  queue->save_to_files = true;
  // If the dirpath is empty, we make the save_to_files bool as false
  if (!strcmp((char *)queue->dirpath, "")) queue->save_to_files = false;

}

feedback_queue_t *afl_feedback_queue_init(struct feedback *feedback, u8 *name) {

  feedback_queue_t *fbck_queue = ck_alloc(sizeof(feedback_queue_t));

  AFL_BASE_QUEUE_INIT(&(fbck_queue->super));
  fbck_queue->feedback = feedback;

  if (!name) name = (u8 *)"";

  fbck_queue->name = name;

  return fbck_queue;

}

void afl_feedback_queue_deinit(feedback_queue_t *feedback) {

  ck_free(feedback->name);

  ck_free(feedback);

}

global_queue_t *afl_global_queue_init() {

  global_queue_t *global_queue = ck_alloc(sizeof(global_queue_t));

  AFL_BASE_QUEUE_INIT(&(global_queue->super));

  global_queue->extra_functions =
      ck_alloc(sizeof(struct global_queue_functions));

  global_queue->extra_functions->add_feedback_queue = _add_feedback_queue_;

  return global_queue;

}

void afl_global_queue_deinit(global_queue_t *queue) {

  if (queue->feedback_queues_num)
    LIST_FOREACH_CLEAR(&(queue->feedback_queues), feedback_queue_t,
                       { afl_feedback_queue_deinit(el); });

  ck_free(queue->extra_functions);
  ck_free(queue);

}

void _add_feedback_queue_(global_queue_t *  global_queue,
                          feedback_queue_t *fbck_queue) {

  list_append(&(global_queue->feedback_queues), fbck_queue);
  global_queue->feedback_queues_num++;

}

