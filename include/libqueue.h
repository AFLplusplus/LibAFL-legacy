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

#ifndef QUEUE_FILE_INCLUDED
#define QUEUE_FILE_INCLUDED

#include "libinput.h"
#include "list.h"
#include <stdbool.h>

/*
This is the generic interface implementation for the queue and queue entries.
We've tried to keep it generic and yet including, but if you want to extend the
queue/entry, simply "inherit" this struct by including it in your custom struct
and keeping it as the first member of your struct.
*/

struct base_queue;
struct feedback;

typedef struct queue_entry {

  raw_input_t *       input;
  bool                on_disk;
  u8 *                filename;
  struct base_queue * queue;
  struct queue_entry *next;
  struct queue_entry *prev;
  struct queue_entry *parent;

  list_t children;

  struct queue_entry_functions *functions;

  /* TODO: Add feedback_meta_data member after feedback completion */

} queue_entry_t;

struct queue_entry_functions {

  raw_input_t *(*get_input)(queue_entry_t *);
  bool (*is_on_disk)(queue_entry_t *);
  queue_entry_t *(*get_next)(queue_entry_t *);
  queue_entry_t *(*get_prev)(queue_entry_t *);
  queue_entry_t *(*get_parent)(queue_entry_t *);
  queue_entry_t *(*get_child)(
      queue_entry_t *,
      size_t);     /*TODO: Still need to add a base implementation for this.*/

};

void afl_queue_entry_init(queue_entry_t *);
void afl_queue_entry_deinit(queue_entry_t *);

static inline queue_entry_t *AFL_QUEUE_ENTRY_INIT(queue_entry_t *queue_entry) {

  queue_entry_t *new_queue_entry = NULL;

  if (queue_entry)
    afl_queue_entry_init(queue_entry);

  else {

    new_queue_entry = ck_alloc(sizeof(queue_entry_t));
    afl_queue_entry_init(new_queue_entry);

  }

  return new_queue_entry;

}

#define AFL_QUEUE_ENTRY_DEINIT(queue_entry) afl_queue_entry_deinit(queue_entry);

// Default implementations for the functions for queue_entry vtable
raw_input_t *  _get_input_(queue_entry_t *entry);
queue_entry_t *_get_next_(queue_entry_t *entry);
queue_entry_t *_get_prev_(queue_entry_t *entry);
queue_entry_t *_get_parent_(queue_entry_t *entry);

typedef struct base_queue {

  queue_entry_t *base;
  size_t         size;
  u8 *           dirpath;
  size_t         names_id;
  bool           save_to_files;

  struct base_queue_functions *functions;

  /* TODO: Still need to add shared_mutex (after multithreading), map of
   * engine:queue_entry */

} base_queue_t;

struct base_queue_functions {

  void (*add_to_queue)(base_queue_t *, queue_entry_t *);
  void (*remove_from_queue)(base_queue_t *);

  queue_entry_t *(*get)(base_queue_t *);
  queue_entry_t *(*get_next_in_queue)(base_queue_t *);
  queue_entry_t *(*get_queue_base)(base_queue_t *);
  size_t (*get_size)(base_queue_t *);
  u8 *(*get_dirpath)(base_queue_t *);
  size_t (*get_names_id)(base_queue_t *);
  bool (*get_save_to_files)(base_queue_t *);

  void (*set_directory)(base_queue_t *, u8 *);

};

/* TODO: Add the base  */

void afl_base_queue_init(base_queue_t *);
void afl_base_queue_deinit(base_queue_t *);

void           _add_to_queue_(base_queue_t *, queue_entry_t *);
queue_entry_t *_get_queue_base_(base_queue_t *);
size_t         _get_base_queue_size_(base_queue_t *);
u8 *           _get_dirpath_(base_queue_t *);
size_t         _get_names_id_(base_queue_t *);
bool           _get_save_to_files_(base_queue_t *);
void           _set_directory_(base_queue_t *, u8 *);

static inline base_queue_t *AFL_BASE_QUEUE_INIT(base_queue_t *base_queue) {

  base_queue_t *new_base_queue = NULL;

  if (base_queue)
    afl_base_queue_init(base_queue);

  else {

    new_base_queue = ck_alloc(sizeof(base_queue_t));
    afl_base_queue_init(new_base_queue);

  }

  return new_base_queue;

}

#define AFL_BASE_QUEUE_DEINIT(base_queue) afl_base_queue_deinit(base_queue);

typedef struct feedback_queue {

  base_queue_t super;  // Inheritence from base queue

  struct feedback *feedback;
  u8 *             name;

} feedback_queue_t;

feedback_queue_t *afl_feedback_queue_init(
    struct feedback *, u8 *);  // "constructor" for the above feedback queue

void afl_feedback_queue_deinit(feedback_queue_t *);

typedef struct global_queue {

  base_queue_t super;
  list_t feedback_queues;  // One global queue can have multiple feedback queues

  size_t feedback_queues_num;

  struct global_queue_functions *extra_functions;
  /*TODO: Add a map of Engine:feedback_queue
    UPDATE: Engine will have a ptr to current feedback queue rather than this*/

} global_queue_t;

struct global_queue_functions {

  int (*schedule)(global_queue_t *);
  void (*add_feedback_queue)(global_queue_t *, feedback_queue_t *);

};

// Default implementations of global queue vtable functions
void _add_feedback_queue_(global_queue_t *, feedback_queue_t *);
/* TODO: ADD defualt implementation for the schedule function based on random.
 */

global_queue_t *afl_global_queue_init();
void            afl_global_queue_deinit(global_queue_t *);

#endif

