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

#ifndef LIBQUEUE_H
#define LIBQUEUE_H

#include <stdbool.h>
#include <limits.h>

#include "input.h"
#include "list.h"
#include "afl-shmem.h"

/*
This is the generic interface implementation for the queue and queue entries.
We've tried to keep it generic and yet including, but if you want to extend the
queue/entry, simply "inherit" this struct by including it in your custom struct
and keeping it as the first member of your struct.
*/

struct base_queue;
struct feedback;

typedef struct queue_entry queue_entry_t;

struct queue_entry_functions {

  raw_input_t *(*get_input)(queue_entry_t *);
  bool (*is_on_disk)(queue_entry_t *);
  queue_entry_t *(*get_next)(queue_entry_t *);
  queue_entry_t *(*get_prev)(queue_entry_t *);
  queue_entry_t *(*get_parent)(queue_entry_t *);
  queue_entry_t *(*get_child)(queue_entry_t *, size_t);    /*TODO: Still need to add a base implementation for this.*/

};

struct queue_entry {

  raw_input_t *       input;
  bool                on_disk;
  char                filename[FILENAME_LEN_MAX];
  struct base_queue * queue;
  struct queue_entry *next;
  struct queue_entry *prev;
  struct queue_entry *parent;

  struct queue_entry_functions funcs;

};

afl_ret_t afl_queue_entry_init(queue_entry_t *, raw_input_t *);
void      afl_queue_entry_deinit(queue_entry_t *);

static inline queue_entry_t *afl_queue_entry_create(raw_input_t *input) {

  queue_entry_t *queue_entry = calloc(1, sizeof(queue_entry_t));
  if (!queue_entry) { return NULL; }
  if (afl_queue_entry_init(queue_entry, input) != AFL_RET_SUCCESS) {

    free(queue_entry);
    return NULL;

  }

  return queue_entry;

}

static inline void afl_queue_entry_delete(queue_entry_t *queue_entry) {

  afl_queue_entry_deinit(queue_entry);
  free(queue_entry);

}

// Default implementations for the functions for queue_entry vtable
raw_input_t *  afl_get_input_default(queue_entry_t *entry);
queue_entry_t *afl_get_next_default(queue_entry_t *entry);
queue_entry_t *afl_get_prev_default(queue_entry_t *entry);
queue_entry_t *afl_get_parent_default(queue_entry_t *entry);

typedef struct base_queue base_queue_t;

struct base_queue_functions {

  afl_ret_t (*add_to_queue)(base_queue_t *, queue_entry_t *);
  void (*remove_from_queue)(base_queue_t *);

  queue_entry_t *(*get)(base_queue_t *);
  queue_entry_t *(*get_next_in_queue)(base_queue_t *, int);
  queue_entry_t *(*get_queue_base)(base_queue_t *);
  size_t (*get_size)(base_queue_t *);
  char *(*get_dirpath)(base_queue_t *);
  size_t (*get_names_id)(base_queue_t *);
  bool (*get_save_to_files)(base_queue_t *);

  void (*set_dirpath)(base_queue_t *, char *);
  void (*set_engine)(base_queue_t *, engine_t *);

};

struct base_queue {

  queue_entry_t **            queue_entries;
  queue_entry_t *             base;
  u64                         current;
  int                         engine_id;
  engine_t *                  engine;
  queue_entry_t *             end;
  size_t                      size;
  char                        dirpath[PATH_MAX];
  size_t                      names_id;
  bool                        save_to_files;
  bool                        fuzz_started;
  struct base_queue_functions funcs;

};

/* TODO: Add the base  */

afl_ret_t afl_base_queue_init(base_queue_t *);
void      afl_base_queue_deinit(base_queue_t *);

afl_ret_t      afl_add_to_queue_default(base_queue_t *, queue_entry_t *);
queue_entry_t *afl_get_queue_base_default(base_queue_t *);
size_t         afl_get_base_queue_size_default(base_queue_t *);
char *         afl_get_dirpath_default(base_queue_t *);
size_t         afl_get_names_id_default(base_queue_t *);
bool           afl_get_save_to_files_default(base_queue_t *);
void           afl_set_dirpath_default(base_queue_t *, char *);
void           afl_set_engine_base_queue_default(base_queue_t *, engine_t *);
queue_entry_t *afl_get_next_base_queue_default(base_queue_t *queue, int engine_id);

static inline base_queue_t *afl_base_queue_create() {

  base_queue_t *base_queue = calloc(1, sizeof(base_queue_t));
  if (!base_queue) { return NULL; }

  if (afl_base_queue_init(base_queue) != AFL_RET_SUCCESS) {

    free(base_queue);
    return NULL;

  }

  return base_queue;

}

static inline void afl_base_queue_delete(base_queue_t *base_queue) {

  afl_base_queue_deinit(base_queue);

  free(base_queue);

}

typedef struct feedback_queue {

  base_queue_t base;  // Inheritence from base queue

  struct feedback *feedback;
  char *           name;

} feedback_queue_t;

afl_ret_t afl_feedback_queue_init(feedback_queue_t *, struct feedback *,
                                  char *);  // "constructor" for the above feedback queue

void afl_feedback_queue_deinit(feedback_queue_t *);

static inline feedback_queue_t *afl_feedback_queue_create(struct feedback *feedback, char *name) {

  feedback_queue_t *feedback_queue = calloc(1, sizeof(feedback_queue_t));
  if (!feedback_queue) { return NULL; }

  if (afl_feedback_queue_init(feedback_queue, feedback, name) != AFL_RET_SUCCESS) {

    free(feedback_queue);
    return NULL;

  }

  return feedback_queue;

}

static inline void afl_feedback_queue_delete(feedback_queue_t *feedback_queue) {

  afl_feedback_queue_deinit(feedback_queue);

  free(feedback_queue);

}

typedef struct global_queue global_queue_t;

struct global_queue_functions {

  int (*schedule)(global_queue_t *);
  afl_ret_t (*add_feedback_queue)(global_queue_t *, feedback_queue_t *);

};

struct global_queue {

  base_queue_t       base;
  feedback_queue_t **feedback_queues;  // One global queue can have
                                       // multiple feedback queues

  size_t feedback_queues_count;

  struct global_queue_functions extra_funcs;
  /*TODO: Add a map of Engine:feedback_queue
    UPDATE: Engine will have a ptr to current feedback queue rather than this*/

};

// Default implementations of global queue vtable functions
afl_ret_t afl_add_feedback_queue_default(global_queue_t *, feedback_queue_t *);
int       afl_global_schedule_default(global_queue_t *);
void      afl_set_engine_global_queue_default(base_queue_t *, engine_t *);

// Function to get next entry from queue, we override the base_queue
// implementation
queue_entry_t *afl_get_next_global_queue_default(base_queue_t *queue, int engine_id);

/* TODO: ADD defualt implementation for the schedule function based on random.
 */

afl_ret_t afl_global_queue_init(global_queue_t *);
void      afl_global_queue_deinit(global_queue_t *);

static inline global_queue_t *afl_global_queue_create() {

  global_queue_t *global_queue = calloc(1, sizeof(global_queue_t));
  if (!global_queue) { return NULL; }

  if (afl_global_queue_init(global_queue) != AFL_RET_SUCCESS) {

    free(global_queue);
    return NULL;

  }

  return global_queue;

}

static inline void afl_global_queue_delete(global_queue_t *global_queue) {

  afl_global_queue_deinit(global_queue);

  free(global_queue);

}

#endif

