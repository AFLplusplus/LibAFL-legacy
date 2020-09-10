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
#include "shmem.h"

/*
This is the generic interface implementation for the queue and queue entries.
We've tried to keep it generic and yet including, but if you want to extend the
queue/entry, simply "inherit" this struct by including it in your custom struct
and keeping it as the first member of your struct.
*/

struct afl_queue;
struct afl_feedback;

typedef struct afl_queueentry afl_queueentry_t;

struct afl_queueentry_funcs {

  afl_input_t *(*get_input)(afl_queueentry_t *);
  bool (*is_on_disk)(afl_queueentry_t *);
  afl_queueentry_t *(*get_next)(afl_queueentry_t *);
  afl_queueentry_t *(*get_prev)(afl_queueentry_t *);
  afl_queueentry_t *(*get_parent)(afl_queueentry_t *);
  afl_queueentry_t *(*get_child)(afl_queueentry_t *,
                                  size_t);                 /*TODO: Still need to add a base implementation for this.*/

};

struct afl_queueentry {

  afl_input_t *   input;
  bool                on_disk;
  char                filename[FILENAME_LEN_MAX];
  struct afl_queue * queue;
  struct afl_queueentry *next;
  struct afl_queueentry *prev;
  struct afl_queueentry *parent;

  struct afl_queueentry_funcs funcs;

};

afl_ret_t afl_queueentry_init(afl_queueentry_t *, afl_input_t *);
void      afl_queueentry_deinit(afl_queueentry_t *);

static inline afl_queueentry_t *afl_queueentry_new(afl_input_t *input) {

  afl_queueentry_t *queue_entry = calloc(1, sizeof(afl_queueentry_t));
  if (!queue_entry) { return NULL; }
  if (afl_queueentry_init(queue_entry, input) != AFL_RET_SUCCESS) {

    free(queue_entry);
    return NULL;

  }

  return queue_entry;

}

static inline void afl_queueentry_delete(afl_queueentry_t *queue_entry) {

  afl_queueentry_deinit(queue_entry);
  free(queue_entry);

}

// Default implementations for the functions for queue_entry vtable
afl_input_t *  afl_get_input_default(afl_queueentry_t *entry);
afl_queueentry_t *afl_get_next_default(afl_queueentry_t *entry);
afl_queueentry_t *afl_get_prev_default(afl_queueentry_t *entry);
afl_queueentry_t *afl_get_parent_default(afl_queueentry_t *entry);

typedef struct afl_queue afl_base_queue_t;

struct base_queue_functions {

  afl_ret_t (*add_to_queue)(afl_base_queue_t *, afl_queueentry_t *);
  void (*remove_from_queue)(afl_base_queue_t *);

  afl_queueentry_t *(*get)(afl_base_queue_t *);
  afl_queueentry_t *(*get_next_in_queue)(afl_base_queue_t *, int);
  afl_queueentry_t *(*get_queue_base)(afl_base_queue_t *);
  size_t (*get_size)(afl_base_queue_t *);
  char *(*get_dirpath)(afl_base_queue_t *);
  size_t (*get_names_id)(afl_base_queue_t *);
  bool (*get_save_to_files)(afl_base_queue_t *);

  void (*set_dirpath)(afl_base_queue_t *, char *);
  void (*set_engine)(afl_base_queue_t *, afl_engine_t *);

};

struct afl_queue {

  afl_queueentry_t **        queue_entries;
  afl_queueentry_t *         base;
  u64                         current;
  int                         engine_id;
  afl_engine_t *              engine;
  afl_queueentry_t *         end;
  size_t                      size;
  char                        dirpath[PATH_MAX];
  size_t                      names_id;
  bool                        save_to_files;
  bool                        fuzz_started;
  struct base_queue_functions funcs;

};

/* TODO: Add the base  */

afl_ret_t afl_base_queue_init(afl_base_queue_t *);
void      afl_base_queue_deinit(afl_base_queue_t *);

afl_ret_t      afl_add_to_queue_default(afl_base_queue_t *, afl_queueentry_t *);
afl_queueentry_t *afl_get_queue_base_default(afl_base_queue_t *);
size_t         afl_get_base_queue_size_default(afl_base_queue_t *);
char *         afl_get_dirpath_default(afl_base_queue_t *);
size_t         afl_get_names_id_default(afl_base_queue_t *);
bool           afl_get_save_to_files_default(afl_base_queue_t *);
void           afl_set_dirpath_default(afl_base_queue_t *, char *);
void           afl_set_engine_base_queue_default(afl_base_queue_t *, afl_engine_t *);
afl_queueentry_t *afl_get_next_base_queue_default(afl_base_queue_t *queue, int engine_id);

static inline afl_base_queue_t *afl_base_queue_new() {

  afl_base_queue_t *base_queue = calloc(1, sizeof(afl_base_queue_t));
  if (!base_queue) { return NULL; }

  if (afl_base_queue_init(base_queue) != AFL_RET_SUCCESS) {

    free(base_queue);
    return NULL;

  }

  return base_queue;

}

static inline void afl_base_queue_delete(afl_base_queue_t *base_queue) {

  afl_base_queue_deinit(base_queue);

  free(base_queue);

}

typedef struct afl_feedback_queue {

  afl_base_queue_t base;  // Inheritence from base queue

  struct afl_feedback *feedback;
  char *           name;

} afl_queue_feedback_t;

afl_ret_t afl_feedback_queue_init(afl_queue_feedback_t *, struct afl_feedback *,
                                  char *);  // "constructor" for the above feedback queue

void afl_feedback_queue_deinit(afl_queue_feedback_t *);

static inline afl_queue_feedback_t *afl_feedback_queue_new(struct afl_feedback *feedback, char *name) {

  afl_queue_feedback_t *feedback_queue = calloc(1, sizeof(afl_queue_feedback_t));
  if (!feedback_queue) { return NULL; }

  if (afl_feedback_queue_init(feedback_queue, feedback, name) != AFL_RET_SUCCESS) {

    free(feedback_queue);
    return NULL;

  }

  return feedback_queue;

}

static inline void afl_feedback_queue_delete(afl_queue_feedback_t *feedback_queue) {

  afl_feedback_queue_deinit(feedback_queue);

  free(feedback_queue);

}

typedef struct afl_queue_global afl_queue_global_t;

struct afl_queue_global_funcs {

  int (*schedule)(afl_queue_global_t *);
  afl_ret_t (*add_feedback_queue)(afl_queue_global_t *, afl_queue_feedback_t *);

};

struct afl_queue_global {

  afl_base_queue_t       base;
  afl_queue_feedback_t **feedback_queues;  // One global queue can have
                                           // multiple feedback queues

  size_t feedback_queues_count;

  struct afl_queue_global_funcs extra_funcs;
  /*TODO: Add a map of Engine:feedback_queue
    UPDATE: Engine will have a ptr to current feedback queue rather than this*/

};

// Default implementations of global queue vtable functions
afl_ret_t afl_add_feedback_queue_default(afl_queue_global_t *, afl_queue_feedback_t *);
int       afl_global_schedule_default(afl_queue_global_t *);
void      afl_set_engine_global_queue_default(afl_base_queue_t *, afl_engine_t *);

// Function to get next entry from queue, we override the base_queue
// implementation
afl_queueentry_t *afl_get_next_global_queue_default(afl_base_queue_t *queue, int engine_id);

/* TODO: ADD defualt implementation for the schedule function based on random.
 */

afl_ret_t afl_global_queue_init(afl_queue_global_t *);
void      afl_global_queue_deinit(afl_queue_global_t *);

static inline afl_queue_global_t *afl_global_queue_new() {

  afl_queue_global_t *global_queue = calloc(1, sizeof(afl_queue_global_t));
  if (!global_queue) { return NULL; }

  if (afl_global_queue_init(global_queue) != AFL_RET_SUCCESS) {

    free(global_queue);
    return NULL;

  }

  return global_queue;

}

static inline void afl_global_queue_delete(afl_queue_global_t *global_queue) {

  afl_global_queue_deinit(global_queue);

  free(global_queue);

}

#endif

