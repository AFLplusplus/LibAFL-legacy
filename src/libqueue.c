#include "libqueue.h"

// We start with the implementation of queue_entry functions here.
queue_entry_t *afl_queue_entry_init() {

  queue_entry_t *entry = ck_alloc(sizeof(queue_entry_t));
  entry->operations = ck_alloc(sizeof(struct queue_entry_operations));

  entry->operations->get_input = get_input;
  entry->operations->get_next = get_next;
  entry->operations->get_prev = get_prev;
  entry->operations->get_parent = get_parent;

  return entry;

}

void afl_queue_entry_deinit(queue_entry_t *entry) {

  ck_free(entry->operations);
  ck_free(entry);

}

// Default implementations for the queue entry vtable functions
raw_input_t *get_input(queue_entry_t *entry) {

  if (entry->on_disk) {

    raw_input_t *load = entry->input->operations->empty(entry->input);

    if (!load->operations->load_from_file(load, entry->filename))
      return load;
    else
      return NULL;

  }

  return entry->input;

}

queue_entry_t *get_next(queue_entry_t *entry) {

  return entry->next;

}

queue_entry_t *get_prev(queue_entry_t *entry) {

  return entry->prev;

}

queue_entry_t *get_parent(queue_entry_t *entry) {

  return entry->parent;

}

// We implement the queue based functions now.

base_queue_t *afl_base_queue_init(void) {

  base_queue_t *queue = ck_alloc(sizeof(base_queue_t));
  queue->operations = ck_alloc(sizeof(struct base_queue_operations));

  queue->save_to_files = false;

  queue->operations->add_to_queue = add_to_queue;
  queue->operations->get_queue_base = get_queue_base;
  queue->operations->get_size = get_size;
  queue->operations->get_dirpath = get_dirpath;
  queue->operations->get_names_id = get_names_id;
  queue->operations->get_save_to_files = get_save_to_files;
  queue->operations->set_directory = set_directory;

  return queue;

}

void afl_base_queue_deinit(base_queue_t *queue) {

  ck_free(queue->operations);
  ck_free(queue);

  /*TODO: Clear the queue entries too here*/

}

void add_to_queue(base_queue_t *queue, queue_entry_t *entry) {

  entry->next = queue->base;
  /*TODO: Need to add mutex stuff here. */
  if (queue->base) queue->base->prev = entry;

  queue->base = entry;
  queue->size++;

}

queue_entry_t *get_queue_base(base_queue_t *queue) {

  return queue->base;

}

size_t get_size(base_queue_t *queue) {

  return queue->size;

}

u8 *get_dirpath(base_queue_t *queue) {

  return queue->dirpath;

}

size_t get_names_id(base_queue_t *queue) {

  return queue->names_id;

}

bool get_save_to_files(base_queue_t *queue) {

  return queue->save_to_files;

}

void set_directory(base_queue_t *queue, u8 *new_dirpath) {

  if (!new_dirpath) queue->dirpath = "";  // We are unsetting the directory path
  queue->dirpath = new_dirpath;

  queue->save_to_files = true;
  // If the dirpath is empty, we make the save_to_files bool as false
  if (!strcmp(queue->dirpath, "")) queue->save_to_files = false;

}

feedback_queue_t *afl_feedback_queue_init(struct feedback *feedback, u8 *name) {

  feedback_queue_t *fbck_queue = ck_alloc(sizeof(feedback_queue_t));

  fbck_queue->super = *(afl_base_queue_init());
  fbck_queue->feedback = feedback;

  if (!name) name = "";

  fbck_queue->name = name;

  return fbck_queue;

}

void afl_feedback_queue_deinit(feedback_queue_t * feedback) {
  ck_free(feedback->name);

  ck_free(feedback);

}

global_queue_t * afl_global_queue_init() {

  global_queue_t * global_queue = ck_alloc(sizeof(global_queue_t));

  global_queue->super = *(afl_base_queue_init());

  global_queue->extra_ops = ck_alloc(sizeof(struct global_queue_operations));

  global_queue->extra_ops->add_feedback_queue = add_feedback_queue;

  return global_queue;

}

void afl_global_queue_deinit(global_queue_t * queue) {

  if (queue->feedback_queues_num)
    LIST_FOREACH_CLEAR(&(queue->feedback_queues), feedback_queue_t, {
      afl_feedback_queue_deinit(el);
    });

  ck_free(queue->extra_ops);
  ck_free(queue);

}

void add_feedback_queue(global_queue_t *global_queue, feedback_queue_t *fbck_queue) {

  list_append(&(global_queue->feedback_queues), fbck_queue);
  global_queue->feedback_queues_num++;

}
