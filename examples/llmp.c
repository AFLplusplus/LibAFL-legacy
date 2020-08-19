/*
A PoC for low level message passing
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <math.h>
#include <stdbool.h>
#include <pthread.h>

#include <sys/wait.h>
#include <sys/time.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "xxh3.h"
#include "alloc-inl.h"
#include "aflpp.h"
#include "os.h"
#include "feedback.h"
#include "engine.h"
#include "mutator.h"
#include "fuzzone.h"
#include "stage.h"

// We'll start of with a megabyte of maps for now(?)
#define LLMP_MAP_SIZE (1 << 20)

/* At EOP from worker to main, restart from offset 0,
  at EOP from main to worker, look for the new shared map in the payload.
  The payload will be of type `llmp_new_page_t`.
   */
#define LLMP_TAG_END_OF_PAGE_V1 (0xAF1E0F1)

/* Just a u32 in a msg, for testing purposes */
#define LLMP_TAG_RANDOM_U32_V1 (0x344D011)

/* The actual message.
    Sender is the original client id.
    The buf can be cast to any content.
    Once committed, this should not be touched again. */
typedef struct llmp_message {

  /* Tag is the (unique) tag of a message.
  It should be unique per application and version */
  u32 tag;
  /* the sender's id */
  u32 sender;
  /* unique id for this msg */
  volatile u32 message_id;

  /* the length of the payload */
  size_t buf_len;
  /* the actual content (syntax needs c99) */
  u8 buf[];

} __attribute__((packed)) llmp_message_t;

/* A sharedmap page, used for unidirectional data flow.
   After a new message is added, current_id should be set to the messages'
   unique id. Will then be read by the connected clients. If the page is full, a
   LLMP_TAG_END_OF_PAGE_V1 packet must be placed. In case of the broker, the
   sharedmap id of the next page must be included. The connected clients will
   instead reuse the ring buffer. Each client page needs to be large enough for
   the broker to consume all messages in the given time. Only the sender should
   ever write to this, and never remove anything.
*/
typedef struct llmp_page {

  /* who sends messages to this page */
  u32 sender;
  /* The id of the last finished message */
  volatile size_t current_id;
  /* Total size of the page */
  size_t size_total;
  /* How much of the page we already used */
  size_t size_used;
  /* The messages start here. They can be of variable size, so don't address
   * them by array. */
  llmp_message_t messages[];

} __attribute__((__packed__)) llmp_page_t;

/* A new sharedmap. */
typedef struct llmp_msg_new_page {

  /* unique map id for this map */
  u32 map_id;
  /* size of this map */
  size_t map_size;
  /* 0-terminated str handle for this map */
  char map_str[AFL_SHMEM_STRLEN_MAX];

} __attribute__((__packed__)) llmp_msg_new_page_t;

/* Data needed to store incoming messages */
typedef struct llmp_incoming {

  /* Optional id of the other side, if needed */
  u32 id;
  /* Map to the other side */
  afl_shmem_t map;
  /* The last message we received */
  llmp_message_t *current_message;

} llmp_incoming_t;

/* state of the main broker */
typedef struct llmp_broker_state {

  llmp_message_t *last_msg_sent;

  afl_shmem_t * current_broadcast_map;
  afl_shmem_t **broadcast_maps;

  size_t          llmp_client_count;
  llmp_incoming_t llmp_clients[];

} llmp_broker_state_t;

/* state of the attached clients */
typedef struct llmp_client_state {

  /* unique ID of this client */
  u32 id;
  /* The ringbuf to write to */
  afl_shmem_t *out_ringbuf;
  /* the current broadcast map to read from */
  afl_shmem_t *current_broadcast_map;
  /* the last msg we sent */
  llmp_message_t *last_msg_sent;

} llmp_client_state_t;

/* We need at least this much space at the end of each page to start new */
#define LLMP_MSG_NEW_PAGE_LEN \
  (sizeof(llmp_message_t) + sizeof(llmp_msg_new_page_t))

bool llmp_msg_in_page(llmp_page_t *page, llmp_message_t *msg) {

  return ((u8 *)page < (u8 *)msg &&
          ((u8 *)page + page->size_total) > (u8 *)msg);

}

/* Gets the llmp page struct from the shmem map */
llmp_page_t *llmp_page_from_shmem(afl_shmem_t *afl_shmem) {

  return (llmp_page_t *)afl_shmem->map;

}

void llmp_page_init(llmp_page_t *page, u32 sender, size_t size) {

  page->sender = sender;
  page->current_id = 0;
  page->size_total = size;
  page->size_used = 0;

}

/* Read next message. Make sure to MEM_BARRIER(); at some point before */
llmp_message_t *llmp_next_message(llmp_page_t *   page,
                                  llmp_message_t *current_message) {

  if (!page->current_id) {

    /* No messages yet */
    return NULL;

  } else if (!current_message ||

             current_message->tag == LLMP_TAG_END_OF_PAGE_V1) {

    /* We never read a message from this queue or reach EOP */
    return page->messages;

  } else if (current_message->message_id == page->current_id) {

    /* Oops! No new message! */
    return NULL;

  } else {

    return (llmp_message_t *)((u8 *)current_message + sizeof(llmp_message_t) +
                              current_message->buf_len);

  }

}

/* Special allocation function for EOP messages (and nothing else!) */
llmp_message_t *llmp_alloc_eop(llmp_page_t *page, llmp_message_t *last_msg) {

  if (!llmp_msg_in_page(page, last_msg)) {

    FATAL("EOP without any useful last_msg in the current page? size_used %ld, size_total %ld, last_msg_ptr: %p", page->size_used, page->size_total, last_msg);

  }

  llmp_message_t *ret =
      (llmp_message_t *)((u8 *)last_msg + sizeof(llmp_message_t) +
                         last_msg->buf_len);
  ret->buf_len = sizeof(llmp_msg_new_page_t);
  page->size_used += sizeof(llmp_message_t) + ret->buf_len;
  return ret;

}

/* will return a ptr to the next msg buf, or NULL if map is full */
llmp_message_t *llmp_alloc_next(llmp_page_t *page, llmp_message_t *last_msg,
                                size_t buf_len) {

  size_t new_msg_size = sizeof(llmp_message_t) + buf_len;

  //printf("alloc size_used %ld, new_size %ld, pl %ld, size_total %ld\n", page->size_used, new_msg_size, LLMP_MSG_NEW_PAGE_LEN, page->size_total);
  //fflush(stdout);

  /* Still space for the new message plus the additional "we're full" message?
   */
  if (page->size_used + new_msg_size + LLMP_MSG_NEW_PAGE_LEN >
      page->size_total) {

    /* We're full. */
    return NULL;

  }

  page->size_used += new_msg_size;

  if (!last_msg || last_msg->tag == LLMP_TAG_END_OF_PAGE_V1) {

    /* We start fresh */
    page->messages->buf_len = buf_len;
    return page->messages;

  } else if (page->current_id != last_msg->message_id) {

    /* Oops, wrong usage! */
    FATAL("BUG: The current message never got commited using llmp_commit!");

  } else {

    llmp_message_t *ret =
        (llmp_message_t *)((u8 *)last_msg + sizeof(llmp_message_t) +
                           last_msg->buf_len);
    ret->buf_len = buf_len;
    return ret;

  }

}

/* Commit the message last allocated by llmp_alloc_next to the queue */
bool llmp_commit(llmp_page_t *page, llmp_message_t *msg) {

  if (!msg || !llmp_msg_in_page(page, msg)) {

    FATAL("BUG: Uh-Oh! Wrong msg passed to llmp_send_allocated :(");

  }

  MEM_BARRIER();
  page->current_id = msg->message_id;
  MEM_BARRIER();
  return true;

}

/* Blocks/loops until the next message gets posted */
llmp_message_t *llmp_next_message_blocking(llmp_page_t *   page,
                                           llmp_message_t *current_message) {

  u32 current_id = 0;
  if (current_message != NULL) {

    if (unlikely(current_message->tag == LLMP_TAG_END_OF_PAGE_V1 &&
                 current_message)) {

      FATAL("BUG: full page passed to await_message_blocking");

    }

    current_id = current_message->message_id;

  }

  while (1) {

    MEM_BARRIER();
    if (page->current_id != current_id) {

      llmp_message_t *ret = llmp_next_message(page, current_message);
      if (!ret) { FATAL("BUG: blocking llmp message may never be NULL!"); }
      return ret;

    }

  }

}

/* no more space left! We'll have to start a new page */
afl_ret_t llmp_broker_handle_out_eop(llmp_broker_state_t *broker) {


  size_t broadcast_map_id = 0;
  while (broker->broadcast_maps[broadcast_map_id] !=
         broker->current_broadcast_map) {

    broadcast_map_id++;

  }

  size_t new_broadcast_map_id = broadcast_map_id + 1;

  if (!afl_realloc((void **)&broker->broadcast_maps,
                   1 + new_broadcast_map_id * sizeof(afl_shmem_t **))) {

    return AFL_RET_ALLOC;

  }

  broker->broadcast_maps[new_broadcast_map_id] = broker->current_broadcast_map =
      malloc(sizeof(afl_shmem_t));
  if (!broker->broadcast_maps[new_broadcast_map_id]) {

    FATAL("Could not allocate broadcast map");

  }

  if (!afl_shmem_init(broker->current_broadcast_map, LLMP_MSG_NEW_PAGE_LEN)) {

    return AFL_RET_ALLOC;

  }

  llmp_page_init(llmp_page_from_shmem(broker->current_broadcast_map), new_broadcast_map_id * -1, LLMP_MAP_SIZE);

  llmp_message_t *out =
      llmp_alloc_eop(llmp_page_from_shmem(broker->current_broadcast_map),
                     broker->last_msg_sent);
  llmp_msg_new_page_t *new_page_msg = (llmp_msg_new_page_t *)out->buf;
  new_page_msg->map_id = new_broadcast_map_id;
  new_page_msg->map_size = broker->current_broadcast_map->map_size;
  strncpy(new_page_msg->map_str, broker->current_broadcast_map->shm_str,
          AFL_SHMEM_STRLEN_MAX);
  new_page_msg->map_str[AFL_SHMEM_STRLEN_MAX - 1] = '\0';
  if (!llmp_commit(llmp_page_from_shmem(broker->current_broadcast_map), out)) {

    FATAL("Erro sending msg");

  }

  broker->last_msg_sent = out;

  return AFL_RET_SUCCESS;

}

void llmp_broker_broadcast_new_msgs(llmp_broker_state_t *broker,
                                    llmp_incoming_t *    client) {

  llmp_page_t *incoming = llmp_page_from_shmem(&client->map);
  volatile u32 current_message_id = client->current_message ? client->current_message->message_id : 0;
  while (current_message_id != incoming->current_id) {

    llmp_message_t *msg = llmp_next_message(incoming, client->current_message);
    if (!msg) {

      FATAL(
          "No message received but not all message ids receved! Data out of "
          "sync?");

    }

    if (msg->tag == LLMP_TAG_END_OF_PAGE_V1) {

      /* Ringbuf - we have to start over. */
      client->current_message = NULL;

    } else {

      llmp_message_t *out =
          llmp_alloc_next(llmp_page_from_shmem(broker->current_broadcast_map),
                          broker->last_msg_sent, msg->buf_len);
      if (!out) {

        /* no more space left! We'll have to start a new page */
        afl_ret_t ret = llmp_broker_handle_out_eop(broker);
        if (ret != AFL_RET_SUCCESS) { FATAL("%s", afl_ret_stringify(ret)); }
        /* the alloc is now on a new page */
        out =
            llmp_alloc_next(llmp_page_from_shmem(broker->current_broadcast_map),
                            broker->last_msg_sent, msg->buf_len);
        if (!out) {

          FATAL("Error allocating %ld bytes in shmap %s", msg->buf_len,
                broker->current_broadcast_map->shm_str);

        }

      }

      /* Copy over the whole message.
      If we should need zero copy, we could instead post a link to the
      original msg with the map_id and offset. */
      memcpy(out, msg, sizeof(llmp_message_t) + msg->buf_len);
      if (!llmp_commit(llmp_page_from_shmem(broker->current_broadcast_map),
                       out)) {

        FATAL("Error sending msg");

      }

      broker->last_msg_sent = out;

      client->current_message = msg;

    }

    current_message_id = client->current_message ? client->current_message->message_id : 0;

  }

}

/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page */
void llmp_broker(llmp_broker_state_t *broker) {

  u32 i;

  while (1) {

    MEM_BARRIER();
    for (i = 0; i < broker->llmp_client_count; i++) {

      llmp_incoming_t *client = &broker->llmp_clients[i];
      llmp_broker_broadcast_new_msgs(broker, client);

    }

    sleep(10);

  }

}

/* We don't have any space. Send eop, the reset to beginning of ringbuf */
void llmp_client_handle_out_eop(llmp_client_state_t *client) {

  llmp_message_t *out = llmp_alloc_eop(
      llmp_page_from_shmem(client->out_ringbuf), client->last_msg_sent);
  out->tag = LLMP_TAG_END_OF_PAGE_V1;
  out->sender = client->id;
  out->buf_len = sizeof(llmp_msg_new_page_t);
  /* We don't set anything here anyway - reusing the ringbuf for clients for
  now. llmp_msg_new_page_t *new_page_msg = (llmp_msg_new_page_t *)out->buf;
  */
  if (!llmp_commit(llmp_page_from_shmem(client->out_ringbuf), out)) {

    FATAL("Error sending msg");

  }

  client->last_msg_sent = out;

}

/* A client that randomly produces messages */
void llmp_dummy_client(llmp_client_state_t *client) {

  llmp_message_t *msg;
  while (1) {

    msg = llmp_alloc_next(llmp_page_from_shmem(client->out_ringbuf),
                          client->last_msg_sent, sizeof(u32));

    if (!msg) {

      //printf("dummy client EOP");
      //fflush(stdout);

      /* Page is full -> Tell broker and start from the beginning.
      Also, pray the broker got all messaes we're overwriting. :) */
      llmp_client_handle_out_eop(client);

      msg = llmp_alloc_next(llmp_page_from_shmem(client->out_ringbuf),
                            client->last_msg_sent, sizeof(u32));
      if (!msg) {

        FATAL("BUG: Something went wrong allocating a msg in the shmap");

      }

    }

    msg->sender = client->id;
    msg->tag = LLMP_TAG_RANDOM_U32_V1;
    msg->message_id = client->last_msg_sent ? client->last_msg_sent->message_id + 1 : 1;
    msg->buf_len = sizeof(u32);
    ((u32 *)msg->buf)[0] = rand_below(SIZE_MAX);
    llmp_commit(llmp_page_from_shmem(client->out_ringbuf), msg);
    client->last_msg_sent = msg;

    sleep(rand_below(4000));

  }

}

/* A client listening for new messages, then printing them */
void llmp_printer_client(llmp_client_state_t *client) {

  llmp_message_t *message;
  while (1) {

    MEM_BARRIER();
    message = llmp_next_message_blocking(
        llmp_page_from_shmem(client->current_broadcast_map),
        client->last_msg_sent);
    client->last_msg_sent = message;

    if (message->tag == LLMP_TAG_END_OF_PAGE_V1) {

      if (message->buf_len != sizeof(llmp_msg_new_page_t)) {

        FATAL("BUG: Broker did not send a new page ID on EOP.");

      }

      /* We will get a new page id as payload */
      llmp_msg_new_page_t *new_page = (llmp_msg_new_page_t *)message->buf;

      // TODO: Tidy up ref to old map(?)
      afl_shmem_t *shmem = calloc(1, sizeof(afl_shmem_t));
      if (!shmem) { PFATAL("Could not allocate memory for sharedmem."); }
      afl_shmem_by_str(shmem, new_page->map_str, new_page->map_size);
      client->current_broadcast_map = shmem;

    } else if (message->tag == LLMP_TAG_RANDOM_U32_V1) {

      if (message->buf_len != sizeof(u32)) {

        FATAL("BUG: incorrect buflen size for u32 message type");

      }

      printf("Got a random int from the queue: %d\n", ((u32 *)message->buf)[0]);

    }

  }

}

void *llmp_client_thread(void *thread_args) {

  /* instead of using the shmap directly, we could use `afl_shmem_by_str` */
  llmp_client_state_t *client = (llmp_client_state_t *)thread_args;
  if (!client) {

    // TODO: Propagate errors to broker;
    FATAL("Could not get client");

  }

  if (client->id == 0) {

    llmp_printer_client(client);

  } else {

    llmp_dummy_client(client);

  }

  /* both should never return */
  FATAL("BUG: Unreachable");

}

/* Main entry point function */
int main(int argc, char **argv) {

  s32 i;

  if (argc < 2) { FATAL("No client count given"); }

  int thread_count = atoi(argv[1]);
  if (thread_count <= 0) {

    FATAL("Number of clients should be greater than 0");

  }

  /* Allocate enough space for us and an array of clients */
  llmp_broker_state_t *broker =
      afl_realloc(NULL, sizeof(llmp_broker_state_t) +
                            (thread_count * sizeof(llmp_incoming_t)));
  if (!broker) { FATAL("Could not allocate broker mem"); }
  broker->broadcast_maps = 0;
  broker->llmp_client_count = thread_count;
  broker->last_msg_sent = NULL;

  if (!afl_realloc((void **)&broker->broadcast_maps,
                   1 * sizeof(afl_shmem_t **))) {

    FATAL("Could not allocate mem");

  }

  broker->broadcast_maps[0] = broker->current_broadcast_map =
      malloc(sizeof(afl_shmem_t));
  if (!broker->broadcast_maps[0]) { FATAL("Could not allocate broadcast map"); }

  afl_shmem_init(broker->current_broadcast_map, LLMP_MAP_SIZE);
  llmp_page_init(llmp_page_from_shmem(broker->current_broadcast_map), -1, LLMP_MAP_SIZE);

  pthread_t *threads = malloc(thread_count * sizeof(pthread_t));
  if (!threads) { FATAL("Coul not allocate mem for thread structs"); }

  for (i = 0; i < thread_count; i++) {

    llmp_incoming_t *client = &broker->llmp_clients[i];
    client->current_message = NULL;
    client->id = i;
    if (!afl_shmem_init(&client->map, LLMP_MAP_SIZE)) {

      FATAL("Error creating shared mem");

    }

    llmp_page_init(llmp_page_from_shmem(&client->map), i, LLMP_MAP_SIZE);

    llmp_client_state_t *thread_args = malloc(sizeof(llmp_client_state_t));
    if (!thread_args) { FATAL("Could not allocate mem"); }
    thread_args->current_broadcast_map = broker->current_broadcast_map;
    thread_args->last_msg_sent = NULL;
    thread_args->out_ringbuf = &client->map;
    thread_args->id = client->id;

    pthread_t *thread = &threads[i];

    int s = pthread_create(thread, NULL, llmp_client_thread, thread_args);
    if (!s) {

      OKF("Thread created with thread id %lu", *thread);

    } else {

      FATAL("Error creating thread");

    }

  }

  llmp_broker(broker);

  FATAL("BUG: unreachable");
  return 0;

}

