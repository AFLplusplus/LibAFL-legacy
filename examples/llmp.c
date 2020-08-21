/*
A PoC for low level message passing

To send new messages, the clients place a new message at the end of their
client_out_map. If the ringbuf is filled up, they start place a
LLMP_AGE_END_OF_PAGE_V1 msg and start over placing msgs from the beginning. The
broker _needs to_ always be fast enough to consume more than the clients
produce. For our fuzzing scenario, with the target execution as bottleneck, this
is always the case.

[client0]        [client1]    ...    [clientN]
  |                  |                 /
[out_ringbuf0] [out_ringbuf1] ... [out_ringbufN]
  |                 /                /
  |________________/                /
  |________________________________/
 \|/
[broker]

After the broker received a new message for clientN, (out_ringbufN->current_id
!= last_message->message_id) the broker will copy the message content to its
own, centralized page.

The clients periodically check (current_broadcast_map->current_id !=
last_message->message_id) for new incoming messages. If the page is filled up,
the broker instead creates a new page and places a LLMP_TAG_END_OF_PAGE_V1
message in its queue. The LLMP_TAG_END_PAGE_V1 buf contains the new string to
access the shared map. The clients then switch over to read from that new
current map.

[broker]
  |
[current_broadcast_map]
  |
  |___________________________________
  |_________________                  \
  |                 \                  \
  |                  |                  |
 \|/                \|/                \|/
[client0]        [client1]    ...    [clientN]

In the future, if we need zero copy, the current_broadcast_map could instead
list the client_out_map ID an offset for each message. In that case, the clients
also need to create new shmaps once their bufs are filled up.

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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
#include "alloc-inl.h"
#include "aflpp.h"
#include "common.h"

// We'll start of with a megabyte of maps for now(?)
#define LLMP_MAP_SIZE (1 << 20)

/* At EOP from worker to main, restart from offset 0,
  at EOP from main to worker, look for the new shared map in the payload.
  The payload will be of type `llmp_new_page_t`.
   */
#define LLMP_TAG_END_OF_PAGE_V1 (0xAF1E0F1)

/* Just a u32 in a msg, for testing purposes */
#define LLMP_TAG_RANDOM_U32_V1 (0x344D011)

/* We've added a client */
#define LLMP_TAG_CLIENT_ADDED_V1 (0xC11E471)

/* If you're reading this, we got an issue */
#define LLMP_TAG_UNALLOCATED_V1 (0xDEADAFll)

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
   After a new message is added, current_msg_id should be set to the messages'
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
  volatile size_t current_msg_id;
  /* Total size of the page */
  size_t size_total;
  /* How much of the page we already used */
  size_t size_used;
  /* The messages start here. They can be of variable size, so don't address
   * them by array. */
  llmp_message_t messages[];

} __attribute__((__packed__)) llmp_page_t;

/* A new sharedmap appeared.
  This is an internal message!
  LLMP_TAG_NEW_PAGE_V1
  */
typedef struct llmp_payload_new_page {

  /* size of this map */
  size_t map_size;
  /* 0-terminated str handle for this map */
  char map_str[AFL_SHMEM_STRLEN_MAX];

} __attribute__((__packed__)) llmp_msg_end_of_page_t;

/* Message payload when a client got added
  LLMP_TAG_CLIENT_ADDED_V1
  */
typedef struct llmp_msg_client_added {

  /* size of this map */
  size_t map_size;
  /* 0-terminated str handle for this map */
  char map_str[AFL_SHMEM_STRLEN_MAX];

} __attribute__((__packed__)) llmp_msg_client_added_t;

/* Data needed to store incoming messages */

/* For the client: state */
typedef struct llmp_client_state {

  /* unique ID of this client */
  u32 id;
  /* the last message we received */
  llmp_message_t *last_msg_recvd;
  /* the current broadcast map to read from */
  afl_shmem_t *current_broadcast_map;
  /* the last msg we sent */
  llmp_message_t *last_msg_sent;
  /* The ringbuf to write to */
  afl_shmem_t client_out_map;

} llmp_client_state_t;

/* For the broker: to keep track of the client */
typedef struct llmp_broker_client_metadata {

  /* infos about this client */
  llmp_client_state_t client_state;

  /* these are null for remote clients */

  /* The last message we/the broker received for this client. */
  llmp_message_t *last_msg_broker_read;

  /* pthread associated to this client */
  pthread_t *pthread;
  /* the client loop function */
  void (*client_loop)(llmp_client_state_t *, void *);
  /* Additional data for this client loop */
  void *data;

} llmp_broker_client_metadata_t;

/* state of the main broker */
typedef struct llmp_broker_state {

  llmp_message_t *last_msg_sent;

  size_t       broadcast_map_count;
  afl_shmem_t *broadcast_maps;

  size_t                         llmp_client_count;
  llmp_broker_client_metadata_t *llmp_clients;

} llmp_broker_state_t;

/* We need at least this much space at the end of each page to notify about the
 * next page/restart */
#define LLMP_MSG_END_OF_PAGE_LEN \
  (sizeof(llmp_message_t) + sizeof(llmp_msg_end_of_page_t))

/* If a msg is contained in the current page */
bool llmp_msg_in_page(llmp_page_t *page, llmp_message_t *msg) {

  return ((u8 *)page < (u8 *)msg &&
          ((u8 *)page + page->size_total) > (u8 *)msg);

}

/* Gets the llmp page struct from the shmem map */
llmp_page_t *llmp_page_from_shmem(afl_shmem_t *afl_shmem) {

  return (llmp_page_t *)afl_shmem->map;

}

/* Initialize a new llmp_page_t */
void llmp_page_init(llmp_page_t *page, u32 sender, size_t size) {

  page->sender = sender;
  page->current_msg_id = 0;
  page->size_total = size;
  page->size_used = 0;
  page->messages->tag = LLMP_TAG_UNALLOCATED_V1;

}

/* Pointer to the message behind the lats message */
static llmp_message_t *_llmp_next_msg_ptr(llmp_message_t *last_msg) {

  return (llmp_message_t *)((u8 *)last_msg + sizeof(llmp_message_t) +
                            last_msg->buf_len);

}

/* Read next message. */
llmp_message_t *llmp_recv(llmp_page_t *page, llmp_message_t *last_msg) {

  MEM_BARRIER();
  if (!page->current_msg_id) {

    /* No messages yet */
    return NULL;

  } else if (!last_msg) {

    /* We never read a message from this queue. Return first. */
    return page->messages;

  } else if (last_msg->message_id == page->current_msg_id) {

    /* Oops! No new message! */
    return NULL;

  } else {

    return _llmp_next_msg_ptr(last_msg);

  }

}

/* Blocks/spins until the next message gets posted to the page,
  then returns that message. */
llmp_message_t *llmp_recv_blocking(llmp_page_t *   page,
                                   llmp_message_t *last_msg) {

  u32 current_msg_id = 0;
  if (last_msg != NULL) {

    if (unlikely(last_msg->tag == LLMP_TAG_END_OF_PAGE_V1 &&
                 llmp_msg_in_page(page, last_msg))) {

      FATAL("BUG: full page passed to await_message_blocking or reset failed");

    }

    current_msg_id = last_msg->message_id;

  }

  while (1) {

    MEM_BARRIER();
    if (page->current_msg_id != current_msg_id) {

      llmp_message_t *ret = llmp_recv(page, last_msg);
      if (!ret) { FATAL("BUG: blocking llmp message should never be NULL!"); }
      return ret;

    }

  }

}

/* Special allocation function for EOP messages (and nothing else!)
  The normal alloc will fail if there is not enough space for buf_len + EOP
  So if llmp_alloc_next fails, create new page if necessary, use this function,
  place EOP, commit EOP, reset, alloc again on the new space.
*/
llmp_message_t *llmp_alloc_eop(llmp_page_t *page, llmp_message_t *last_msg) {

  if (!llmp_msg_in_page(page, last_msg)) {

    FATAL(
        "BUG: EOP without any useful last_msg in the current page? size_used "
        "%ld, "
        "size_total %ld, last_msg_ptr: %p",
        page->size_used, page->size_total, last_msg);

  }

  if (page->size_used + LLMP_MSG_END_OF_PAGE_LEN > page->size_total) {

    FATAL(
        "BUG: EOP does not fit in page! page %p, size_current %ld, size_total "
        "%ld",
        page, page->size_used, page->size_total);

  }

  llmp_message_t *ret = _llmp_next_msg_ptr(last_msg);

  ret->buf_len = sizeof(llmp_msg_end_of_page_t);
  ret->message_id = last_msg->message_id += 1;
  ret->tag = LLMP_TAG_END_OF_PAGE_V1;

  page->size_used += LLMP_MSG_END_OF_PAGE_LEN;

  return ret;

}

/* will return a ptr to the next msg buf, or NULL if map is full */
llmp_message_t *llmp_alloc_next(llmp_page_t *page, llmp_message_t *last_msg,
                                size_t buf_len) {

  size_t complete_msg_size = sizeof(llmp_message_t) + buf_len;

  // printf("alloc size_used %ld, new_size %ld, pl %ld, size_total %ld\n",
  // page->size_used, complete_msg_size, LLMP_MSG_END_OF_PAGE_LEN,
  // page->size_total); fflush(stdout);

  /* Still space for the new message plus the additional "we're full" message?
   */
  if (page->size_used + complete_msg_size + LLMP_MSG_END_OF_PAGE_LEN >
      page->size_total) {

    /* We're full. */
    return NULL;

  }

  page->size_used += complete_msg_size;

  llmp_message_t *ret = NULL;

  if (!last_msg || last_msg->tag == LLMP_TAG_END_OF_PAGE_V1) {

    /* We start fresh */
    ret = page->messages;
    ret->message_id = last_msg ? last_msg->message_id + 1 : 1;

  } else if (page->current_msg_id != last_msg->message_id) {

    /* Oops, wrong usage! */
    FATAL("BUG: The current message never got commited using llmp_send!");

  } else {

    ret = _llmp_next_msg_ptr(last_msg);
    ret->message_id = last_msg->message_id + 1;

  }

  ret->buf_len = buf_len;

  /* Maybe catch some bugs... */
  _llmp_next_msg_ptr(ret)->tag = LLMP_TAG_UNALLOCATED_V1;

  return ret;

}

/* Commit the message last allocated by llmp_alloc_next to the queue.
  After commiting, the msg shall no longer be altered!
  It will be read by the consuming threads (broker->clients or client->broker)
 */
bool llmp_send(llmp_page_t *page, llmp_message_t *msg) {

  if (!msg || !llmp_msg_in_page(page, msg)) {

    FATAL("BUG: Uh-Oh! Wrong msg passed to llmp_send_allocated :(");

  }

  MEM_BARRIER();
  page->current_msg_id = msg->message_id;
  MEM_BARRIER();
  return true;

}

static inline afl_shmem_t *_llmp_broker_current_broadcast_map(
    llmp_broker_state_t *broker_state) {

  return &broker_state->broadcast_maps[broker_state->broadcast_map_count - 1];

}

/* no more space left! We'll have to start a new page */
afl_ret_t llmp_broker_handle_out_eop(llmp_broker_state_t *broker) {

  llmp_page_t *old_broadcast_map =
      llmp_page_from_shmem(_llmp_broker_current_broadcast_map(broker));
  broker->broadcast_map_count++;

  if (!afl_realloc((void **)&broker->broadcast_maps,
                   broker->broadcast_map_count * sizeof(afl_shmem_t))) {

    return AFL_RET_ALLOC;

  }

  if (!afl_shmem_init(broker->broadcast_maps, LLMP_MSG_END_OF_PAGE_LEN)) {

    return AFL_RET_ALLOC;

  }

  llmp_page_t *new_broadcast_map =
      llmp_page_from_shmem(_llmp_broker_current_broadcast_map(broker));
  llmp_page_init(new_broadcast_map, -1, LLMP_MAP_SIZE);

  new_broadcast_map->current_msg_id = old_broadcast_map->current_msg_id;

  /* On the old map, place a last message linking to the new map for the clients
   * to consume */
  llmp_message_t *out =
      llmp_alloc_eop(old_broadcast_map, broker->last_msg_sent);
  llmp_msg_end_of_page_t *new_page_msg = (llmp_msg_end_of_page_t *)out->buf;

  /* copy the infos to the message we're going to send on the old buf */
  new_page_msg->map_size = _llmp_broker_current_broadcast_map(broker)->map_size;
  strncpy(new_page_msg->map_str,
          _llmp_broker_current_broadcast_map(broker)->shm_str,
          AFL_SHMEM_STRLEN_MAX);
  new_page_msg->map_str[AFL_SHMEM_STRLEN_MAX - 1] = '\0';

  /* Send the last msg on the old buf */
  if (!llmp_send(old_broadcast_map, out)) { FATAL("Erro sending msg"); }

  broker->last_msg_sent = out;

  return AFL_RET_SUCCESS;

}

llmp_message_t *llmp_broker_alloc_next(llmp_broker_state_t *broker,
                                       size_t               len) {

  llmp_page_t *broadcast_page =
      llmp_page_from_shmem(_llmp_broker_current_broadcast_map(broker));

  llmp_message_t *out =
      llmp_alloc_next(broadcast_page, broker->last_msg_sent, len);

  if (!out) {

    /* no more space left! We'll have to start a new page */
    afl_ret_t ret = llmp_broker_handle_out_eop(broker);
    if (ret != AFL_RET_SUCCESS) { FATAL("%s", afl_ret_stringify(ret)); }

    /* handle_out_eop allocates a new current broadcast_map */
    broadcast_page =
        llmp_page_from_shmem(_llmp_broker_current_broadcast_map(broker));

    /* the alloc is now on a new page */
    out = llmp_alloc_next(broadcast_page, broker->last_msg_sent, len);
    if (!out) {

      FATAL("Error allocating %ld bytes in shmap %s", len,
            _llmp_broker_current_broadcast_map(broker)->shm_str);

    }

  }

  return out;

}

/* broker broadcast to its own page for all others to read */
void llmp_broker_broadcast_new_msgs(llmp_broker_state_t *          broker,
                                    llmp_broker_client_metadata_t *client) {

  // TODO: We could memcpy a range of pending messages, instead of one by one.

  llmp_page_t *incoming =
      llmp_page_from_shmem(&client->client_state.client_out_map);
  u32 current_message_id = client->last_msg_broker_read
                               ? client->last_msg_broker_read->message_id
                               : 0;
  while (current_message_id != incoming->current_msg_id) {

    llmp_message_t *msg = llmp_recv(incoming, client->last_msg_broker_read);
    if (!msg) {

      FATAL(
          "No message received but not all message ids receved! Data out of "
          "sync?");

    }

    if (msg->tag == LLMP_TAG_END_OF_PAGE_V1) {

      /* Ringbuf - we have to start over. */
      client->last_msg_broker_read = NULL;

    } else {

      llmp_message_t *out = llmp_broker_alloc_next(broker, msg->buf_len);

      if (!out) {

        FATAL("Error allocating %ld bytes in shmap %s", msg->buf_len,
              _llmp_broker_current_broadcast_map(broker)->shm_str);

      }

      /* Copy over the whole message.
      If we should need zero copy, we could instead post a link to the
      original msg with the map_id and offset. */
      memcpy(out, msg, sizeof(llmp_message_t) + msg->buf_len);

      /* We need to replace the message ID with our own */
      llmp_page_t *out_page =
          llmp_page_from_shmem(_llmp_broker_current_broadcast_map(broker));

      out->message_id = out_page->current_msg_id + 1;
      if (!llmp_send(out_page, out)) { FATAL("Error sending msg"); }

      broker->last_msg_sent = out;

      client->last_msg_broker_read = msg;

    }

    current_message_id = client->last_msg_broker_read
                             ? client->last_msg_broker_read->message_id
                             : 0;

  }

}

/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page */
void llmp_broker_loop(llmp_broker_state_t *broker) {

  u32 i;

  while (1) {

    MEM_BARRIER();
    for (i = 0; i < broker->llmp_client_count; i++) {

      llmp_broker_client_metadata_t *client = &broker->llmp_clients[i];
      llmp_broker_broadcast_new_msgs(broker, client);

    }

    usleep(10 * 1000);

  }

}

/* A wrapper around unpacking the data, calling through to the loop */
static void *_llmp_client_wrapped_loop(void *llmp_client_broker_metadata_ptr) {

  llmp_broker_client_metadata_t *metadata =
      (llmp_broker_client_metadata_t *)llmp_client_broker_metadata_ptr;
  metadata->client_loop(&metadata->client_state, metadata->data);

  WARNF("Client loop exited for client %d", metadata->client_state.id);
  return NULL;

}

/* Kicks off all threaded clients in the brackground, using pthreads */
bool llmp_broker_launch_threaded_clients(llmp_broker_state_t *broker) {

  size_t i;

  for (i = 0; i < broker->llmp_client_count; i++) {

    if (broker->llmp_clients[i].pthread != NULL) {

      /* Got a pthread -> threaded client. Spwan. :) */
      int s =
          pthread_create(broker->llmp_clients[i].pthread, NULL,
                         _llmp_client_wrapped_loop, &broker->llmp_clients[i]);

      if (s) {

        // TODO: Better Error-handling! :)
        PFATAL("Error creating thread %ld", i);

      }

    }

  }

  return true;

}

/* Start all threads and the main broker. Never returns. */
void llmp_broker_run(llmp_broker_state_t *broker) {

  llmp_broker_launch_threaded_clients(broker);
  llmp_broker_loop(broker);

}

/* We don't have any space. Send eop, the reset to beginning of ringbuf */
void llmp_client_handle_out_eop(llmp_client_state_t *client) {

  llmp_message_t *out = llmp_alloc_eop(
      llmp_page_from_shmem(&client->client_out_map), client->last_msg_sent);
  out->tag = LLMP_TAG_END_OF_PAGE_V1;
  out->sender = client->id;
  out->buf_len = sizeof(llmp_msg_end_of_page_t);
  /* We don't set anything here anyway - reusing the ringbuf for clients for
  now. llmp_msg_end_of_page_t *new_page_msg = (llmp_msg_end_of_page_t
  *)out->buf;
  */
  if (!llmp_send(llmp_page_from_shmem(&client->client_out_map), out)) {

    FATAL("Error sending msg");

  }

  client->last_msg_sent = out;

}

/* A client receives a broadcast message. Returns null if no message is availiable */
llmp_message_t *llmp_client_recv(llmp_client_state_t *client) {

  llmp_message_t *msg = llmp_recv(llmp_page_from_shmem(&client->client_out_map),
                                  client->last_msg_recvd);
  if (msg->tag == LLMP_TAG_UNALLOCATED_V1) {

    FATAL("BUG: Read unallocated msg");

  }

  client->last_msg_recvd = msg;
  return msg;

}

/* A client blocks until the next broadcast rolls in */
llmp_message_t *llmp_client_recv_blocking(llmp_client_state_t *client) {

  llmp_message_t *msg = llmp_recv_blocking(llmp_page_from_shmem(client->current_broadcast_map),
                            client->last_msg_recvd);
  if (msg->tag == LLMP_TAG_UNALLOCATED_V1) {

    FATAL("BUG: Read unallocated msg");

  }

  client->last_msg_recvd = msg;
  return msg;

}

/* Alloc the next message, internally resetting the ringbuf if full */
llmp_message_t *llmp_client_alloc_next(llmp_client_state_t *client,
                                       size_t               size) {

  llmp_message_t *msg;

  msg = llmp_alloc_next(llmp_page_from_shmem(&client->client_out_map),
                        client->last_msg_sent, size);

  if (!msg) {

    /* Page is full -> Tell broker and start from the beginning.
    Also, pray the broker got all messaes we're overwriting. :) */
    llmp_client_handle_out_eop(client);

    /* The client_out_map will have been changed by handle_out_eop. Don't alias.
     */
    msg = llmp_alloc_next(llmp_page_from_shmem(&client->client_out_map),
                          client->last_msg_sent, sizeof(u32));
    if (!msg) {

      FATAL("BUG: Something went wrong allocating a msg in the shmap");

    }

  }

  msg->sender = client->id;
  msg->message_id =
      client->last_msg_sent ? client->last_msg_sent->message_id + 1 : 1;

  return msg;

}

/* Commits a msg to the client's out ringbuf */
bool llmp_client_send(llmp_client_state_t *client_state, llmp_message_t *msg) {

  bool ret =
      llmp_send(llmp_page_from_shmem(&client_state->client_out_map), msg);
  client_state->last_msg_sent = msg;
  return ret;

}

/* A client that randomly produces messages */
void llmp_client_loop_rand_u32(llmp_client_state_t *client, void *data) {

  (void)data;

  while (1) {

    llmp_message_t *msg = llmp_client_alloc_next(client, sizeof(u32));
    msg->tag = LLMP_TAG_RANDOM_U32_V1;
    ((u32 *)msg->buf)[0] = rand_below(SIZE_MAX);

    OKF("%d Sending msg with id %d and payload %d.", client->id,
        msg->message_id, ((u32 *)msg->buf)[0]);

    llmp_client_send(client, msg);
    usleep(rand_below(4000) * 1000);

  }

}

/* A simple client that, on connect, reads the new client's shmap str and writes
 * the broker's initial map str */
void llmp_client_loop_tcp(llmp_client_state_t *client_state, void *data) {

  int port = (int)(size_t)data;

  char broker_map_str[AFL_SHMEM_STRLEN_MAX];
  strncpy(broker_map_str, client_state->current_broadcast_map->shm_str,
          AFL_SHMEM_STRLEN_MAX);

  struct sockaddr_in serv_addr = {0};

  int listenfd = socket(AF_INET, SOCK_STREAM, 0);

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  /* port 2801 */
  serv_addr.sin_port = htons(port);

  bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  listen(listenfd, 10);

  llmp_message_t *msg =
      llmp_client_alloc_next(client_state, sizeof(llmp_msg_client_added_t));

  while (1) {

    if (!msg) { FATAL("Error allocating new client msg in tcp client!"); }

    msg->tag = LLMP_TAG_CLIENT_ADDED_V1;
    /* TODO: Maybe the new tcp client wants to tell us its size, instead? */
    llmp_msg_client_added_t *payload = (llmp_msg_client_added_t *)msg->buf;
    payload->map_size = LLMP_MAP_SIZE;

    int connfd = accept(listenfd, (struct sockaddr *)NULL, NULL);

    if (write(connfd, broker_map_str, AFL_SHMEM_STRLEN_MAX) !=
        AFL_SHMEM_STRLEN_MAX) {

      WARNF("Socket_client: TCP client disconnected immediately");
      close(connfd);
      continue;

    }

    ssize_t rlen_total = 0;

    while (rlen_total != AFL_SHMEM_STRLEN_MAX) {

      ssize_t rlen =
          read(connfd, payload->map_str, AFL_SHMEM_STRLEN_MAX - rlen_total);
      if (rlen < 0) {

        // TODO: Handle EINTR?
        WARNF("No complete map str receved from TCP client");
        close(connfd);
        continue;

      }

    }

    close(connfd);

    if (!llmp_client_send(client_state, msg)) {

      FATAL("BUG: Error sending incoming tcp msg to broker");

    }

    msg = llmp_client_alloc_next(client_state, sizeof(llmp_msg_client_added_t));

  }

}

/* A client listening for new messages, then printing them */
void llmp_client_loop_print_u32(llmp_client_state_t *client_state, void *data) {

  (void)data;

  llmp_message_t *message;
  while (1) {

    MEM_BARRIER();
    message = llmp_client_recv_blocking(client_state);

    if (message->tag == LLMP_TAG_RANDOM_U32_V1) {

      if (message->buf_len != sizeof(u32)) {

        FATAL("BUG: incorrect buflen size for u32 message type");

      }

      printf("Got a random int from the queue: %d\n", ((u32 *)message->buf)[0]);

    }

  }

}

/* Client thread will be called with llmp_client_state_t client, containing the
data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_new_threaded_client(llmp_broker_state_t *broker,
                                     void (*client_loop)(llmp_client_state_t *,
                                                         void *),
                                     void *data) {

  /* make space for a new client and calculate its id */
  broker->llmp_client_count++;
  afl_realloc(
      (void **)&broker->llmp_clients,
      broker->llmp_client_count * sizeof(llmp_broker_client_metadata_t));

  llmp_broker_client_metadata_t *client =
      &broker->llmp_clients[broker->llmp_client_count - 1];
  memset(client, 0, sizeof(llmp_broker_client_metadata_t));

  client->pthread = malloc(sizeof(pthread_t));
  if (!client->pthread) { return false; }

  memset(client->pthread, 0, sizeof(pthread_t));

  client->last_msg_broker_read = NULL;
  client->client_state.last_msg_recvd = NULL;
  client->client_state.last_msg_sent = NULL;
  client->client_state.id = broker->llmp_client_count;

  client->client_loop = client_loop;
  client->data = data;

  if (!afl_shmem_init(&client->client_state.client_out_map, LLMP_MAP_SIZE)) {

    return false;

  }

  llmp_page_init(llmp_page_from_shmem(&client->client_state.client_out_map),
                 client->client_state.id, LLMP_MAP_SIZE);

  /* Each client starts with the very first map.
  They should then iterate through all maps once and work on all old messages.
*/
  client->client_state.current_broadcast_map = &broker->broadcast_maps[0];

  return true;

}

/* Register a simple tcp client that will listen for new shard map clients via
 * tcp */
void llmp_broker_new_tcp_client(llmp_broker_state_t *broker, int port) {

  llmp_broker_new_threaded_client(broker, llmp_client_loop_tcp,
                                  (void *)(size_t)port);

}

/* Allocate and set up the new broker instance. Afterwards, run with broker_run.
 */
llmp_broker_state_t *llmp_broker_new() {

  /* Allocate enough space for us and an array of clients */
  llmp_broker_state_t *broker = malloc(sizeof(llmp_broker_state_t));
  if (!broker) { FATAL("Could not allocate broker mem"); }
  broker->last_msg_sent = NULL;
  broker->llmp_client_count = 0;

  broker->llmp_clients = NULL;
  broker->broadcast_maps = NULL;

  /* let's create some space for outgoing maps */
  if (!afl_realloc((void **)&broker->broadcast_maps, 1 * sizeof(afl_shmem_t))) {

    FATAL("Could not allocate mem");

  }

  broker->broadcast_map_count = 1;

  if (!afl_shmem_init(_llmp_broker_current_broadcast_map(broker),
                      LLMP_MAP_SIZE)) {

    FATAL("Could not allocate shared map for broker");

  }

  llmp_page_init(
      llmp_page_from_shmem(_llmp_broker_current_broadcast_map(broker)), -1,
      LLMP_MAP_SIZE);

  return broker;

}

/* Main entry point function */
int main(int argc, char **argv) {

  if (argc < 2 || argc > 3) {

    FATAL("Usage ./llmp_test <thread_count> <port=0xAF1>");

  }

  int thread_count = atoi(argv[1]);
  if (thread_count <= 0) {

    FATAL("Number of clients should be greater than 0");

  }

  int port = 0xAF1;

  if (argc > 2) {

    port = atoi(argv[2]);
    if (port <= 0 || port >= 1 << 16) { FATAL("illegal port"); }

  }

  llmp_broker_state_t *broker = llmp_broker_new();

  llmp_broker_new_tcp_client(broker, port);

  if (!llmp_broker_new_threaded_client(broker, llmp_client_loop_print_u32,
                                       NULL)) {

    FATAL("error adding threaded client");

  }

  int i;
  for (i = 0; i < thread_count; i++) {

    if (!llmp_broker_new_threaded_client(broker, llmp_client_loop_rand_u32,
                                         NULL)) {

      FATAL("error adding threaded client");

    }

  }

  llmp_broker_run(broker);

}

