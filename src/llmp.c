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
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <math.h>
#include <stdbool.h>
#include <pthread.h>
#include <netdb.h>
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
#include "debug.h"
#include "alloc-inl.h"
#include "aflpp.h"
#include "common.h"
#include "llmp.h"

#define LLMP_DEBUG
/* all the debug prints */
#ifdef LLMP_DEBUG
#define DBG(x...) ACTF("(llmp) " x)
#else
#define DBG(x...) {}
#endif

/* INTERNAL TAG
  At EOP from worker to main, restart from offset 0,
  at EOP from main to worker, look for the new shared map in the payload.
  The payload will be of type `llmp_new_page_t`.
   */
#define LLMP_TAG_END_OF_PAGE_V1 (0xAF1E0F1)

/* INTERNAL TAG (?)
  We've added a client */
#define LLMP_TAG_CLIENT_ADDED_V1 (0xC11E471)

/* INTERNAL TAG
  If you're reading this, we got an issue */
#define LLMP_TAG_UNALLOCATED_V1 (0xDEADAFll)

/* Message payload when a client got added LLMP_TAG_CLIENT_ADDED_V1 */
/* A new sharedmap appeared.
  This is an internal message!
  LLMP_TAG_NEW_PAGE_V1
  */
typedef struct llmp_payload_new_page {

  /* size of this map */
  size_t map_size;
  /* 0-terminated str handle for this map */
  char shm_str[AFL_SHMEM_STRLEN_MAX];

} __attribute__((__packed__)) llmp_payload_new_page_t;

/* We need at least this much space at the end of each page to notify about the
 * next page/restart */
#define LLMP_MSG_END_OF_PAGE_LEN \
  (sizeof(llmp_message_t) + sizeof(llmp_payload_new_page_t))

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
static void _llmp_page_init(llmp_page_t *page, u32 sender, size_t size) {

  page->sender = sender;
  page->current_msg_id = 0;
  page->max_alloc_size = 0;
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

  ret->buf_len = sizeof(llmp_payload_new_page_t);
  ret->message_id = last_msg->message_id += 1;
  ret->tag = LLMP_TAG_END_OF_PAGE_V1;

  page->size_used += LLMP_MSG_END_OF_PAGE_LEN;

  return ret;

}

/* Will return a ptr to the next msg buf, or NULL if map is full. */
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
  page->max_alloc_size = MAX(page->max_alloc_size, ret->buf_len);

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

/* create a new shard page. Size_requested will be the min size, you may get a
 * larger map. Retruns NULL on error. */
llmp_page_t *llmp_new_page_shmem(afl_shmem_t *uninited_afl_shmem, size_t sender,
                                 size_t size_requested) {

  size_t size = next_pow2(MAX(size_requested, (size_t)LLMP_INITIAL_MAP_SIZE));
  if (!afl_shmem_init(uninited_afl_shmem, size)) { return NULL; }
  _llmp_page_init(llmp_page_from_shmem(uninited_afl_shmem), sender,
                  size_requested);
  return llmp_page_from_shmem(uninited_afl_shmem);

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

  llmp_page_t *new_broadcast_map = llmp_new_page_shmem(
      &broker->broadcast_maps[broker->broadcast_map_count - 1], -1,
      MAX(old_broadcast_map->max_alloc_size * 2,
          (size_t)LLMP_INITIAL_MAP_SIZE));
  if (!new_broadcast_map) { return AFL_RET_ALLOC; }

  new_broadcast_map->current_msg_id = old_broadcast_map->current_msg_id;
  new_broadcast_map->max_alloc_size = old_broadcast_map->max_alloc_size;

  /* On the old map, place a last message linking to the new map for the clients
   * to consume */
  llmp_message_t *out =
      llmp_alloc_eop(old_broadcast_map, broker->last_msg_sent);
  llmp_payload_new_page_t *new_page_msg = (llmp_payload_new_page_t *)out->buf;

  /* copy the infos to the message we're going to send on the old buf */
  new_page_msg->map_size = _llmp_broker_current_broadcast_map(broker)->map_size;
  strncpy(new_page_msg->shm_str,
          _llmp_broker_current_broadcast_map(broker)->shm_str,
          AFL_SHMEM_STRLEN_MAX);
  new_page_msg->shm_str[AFL_SHMEM_STRLEN_MAX - 1] = '\0';

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

static llmp_broker_client_metadata_t* _llmp_broker_register_client(llmp_broker_state_t *broker) {

  /* make space for a new client and calculate its id */
  afl_realloc(
      (void **)&broker->llmp_clients,
      (broker->llmp_client_count + 1) * sizeof(llmp_broker_client_metadata_t));

  llmp_broker_client_metadata_t *client =
      &broker->llmp_clients[broker->llmp_client_count];
  memset(client, 0, sizeof(llmp_broker_client_metadata_t));

  client->client_state.id = broker->llmp_client_count;

  broker->llmp_client_count++;

  return client;

}


static bool llmp_broker_register_clientprocess(llmp_broker_state_t *broker, llmp_payload_new_page_t *client_map_info) {

  llmp_broker_client_metadata_t *client = _llmp_broker_register_client(broker);

  if (!afl_shmem_by_str(&client->client_state.client_out_map, client_map_info->shm_str, client_map_info->map_size)) {

    DBG("Could not get shmem by str for map %s of size %ld", client_map_info->shm_str, client_map_info->map_size);
    // TODO: Handle EINTR?
    afl_shmem_deinit(&client->client_state.client_out_map);
    broker->llmp_client_count--;
    return false;

  }

  DBG("Added clientprocess with id %d", client->client_state.id);

  return true;

}

/* broker broadcast to its own page for all others to read */
void llmp_broker_handle_new_msgs(llmp_broker_state_t *          broker,
                                    llmp_broker_client_metadata_t *client) {

  // TODO: We could memcpy a range of pending messages, instead of one by one.

  llmp_page_t *incoming =
      llmp_page_from_shmem(&client->client_state.client_out_map);
  u32 current_message_id = client->last_msg_broker_read
                               ? client->last_msg_broker_read->message_id
                               : 0;
  while (current_message_id != incoming->current_msg_id) {
      
    llmp_message_t *msg = llmp_recv(incoming, client->last_msg_broker_read);

    DBG("Our current_message_id for client %d is %d%s, now processing msg id %d with tag 0x%X", client->client_state.id, current_message_id,
    client->last_msg_broker_read ? "": " (last msg was NULL)", msg->message_id, msg->tag);

    if (!msg) {

      FATAL(
          "No message received but not all message ids receved! Data out of "
          "sync?");

    }

    if (msg->tag == LLMP_TAG_END_OF_PAGE_V1) {

      DBG("Got EOP from client %d", client->client_state.id);

      /* Ringbuf - we have to start over. */
      client->last_msg_broker_read = NULL;

    } else if (msg->tag == LLMP_TAG_CLIENT_ADDED_V1) {

      DBG("Will add a new client.");

      /* This client informs us about yet another new client
      add it to the list! Also, no need to forward this msg. */
      if (msg->buf_len != sizeof(llmp_payload_new_page_t)) {
        WARNF("Ignoring broken CLIENT_ADDED msg due to incorrect size. "
        "Expected %ld but got %ld", sizeof(llmp_payload_new_page_t), msg->buf_len);
      } else {
        llmp_payload_new_page_t *pageinfo = (llmp_payload_new_page_t *)msg->buf;
        if (!llmp_broker_register_clientprocess(broker, pageinfo)) {
          FATAL("Could not register clientprocess with shm_str %s", pageinfo->shm_str);
        }
      }

    } else {

      DBG("Broadcasting msg with id %d, tag 0x%X", msg->message_id, msg->tag);
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

    }
    client->last_msg_broker_read = msg;
    current_message_id = msg->message_id;

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
      llmp_broker_handle_new_msgs(broker, client);

    }

    /* 5 milis of sleep for now to not busywait at 100% */
    usleep(5 * 1000);

  }

}

/* A wrapper around unpacking the data, calling through to the loop */
static void *_llmp_client_wrapped_loop(void *llmp_client_broker_metadata_ptr) {

  llmp_broker_client_metadata_t *metadata =
      (llmp_broker_client_metadata_t *)llmp_client_broker_metadata_ptr;
  metadata->clientloop(&metadata->client_state, metadata->data);

  WARNF("Client loop exited for client %d", metadata->client_state.id);
  return NULL;

}

/* Kicks off all threaded clients in the brackground, using pthreads */
bool llmp_broker_launch_clientloops(llmp_broker_state_t *broker) {

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

  llmp_broker_launch_clientloops(broker);
  llmp_broker_loop(broker);

}

/* We don't have any space. Send eop, the reset to beginning of ringbuf */
static void llmp_client_handle_out_eop(llmp_client_state_t *client) {

  llmp_message_t *out = llmp_alloc_eop(
      llmp_page_from_shmem(&client->client_out_map), client->last_msg_sent);
  out->tag = LLMP_TAG_END_OF_PAGE_V1;
  out->sender = client->id;
  out->buf_len = sizeof(llmp_payload_new_page_t);
  /* We don't set anything here anyway - reusing the ringbuf for clients for
  now. llmp_payload_new_page_t *new_page_msg = (llmp_payload_new_page_t
  *)out->buf;
  */
  if (!llmp_send(llmp_page_from_shmem(&client->client_out_map), out)) {

    FATAL("Error sending msg");

  }

  client->last_msg_sent = out;

}

/* A client receives a broadcast message. Returns null if no message is
 * availiable */
llmp_message_t *llmp_client_recv(llmp_client_state_t *client) {

  llmp_message_t *msg = llmp_recv(llmp_page_from_shmem(&client->client_out_map),
                                  client->last_msg_recvd);
  if (msg->tag == LLMP_TAG_UNALLOCATED_V1) {

    FATAL("BUG: Read unallocated msg");

  }

  client->last_msg_recvd = msg;
  return msg;

}

/* A client blocks/spins until the next message gets posted to the page,
  then returns that message. */
llmp_message_t *llmp_client_recv_blocking(llmp_client_state_t *client) {

  llmp_message_t *msg =
      llmp_recv_blocking(llmp_page_from_shmem(client->current_broadcast_map),
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

  DBG("Client %d sends new msg with tag 0x%X and size %ld", client_state->id, msg->tag, msg->buf_len);

  bool ret =
      llmp_send(llmp_page_from_shmem(&client_state->client_out_map), msg);
  client_state->last_msg_sent = msg;
  return ret;

}

/* A simple client that, on connect, reads the new client's shmap str and writes
 * the broker's initial map str */
void llmp_clientloop_process_server(llmp_client_state_t *client_state,
                                    void *               data) {

  int port = (int)(size_t)data;

  llmp_payload_new_page_t initial_broadcast_map = {0};
  initial_broadcast_map.map_size =
      client_state->current_broadcast_map->map_size;
  strncpy(initial_broadcast_map.shm_str,
          client_state->current_broadcast_map->shm_str,
          AFL_SHMEM_STRLEN_MAX - 1);

  struct sockaddr_in serv_addr = {0};

  int listenfd = socket(AF_INET, SOCK_STREAM, 0);

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  /* port 2801 */
  serv_addr.sin_port = htons(port);

  if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
    PFATAL("Could not bind to %d", port);
  }
  if (listen(listenfd, 10) == -1) {
    PFATAL("Coult not listen to %d", port);
  }

  llmp_message_t *msg =
      llmp_client_alloc_next(client_state, sizeof(llmp_payload_new_page_t));

  while (1) {

    if (!msg) { FATAL("Error allocating new client msg in tcp client!"); }

    msg->tag = LLMP_TAG_CLIENT_ADDED_V1;
    llmp_payload_new_page_t *payload = (llmp_payload_new_page_t *)msg->buf;

    int connfd = accept(listenfd, (struct sockaddr *)NULL, NULL);
    if (connfd == -1) {
      WARNF("Error on accept");
      continue;
    }

    DBG("New clientprocess connected");

    if (write(connfd, &initial_broadcast_map,
              sizeof(llmp_payload_new_page_t)) !=
        sizeof(llmp_payload_new_page_t)) {

      WARNF("Socket_client: TCP client disconnected immediately");
      close(connfd);
      continue;

    }

    size_t rlen_total = 0;

    while (rlen_total < sizeof(llmp_payload_new_page_t)) {
    
      ssize_t rlen =
          read(connfd, payload + rlen_total, sizeof(llmp_payload_new_page_t) - rlen_total);
      if (rlen < 0) {

        // TODO: Handle EINTR?
        WARNF("No complete map str receved from TCP client");
        close(connfd);
        continue;

      }

      rlen_total += rlen;

    }

    close(connfd);

    DBG("Got new client with map id %s and size %ld", payload->shm_str, payload->map_size);

    if (!llmp_client_send(client_state, msg)) {

      FATAL("BUG: Error sending incoming tcp msg to broker");

    }

    msg = llmp_client_alloc_next(client_state, sizeof(llmp_payload_new_page_t));

  }

}

/* Creates a new client process that will connect to the given port */
llmp_client_state_t *llmp_client_new(int port) {

  int                connfd = 0;
  struct sockaddr_in servaddr = {0};

  llmp_client_state_t *client_state = calloc(1, sizeof(llmp_client_state_t));

  client_state->current_broadcast_map = calloc(1, sizeof(afl_shmem_t));
  if (!client_state->current_broadcast_map) {

    PFATAL("Could not allocate mem");

  }

  if (!llmp_new_page_shmem(&client_state->client_out_map, client_state->id,
                           LLMP_INITIAL_MAP_SIZE)) {

    PFATAL("Could not create sharedmem");

  }

  // socket create and varification
  connfd = socket(AF_INET, SOCK_STREAM, 0);
  if (connfd == -1) { PFATAL("Unable to create socket"); }

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  servaddr.sin_port = htons(port);

  if (connect(connfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {

    FATAL(
        "Unable to connect to broker at localhost:%d, make sure it's running "
        "and has a port exposed",
        port);

  }

  llmp_payload_new_page_t client_map_msg, broker_map_msg = {0};
  client_map_msg.map_size = client_state->client_out_map.map_size;
  strncpy(client_map_msg.shm_str, client_state->client_out_map.shm_str,
          AFL_SHMEM_STRLEN_MAX - 1);

  if (write(connfd, &client_map_msg, sizeof(llmp_payload_new_page_t)) !=
      sizeof(llmp_payload_new_page_t)) {

    afl_shmem_deinit(&client_state->client_out_map);
    free(client_state);
    close(connfd);
    FATAL("Socket_client: TCP server disconnected immediately");

  }

  size_t rlen_total = 0;

  while (rlen_total < sizeof(llmp_payload_new_page_t)) {

    ssize_t rlen = read(connfd, &broker_map_msg + rlen_total,
                        sizeof(llmp_payload_new_page_t) - rlen_total);
    if (rlen < 0) {

      // TODO: Handle EINTR?
      afl_shmem_deinit(&client_state->client_out_map);
      free(client_state);
      close(connfd);

      // printf("No complete map str receved from llmp tcp server");
      return NULL;

    }

    rlen_total += rlen;

  }

  close(connfd);

  if (!afl_shmem_by_str(client_state->current_broadcast_map,
                        broker_map_msg.shm_str, broker_map_msg.map_size)) {

    // TODO: Handle EINTR?
    afl_shmem_deinit(&client_state->client_out_map);
    free(client_state);
    close(connfd);

    FATAL("Could not allocate shmem");

  }

  return client_state;

}

/* Client thread will be called with llmp_client_state_t client, containing the
data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_register_threaded_clientloop(llmp_broker_state_t *broker,
                                              clientloop_t         clientloop,
                                              void *               data) {

  llmp_broker_client_metadata_t *client = _llmp_broker_register_client(broker);

  client->pthread = malloc(sizeof(pthread_t));
  if (!client->pthread) { return false; }
  memset(client->pthread, 0, sizeof(pthread_t));

  client->clientloop = clientloop;
  client->data = data;

  if (!llmp_new_page_shmem(&client->client_state.client_out_map,
                           client->client_state.id, LLMP_INITIAL_MAP_SIZE)) {

    DBG("Could not get shared map");
    return false;

  }

  /* Each client starts with the very first map.
  They should then iterate through all maps once and work on all old messages.
*/
  client->client_state.current_broadcast_map = &broker->broadcast_maps[0];

  DBG("Registered threaded client with id %d (loop func at %p)", client->client_state.id, client->clientloop);

  return true;

}

/* Register a simple tcp client that will listen for new shard map clients via
 * tcp */
void llmp_broker_register_local_server(llmp_broker_state_t *broker, int port) {

  if (!llmp_broker_register_threaded_clientloop(
      broker, llmp_clientloop_process_server, (void *)(size_t)port)
  ) {
    FATAL("Error registering new threaded client");
  }

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

    free(broker);
    return NULL;

  }

  broker->broadcast_map_count = 1;

  if (!llmp_new_page_shmem(_llmp_broker_current_broadcast_map(broker), -1,
                           LLMP_INITIAL_MAP_SIZE)) {

    afl_free(broker->broadcast_maps);
    free(broker);
    return NULL;

  }

  return broker;

}

/* Other files may dbg too */
#undef DBG
