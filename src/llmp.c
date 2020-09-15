/*
A PoC for low level message passing

To send new messages, the clients place a new message at the end of their
client_out_map. If the ringbuf is filled up, they start place a
LLMP_AGE_END_OF_PAGE_V1 msg and alloc a new shmap.
Once the broker mapped a page, it flags it save for unmapping.

[client0]        [client1]    ...    [clientN]
  |                  |                 /
[client0_out] [client1_out] ... [clientN_out]
  |                 /                /
  |________________/                /
  |________________________________/
 \|/
[broker]

After the broker received a new message for clientN, (clientN_out->current_id
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


To use, you will have to create a broker using llmp_broker_new().
Then register some clientloops using llmp_broker_register_threaded_clientloop
(or launch them as seperate processes) and call llmp_broker_run();

*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stddef.h>
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

/* INTERNAL TAG
  We allocated this message before */
#define LLMP_TAG_ALLOCATED_V1 (0xA143AF11)

/* Just a random msg */
#define LLMP_ALIVE_V1 (0xA11431)

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
#define LLMP_MSG_END_OF_PAGE_LEN (llmp_align(sizeof(llmp_message_t) + sizeof(llmp_payload_new_page_t)))

#define LLMP_PAGE_HEADER_LEN (offsetof(llmp_page_t, messages))

/* If a msg is contained in the current page */
bool llmp_msg_in_page(llmp_page_t *page, llmp_message_t *msg) {

  DBG("llmp_msg_in_page %p within %p-%p\n", msg, page, page + page->size_total);
  return ((u8 *)page < (u8 *)msg && ((u8 *)page + page->size_total) > (u8 *)msg);

}

/* Gets the llmp page struct from the shmem map */
static inline llmp_page_t *shmem2page(afl_shmem_t *afl_shmem) {

  DBG("shmem2page %p->%p\n", afl_shmem, afl_shmem->map);
  return (llmp_page_t *)afl_shmem->map;

}

/* allign to LLMP_ALIGNNMENT bytes */
static inline size_t llmp_align(size_t to_align) {

  if (LLMP_ALIGNMENT == 0 || (to_align % LLMP_ALIGNMENT == 0)) { return to_align; }

  return to_align + (LLMP_ALIGNMENT - (to_align % LLMP_ALIGNMENT));

}

/* In case we don't have enough space, make sure the next page will be large
  enough. For now, we want to have at least enough space to store 2 of the
  largest messages we encountered. */
static inline size_t new_map_size(size_t max_alloc) {

  return next_pow2(MAX((max_alloc * 2) + LLMP_MSG_END_OF_PAGE_LEN, (size_t)LLMP_INITIAL_MAP_SIZE));

}

/* Initialize a new llmp_page_t. size should be relative to
 * llmp_page_t->messages */
static void _llmp_page_init(llmp_page_t *page, u32 sender, size_t size) {

  DBG("_llmp_page_init %p %u %lu\n", page, sender, size);
  page->sender = sender;
  page->current_msg_id = 0;
  page->max_alloc_size = 0;
  page->size_total = size;
  page->size_used = 0;
  page->messages->message_id = 0;
  page->messages->tag = LLMP_TAG_UNALLOCATED_V1;
  page->save_to_unmap = false;

}

/* Pointer to the message behind the last message */
static inline llmp_message_t *_llmp_next_msg_ptr(llmp_message_t *last_msg) {

  DBG("_llmp_next_msg_ptr %p %lu + %lu\n", last_msg, last_msg->buf_len, sizeof(llmp_message_t));
  return (llmp_message_t *)((u8 *)last_msg + sizeof(llmp_message_t) + last_msg->buf_len);

}

/* Read next message. */
llmp_message_t *llmp_recv(llmp_page_t *page, llmp_message_t *last_msg) {

  DBG("llmp_recv %p %p\n", page, last_msg);

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
llmp_message_t *llmp_recv_blocking(llmp_page_t *page, llmp_message_t *last_msg) {

  DBG("llmp_recv_blocking %p %p page->current_msg_id %lu last_msg->message_id "
      "%u\n",
      page, last_msg, page->current_msg_id, last_msg->message_id);

  u32 current_msg_id = 0;
  if (last_msg != NULL) {

    if (unlikely(last_msg->tag == LLMP_TAG_END_OF_PAGE_V1 && llmp_msg_in_page(page, last_msg))) {

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

#ifdef LLMP_DEBUG
  if (!llmp_msg_in_page(page, last_msg)) {

    /* This should only happen if the initial alloc > initial page len */
    DBG("EOP without any useful last_msg in the current page. size_used %ld, "
        "size_total %ld, last_msg_ptr: %p, max_alloc_size: %ld",
        page->size_used, page->size_total, last_msg, page->max_alloc_size);

  }

#endif

  if (page->size_used + LLMP_MSG_END_OF_PAGE_LEN > page->size_total) {

    FATAL(
        "BUG: EOP does not fit in page! page %p, size_current %ld, size_total "
        "%ld",
        page, page->size_used, page->size_total);

  }

  llmp_message_t *ret = last_msg ? _llmp_next_msg_ptr(last_msg) : page->messages;

  if (ret->tag == LLMP_TAG_ALLOCATED_V1) { FATAL("Did not call send() on last message!"); }

  ret->buf_len = sizeof(llmp_payload_new_page_t);
  ret->message_id = last_msg ? last_msg->message_id += 1 : 1;
  ret->tag = LLMP_TAG_END_OF_PAGE_V1;

  page->size_used += LLMP_MSG_END_OF_PAGE_LEN;

  return ret;

}

/* Will return a ptr to the next msg buf, or NULL if map is full. */
llmp_message_t *llmp_alloc_next(llmp_page_t *page, llmp_message_t *last_msg, size_t buf_len) {

  DBG("llmp_alloc_next %p %p %lu\n", page, last_msg, buf_len);

  size_t complete_msg_size = llmp_align(sizeof(llmp_message_t) + buf_len);
  DBG("XXX complete_msg_size %lu (h: %lu)\n", complete_msg_size, sizeof(llmp_message_t));

  /* In case we don't have enough space, make sure the next page will be large
   * enough */
  page->max_alloc_size = MAX(page->max_alloc_size, complete_msg_size);

  llmp_message_t *ret = NULL;

  DBG("last_msg %p %d (%d)\n", last_msg, last_msg ? (int)last_msg->tag : -1, (int)LLMP_TAG_END_OF_PAGE_V1);

  if (!last_msg || last_msg->tag == LLMP_TAG_END_OF_PAGE_V1) {

    /* We start fresh */
    ret = page->messages;
    /* The initial message may not be alligned, so we at least align the end of
    it. Technically, size_t can be smaller than a pointer, then who knows what
    happens */
    size_t base_addr = (size_t)ret;
    buf_len = llmp_align(base_addr + complete_msg_size) - base_addr - sizeof(llmp_message_t);
    complete_msg_size = buf_len + sizeof(llmp_message_t);
    DBG("XXX complete_msg_size NEW %lu\n", complete_msg_size);

    /* Still space for the new message plus the additional "we're full" message?
     */
    if (page->size_used + complete_msg_size + LLMP_MSG_END_OF_PAGE_LEN > page->size_total) {

      DBG("No more space in page (tried %ld bytes + END_OF_PAGE_LEN, used: "
          "%ld, "
          "total size %ld). Returning NULL",
          buf_len, page->size_used, page->size_total);

      /* We're full. */
      return NULL;

    }

    /* We need to start with 1 for ids, as current message id is initialized
     * with 0... */
    ret->message_id = last_msg ? last_msg->message_id + 1 : 1;

  } else if (page->current_msg_id != last_msg->message_id) {

    /* Oops, wrong usage! */
    FATAL(
        "BUG: The current message never got commited using llmp_send! "
        "(page->current_msg_id %ld, last_msg->message_id: %d)",
        page->current_msg_id, last_msg->message_id);

  } else {

    buf_len = complete_msg_size - sizeof(llmp_message_t);

    /* Still space for the new message plus the additional "we're full" message?
     */
    if (page->size_used + complete_msg_size + LLMP_MSG_END_OF_PAGE_LEN > page->size_total) {

      DBG("No more space in page (tried %ld bytes + END_OF_PAGE_LEN, used: "
          "%ld, "
          "total size %ld). Returning NULL",
          buf_len, page->size_used, page->size_total);

      /* We're full. */
      return NULL;

    }

    ret = _llmp_next_msg_ptr(last_msg);
    ret->message_id = last_msg->message_id + 1;
    DBG("XXX ret %p id %u buf_len %lu complete_msg_size %lu\n", ret, ret->message_id, buf_len, complete_msg_size);

  }

  /* The beginning of our message should be messages + size_used, else nobody
   * sent the last msg! */

  DBG("XXX ret %p - page->messages %p = %lu != %lu, will add %lu -> %p\n", ret, page->messages,
      (size_t)((u8 *)ret - (u8 *)page->messages), page->size_used, complete_msg_size, ((u8 *)ret) + complete_msg_size);
  if ((!last_msg && page->size_used) || ((size_t)((u8 *)ret - (u8 *)page->messages) != page->size_used)) {

    FATAL(
        "Allocated new message without calling send() inbetween. ret: %p, "
        "page: %p, complete_msg_size: %ld, size_used: %ld, last_msg: %p, "
        "page->messages %p",
        ret, page, buf_len, page->size_used, last_msg, page->messages);

  }

  page->size_used += complete_msg_size;

  ret->buf_len = buf_len;

  DBG("Returning new message at %p with len %ld, TAG was %x", ret, ret->buf_len, ret->tag);

  /* Maybe catch some bugs... */
  _llmp_next_msg_ptr(ret)->tag = LLMP_TAG_UNALLOCATED_V1;
  ret->tag = LLMP_TAG_ALLOCATED_V1;

  return ret;

}

/* Commit the message last allocated by llmp_alloc_next to the queue.
  After commiting, the msg shall no longer be altered!
  It will be read by the consuming threads (broker->clients or client->broker)
 */
bool llmp_send(llmp_page_t *page, llmp_message_t *msg) {

  DBG("llmp_send %p %p message_id %u\n", page, msg, msg->message_id);

  if (msg->tag == LLMP_TAG_UNALLOCATED_V1) { FATAL("No tag set on message with id %d!", msg->message_id); }

  if (!msg || !llmp_msg_in_page(page, msg)) {

    DBG("BUG: Uh-Oh! Wrong msg passed to llmp_send_allocated :(");
    return false;

  }

  MEM_BARRIER();
  page->current_msg_id = msg->message_id;
  MEM_BARRIER();
  return true;

}

static inline afl_shmem_t *_llmp_broker_current_broadcast_map(llmp_broker_t *broker_state) {

  DBG("_llmp_broker_current_broadcast_map %p [%u]-> %p\n", broker_state, (u32)broker_state->broadcast_map_count - 1,
      &broker_state->broadcast_maps[broker_state->broadcast_map_count - 1]);
  return &broker_state->broadcast_maps[broker_state->broadcast_map_count - 1];

}

/* create a new shard page. Size_requested will be the min size, you may get a
 * larger map. Retruns NULL on error. */
llmp_page_t *llmp_new_page_shmem(afl_shmem_t *uninited_afl_shmem, size_t sender, size_t size_requested) {

  size_t size = next_pow2(MAX(size_requested + LLMP_PAGE_HEADER_LEN, (size_t)LLMP_INITIAL_MAP_SIZE));
  if (!afl_shmem_init(uninited_afl_shmem, size)) { return NULL; }
  _llmp_page_init(shmem2page(uninited_afl_shmem), sender, size_requested);
  DBG("llmp_new_page_shmem %p %lu %lu -> size %lu\n", uninited_afl_shmem, sender, size_requested, size);
  return shmem2page(uninited_afl_shmem);

}

/* This function handles EOP by creating a new shared page and informing the
  listener about it using a EOP message. */
static afl_shmem_t *llmp_handle_out_eop(afl_shmem_t *maps, size_t *map_count_p, llmp_message_t **last_msg_p) {

  DBG("llmp_handle_out_eop %p %p=%lu %p=%p\n", maps, map_count_p, *map_count_p, last_msg_p, *last_msg_p);

  u32          map_count = *map_count_p;
  llmp_page_t *old_map = shmem2page(&maps[map_count - 1]);

  if (!(maps = afl_realloc((void *)maps, (map_count + 1) * sizeof(afl_shmem_t)))) {

    DBG("Unable to alloc space for broker map");
    return NULL;

  }

  /* Broadcast a new, large enough, message. Also sorry for that c ptr stuff! */
  llmp_page_t *new_map = llmp_new_page_shmem(&maps[map_count], old_map->sender, new_map_size(old_map->max_alloc_size));
  if (!new_map) {

    DBG("Unable to initialize new broker page");
    afl_free(maps);
    return NULL;

  }

  /* Realloc may have changed the location of maps_p (and old_map) in memory :/
   */
  old_map = shmem2page(&maps[map_count - 1]);

  *map_count_p = map_count + 1;

  new_map->current_msg_id = old_map->current_msg_id;
  new_map->max_alloc_size = old_map->max_alloc_size;

  /* On the old map, place a last message linking to the new map for the clients
   * to consume */
  llmp_message_t *out = llmp_alloc_eop(old_map, *last_msg_p);

  out->sender = old_map->sender;

  llmp_payload_new_page_t *new_page_msg = (llmp_payload_new_page_t *)out->buf;

  /* copy the infos to the message we're going to send on the old buf */
  new_page_msg->map_size = maps[map_count].map_size;
  memcpy(new_page_msg->shm_str, maps[map_count].shm_str, AFL_SHMEM_STRLEN_MAX);

  // We never sent a msg on the new buf */
  *last_msg_p = NULL;

  /* Send the last msg on the old buf */
  if (!llmp_send(old_map, out)) {

    DBG("Could not inform the broker!");
    afl_free(maps);
    return NULL;

  }

  return maps;

}

/* no more space left! We'll have to start a new page */
afl_ret_t llmp_broker_handle_out_eop(llmp_broker_t *broker) {

  DBG("Broadcasting broker EOP");
  broker->broadcast_maps =
      llmp_handle_out_eop(broker->broadcast_maps, &broker->broadcast_map_count, &broker->last_msg_sent);
  return broker->broadcast_maps ? AFL_RET_SUCCESS : AFL_RET_ALLOC;

}

llmp_message_t *llmp_broker_alloc_next(llmp_broker_t *broker, size_t len) {

  llmp_page_t *broadcast_page = shmem2page(_llmp_broker_current_broadcast_map(broker));

  llmp_message_t *out = llmp_alloc_next(broadcast_page, broker->last_msg_sent, len);

  if (!out) {

    /* no more space left! We'll have to start a new page */
    afl_ret_t ret = llmp_broker_handle_out_eop(broker);
    if (ret != AFL_RET_SUCCESS) { FATAL("%s", afl_ret_stringify(ret)); }

    /* llmp_handle_out_eop allocates a new current broadcast_map */
    broadcast_page = shmem2page(_llmp_broker_current_broadcast_map(broker));

    /* the alloc is now on a new page */
    out = llmp_alloc_next(broadcast_page, broker->last_msg_sent, len);
    if (!out) {

      FATAL("Error allocating %ld bytes in shmap %s", len, _llmp_broker_current_broadcast_map(broker)->shm_str);

    }

  }

  return out;

}

/* Registers a new client for the given sharedmap str and size.
  Be careful: Intenral realloc may change the location of the client map */
static llmp_broker_client_metadata_t *llmp_broker_register_client(llmp_broker_t *broker, char *shm_str,
                                                                  size_t map_size) {

  /* make space for a new client and calculate its id */
  if (!(broker->llmp_clients = afl_realloc((void *)broker->llmp_clients,
                                           (broker->llmp_client_count + 1) * sizeof(llmp_broker_client_metadata_t)))) {

    DBG("Failed to register new client!");
    return NULL;

  }

  llmp_broker_client_metadata_t *client = &broker->llmp_clients[broker->llmp_client_count];
  memset(client, 0, sizeof(llmp_broker_client_metadata_t));

  client->client_state = calloc(1, sizeof(llmp_client_state_t));
  if (!client->client_state) { return NULL; }

  client->client_state->id = broker->llmp_client_count;

  client->cur_client_map = calloc(1, sizeof(afl_shmem_t));
  if (!client->cur_client_map) {

    DBG("Could not allocate mem for client map");
    return NULL;

  }

  if (!afl_shmem_by_str(client->cur_client_map, shm_str, map_size)) {

    DBG("Could not map shmem '%s'", shm_str);
    return NULL;

  }

#ifdef LLMP_DEBUG
  DBG("Registerd new client.");
  size_t i;
  for (i = 0; i < broker->llmp_client_count; i++) {

    u32 actual_id = broker->llmp_clients[i].client_state->id;
    if (i != actual_id) { FATAL("Inconsistent client state detected: id is %d but should be %ld", actual_id, i); }

  }

#endif

  broker->llmp_client_count++;

  // tODO: Add client map

  DBG("Added clientprocess with id %d", client->client_state->id);

  return client;

}

/* broker broadcast to its own page for all others to read */
static inline void llmp_broker_handle_new_msgs(llmp_broker_t *broker, llmp_broker_client_metadata_t *client) {

  DBG("llmp_broker_handle_new_msgs %p %p->%u\n", broker, client, client->client_state->id);
  // TODO: We could memcpy a range of pending messages, instead of one by one.

  llmp_page_t *incoming = shmem2page(client->cur_client_map);
  u32          current_message_id = client->last_msg_broker_read ? client->last_msg_broker_read->message_id : 0;
  while (current_message_id != incoming->current_msg_id) {

    llmp_message_t *msg = llmp_recv(incoming, client->last_msg_broker_read);

    DBG("Broker send: our current_message_id for client %d (at ptr %p) is "
        "%d%s, now processing msg id %d with tag 0x%X",
        client->client_state->id, client, current_message_id,
        client->last_msg_broker_read ? "" : " (last msg was NULL)", msg->message_id, msg->tag);

    if (!msg) { FATAL("No message received but not all message ids receved! Data out of sync?"); }

    if (msg->tag == LLMP_TAG_END_OF_PAGE_V1) {

      llmp_payload_new_page_t *pageinfo = LLMP_MSG_BUF_AS(msg, llmp_payload_new_page_t);
      if (!pageinfo) {

        FATAL("Illegal message length for EOP (is %ld, expected %ld)", msg->buf_len, sizeof(llmp_payload_new_page_t));

      }

      DBG("Got EOP from client %d. Mapping new map.", client->client_state->id);

      /* We can reuse the map mem space, no need to free and calloc.
      However, the pageinfo points to the map we're about to unmap.
      Copy the contents first. */

      llmp_payload_new_page_t pageinfo_cpy;
      memcpy(&pageinfo_cpy, pageinfo, sizeof(llmp_payload_new_page_t));

      afl_shmem_t *client_map = client->cur_client_map;
      shmem2page(client_map)->save_to_unmap = true;
      afl_shmem_deinit(client_map);

      if (!afl_shmem_by_str(client_map, pageinfo->shm_str, pageinfo->map_size)) {

        FATAL("Could not get shmem by str for map %s of size %ld", pageinfo->shm_str, pageinfo->map_size);

      }

    } else if (msg->tag == LLMP_TAG_CLIENT_ADDED_V1) {

      DBG("Will add a new client.");

      /* This client informs us about yet another new client
      add it to the list! Also, no need to forward this msg. */
      llmp_payload_new_page_t *pageinfo = LLMP_MSG_BUF_AS(msg, llmp_payload_new_page_t);
      if (!pageinfo) {

        WARNF(
            "Ignoring broken CLIENT_ADDED msg due to incorrect size. "
            "Expected %ld but got %ld",
            sizeof(llmp_payload_new_page_t), msg->buf_len);

      }

      /* register_client may realloc the clients, we need to find ours again */
      u32 client_id = client->client_state->id;
      if (!llmp_broker_register_client(broker, pageinfo->shm_str, pageinfo->map_size)) {

        FATAL("Could not register clientprocess with shm_str %s", pageinfo->shm_str);

      }

      client->client_type = LLMP_CLIENT_TYPE_FOREIGN_PROCESS;

      /* find client again */
      client = &broker->llmp_clients[client_id];

    } else {

      bool   forward_msg = true;
      size_t i;
      for (i = 0; i < broker->msg_hook_count; i++) {

        llmp_message_hook_data_t *msg_hook = &broker->msg_hooks[i];
        forward_msg &= (*msg_hook->func)(broker, client->client_state, msg, msg_hook->data);

      }

      if (likely(forward_msg)) {

        DBG("Broadcasting msg with id %d, tag 0x%X", msg->message_id, msg->tag);
        llmp_message_t *out = llmp_broker_alloc_next(broker, msg->buf_len);

        if (!out) {

          FATAL("Error allocating %ld bytes in shmap %s", msg->buf_len,
                _llmp_broker_current_broadcast_map(broker)->shm_str);

        }

        /* Copy over the whole message.
        If we should need zero copy, we could instead post a link to the
        original msg with the map_id and offset. */
        DBG("broker memcpy %p->%lu %p->%lu copy %lu\n", out, out->buf_len, msg, msg->buf_len,
            sizeof(llmp_message_t) + msg->buf_len);
        size_t actual_size = out->buf_len;
        memcpy(out, msg, sizeof(llmp_message_t) + msg->buf_len);
        out->buf_len = actual_size;

        /* We need to replace the message ID with our own */
        llmp_page_t *out_page = shmem2page(_llmp_broker_current_broadcast_map(broker));

        out->message_id = out_page->current_msg_id + 1;

        if (!llmp_send(out_page, out)) { FATAL("Error sending msg"); }

        broker->last_msg_sent = out;

      }

    }

    client->last_msg_broker_read = msg;
    current_message_id = msg->message_id;

  }

}

/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
inline void llmp_broker_once(llmp_broker_t *broker) {

  u32 i;
  MEM_BARRIER();
  for (i = 0; i < broker->llmp_client_count; i++) {

    llmp_broker_client_metadata_t *client = &broker->llmp_clients[i];
    llmp_broker_handle_new_msgs(broker, client);

  }

}

/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page */
void llmp_broker_loop(llmp_broker_t *broker) {

  while (1) {

    MEM_BARRIER();
    llmp_broker_once(broker);

    /* 5 milis of sleep for now to not busywait at 100% */
    usleep(5 * 1000);

  }

}

/* A wrapper around unpacking the data, calling through to the loop */
static void *_llmp_client_wrapped_loop(void *llmp_client_broker_metadata_ptr) {

  llmp_broker_client_metadata_t *metadata = (llmp_broker_client_metadata_t *)llmp_client_broker_metadata_ptr;
  metadata->clientloop(metadata->client_state, metadata->data);

  WARNF("Client loop exited for client %d", metadata->client_state->id);
  return NULL;

}

/* Kicks off all threaded clients in the brackground, using pthreads */
bool llmp_broker_launch_clientloops(llmp_broker_t *broker) {

  size_t i;

  /* We never want pthread clients before we fork, libraries may do mutexes,
   * etc... */
  for (i = 0; i < broker->llmp_client_count; i++) {

    if (broker->llmp_clients[i].client_type == LLMP_CLIENT_TYPE_CHILD_PROCESS) {

      int child_id = fork();
      if (child_id < 0) {

        PFATAL("Could not fork");

      } else if (child_id == 0) {

        /*
        s32 dev_null_fd = open("/dev/null", O_WRONLY);
        dup2(dev_null_fd, 2);
        close(dev_null_fd);
        */

        /* in the child, start loop, exit afterwards. */
        DBG("LLMP child process started");
        _llmp_client_wrapped_loop(&broker->llmp_clients[i]);
        DBG("Fork child loop exited");
        exit(1);

      } else {

        broker->llmp_clients[i].pid = child_id;

      }

    }

  }

  /* Now spawn pthread clients */
  for (i = 0; i < broker->llmp_client_count; i++) {

    if (broker->llmp_clients[i].client_type == LLMP_CLIENT_TYPE_PTHREAD) {

      /* Got a pthread -> threaded client. Spwan. :) */
      int s =
          pthread_create(broker->llmp_clients[i].pthread, NULL, _llmp_client_wrapped_loop, &broker->llmp_clients[i]);

      if (s) {

        // TODO: Better Error-handling! :)
        PFATAL("Error creating thread %ld", i);

      }

    }

  }

  return true;

}

/* Start all threads and the main broker. Never returns. */
void llmp_broker_run(llmp_broker_t *broker) {

  llmp_broker_launch_clientloops(broker);
  llmp_broker_loop(broker);

}

/*
 For non zero-copy, we want to get rid of old pages with duplicate messages
 eventually. This function This funtion sees if we can unallocate older pages.
 The broker would have informed us by setting the save_to_unmap-flag.
*/
static void llmp_client_prune_old_pages(llmp_client_state_t *client) {

  u8 *current_map = client->out_maps[client->out_map_count - 1].map;
  /* look for pages that are save_to_unmap, then unmap them. */
  while (client->out_maps[0].map != current_map && shmem2page(&client->out_maps[0])->save_to_unmap) {

    DBG("Page %ld is save to unmap. Unmapping...", shmem2page(&client->out_maps[0])->current_msg_id);
    /* This page is save to unmap. The broker already reads or read it. */

    DBG("Unmap shared map %s from client", client->out_maps[0].shm_str);
    afl_shmem_deinit(&client->out_maps[0]);
    /* We remove at the start, move the other pages back. */
    memmove(client->out_maps, client->out_maps + 1, (client->out_map_count - 1) * sizeof(afl_shmem_t));
    client->out_map_count--;

  }

}

/* We don't have any space. Send eop, the reset to beginning of ringbuf */
static bool llmp_client_handle_out_eop(llmp_client_state_t *client) {

  DBG("Sending client EOP for client %d", client->id);

  if (!(client->out_maps = llmp_handle_out_eop(client->out_maps, &client->out_map_count, &client->last_msg_sent))) {

    DBG("An error occurred when handling client eop");
    return false;

  }

  /* Prune old pages!
    This is a good time to see if we can unallocate older pages.
    The broker would have informed us by setting the flag
  */
  llmp_client_prune_old_pages(client);

  return true;

}

/* A client receives a broadcast message. Returns null if no message is
 * availiable */
llmp_message_t *llmp_client_recv(llmp_client_state_t *client) {

  llmp_message_t *msg = NULL;

  while (1) {

    msg = llmp_recv(shmem2page(client->current_broadcast_map), client->last_msg_recvd);
    if (!msg) { return NULL; }

    client->last_msg_recvd = msg;
    if (msg->tag == LLMP_TAG_UNALLOCATED_V1) {

      FATAL("BUG: Read unallocated msg");

    } else if (msg->tag == LLMP_TAG_END_OF_PAGE_V1) {

      /* we reached the end of the current page.
      We'll init a new page but can reuse the mem are of the current map.
      However, we cannot use the message if we deinit its page, so let's copy */
      llmp_payload_new_page_t pageinfo_cpy;
      afl_shmem_t *           broadcast_map = client->current_broadcast_map;

      llmp_payload_new_page_t *pageinfo = LLMP_MSG_BUF_AS(msg, llmp_payload_new_page_t);
      if (!pageinfo) {

        FATAL("Illegal message length for EOP (is %ld, expected %ld)", msg->buf_len, sizeof(llmp_payload_new_page_t));

      }

      memcpy(&pageinfo_cpy, pageinfo, sizeof(llmp_payload_new_page_t));

      DBG("Got EOP from broker. Mapping new map.");

      /* Never read by broker broker: shmem2page(map)->save_to_unmap = true; */
      afl_shmem_deinit(broadcast_map);

      if (!afl_shmem_by_str(client->current_broadcast_map, pageinfo->shm_str, pageinfo->map_size)) {

        FATAL("Could not get shmem by str for map %s of size %ld", pageinfo->shm_str, pageinfo->map_size);

      }

    } else {

      return msg;

    }

  }

}

/* A client blocks/spins until the next message gets posted to the page,
  then returns that message. */
llmp_message_t *llmp_client_recv_blocking(llmp_client_state_t *client) {

  llmp_page_t *page = shmem2page(client->current_broadcast_map);

  while (1) {

    MEM_BARRIER();
    /* busy-wait for a new msg_id to show up in the page */
    if (page->current_msg_id != (client->last_msg_recvd ? client->last_msg_recvd->message_id : 0)) {

      DBG("Blocking read got new page->current_msg_id %ld (last msg id was %d)", page->current_msg_id,
          (client->last_msg_recvd ? client->last_msg_recvd->message_id : 0));

      llmp_message_t *ret = llmp_client_recv(client);
      if (ret) {

        DBG("blocking got new msg %d", ret->message_id);
        return ret;

      }

#ifdef LLMP_DEBUG
      if (client->last_msg_recvd != NULL && client->last_msg_recvd->tag == LLMP_TAG_END_OF_PAGE_V1) {

        FATAL("BUG: client recv returned null unexpectedly");

      }

#endif
      /* The current page could have changed in recv (EOP) */
      page = shmem2page(client->current_broadcast_map);
      /* last msg will exist, even if EOP was handled internally */

    }

  }

  llmp_message_t *msg = llmp_recv_blocking(shmem2page(client->current_broadcast_map), client->last_msg_recvd);
  if (msg->tag == LLMP_TAG_UNALLOCATED_V1) { FATAL("BUG: Read unallocated msg"); }

  client->last_msg_recvd = msg;
  return msg;

}

/* Alloc the next message, internally resetting the ringbuf if full */
llmp_message_t *llmp_client_alloc_next(llmp_client_state_t *client, size_t size) {

  llmp_message_t *msg;

  msg = llmp_alloc_next(shmem2page(&client->out_maps[client->out_map_count - 1]), client->last_msg_sent, size);

  if (!msg) {

    size_t last_map_count = client->out_map_count;

    /* Page is full -> Tell broker and start from the beginning.
    Also, pray the broker got all messaes we're overwriting. :) */
    if (!llmp_client_handle_out_eop(client)) {

      DBG("BUG: Error sending EOP");
      return NULL;

    }

    if (client->out_map_count == last_map_count ||
        shmem2page(&client->out_maps[client->out_map_count - 1])->messages->tag != LLMP_TAG_UNALLOCATED_V1) {

      FATAL("Error in handle_out_eop");

    }

    /* The client_out_map will have been changed by llmp_handle_out_eop. Don't
     * alias.
     */
    msg = llmp_alloc_next(shmem2page(&client->out_maps[client->out_map_count - 1]), NULL, size);
    if (!msg) {

      DBG("BUG: Something went wrong allocating a msg in the shmap");
      return NULL;

    }

  }

  msg->sender = client->id;
  msg->message_id = client->last_msg_sent ? client->last_msg_sent->message_id + 1 : 1;

  DBG("Allocated message at loc %p with buflen %ld", msg, msg->buf_len);

  return msg;

}

/* Commits a msg to the client's out ringbuf */
bool llmp_client_send(llmp_client_state_t *client_state, llmp_message_t *msg) {

  DBG("Client %d sends new msg at %p with tag 0x%X and size %ld", client_state->id, msg, msg->tag, msg->buf_len);

  llmp_page_t *page = shmem2page(&client_state->out_maps[client_state->out_map_count - 1]);

#ifdef LLMP_DEBUG
  if (!llmp_msg_in_page(page, msg)) {

    FATAL("BUG: Message to send not in correct page (%p not in %p with size %ld)", msg, page, page->size_total);

  }

#endif

  bool ret = llmp_send(page, msg);
  client_state->last_msg_sent = msg;
  return ret;

}

/* A simple client that, on connect, reads the new client's shmap str and
 * writes the broker's initial map str */
void llmp_clientloop_process_server(llmp_client_state_t *client_state, void *data) {

  int port = (int)(size_t)data;

  llmp_payload_new_page_t initial_broadcast_map = {0};
  initial_broadcast_map.map_size = client_state->current_broadcast_map->map_size;
  memcpy(initial_broadcast_map.shm_str, client_state->current_broadcast_map->shm_str, AFL_SHMEM_STRLEN_MAX);

  struct sockaddr_in serv_addr = {0};

  int listenfd = socket(AF_INET, SOCK_STREAM, 0);

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  /* port 2801 */
  serv_addr.sin_port = htons(port);

  if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) { PFATAL("Could not bind to %d", port); }

  if (listen(listenfd, 10) == -1) { PFATAL("Coult not listen to %d", port); }

  llmp_message_t *msg = llmp_client_alloc_next(client_state, sizeof(llmp_payload_new_page_t));

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

    if (write(connfd, &initial_broadcast_map, sizeof(llmp_payload_new_page_t)) != sizeof(llmp_payload_new_page_t)) {

      WARNF("Socket_client: TCP client disconnected immediately");
      close(connfd);
      continue;

    }

    size_t rlen_total = 0;

    while (rlen_total < sizeof(llmp_payload_new_page_t)) {

      ssize_t rlen = read(connfd, payload + rlen_total, sizeof(llmp_payload_new_page_t) - rlen_total);
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

    if (!llmp_client_send(client_state, msg)) { FATAL("BUG: Error sending incoming tcp msg to broker"); }

    msg = llmp_client_alloc_next(client_state, sizeof(llmp_payload_new_page_t));

  }

}

/* Creates a new, unconnected, client state */
llmp_client_state_t *llmp_client_new_unconnected() {

  llmp_client_state_t *client_state = calloc(1, sizeof(llmp_client_state_t));

  client_state->current_broadcast_map = calloc(1, sizeof(afl_shmem_t));
  if (!client_state->current_broadcast_map) {

    DBG("Could not allocate mem");
    return NULL;

  }

  if (!(client_state->out_maps = afl_realloc((void *)client_state->out_maps, 1 * sizeof(afl_shmem_t)))) {

    DBG("Could not allocate memory");
    free(client_state->current_broadcast_map);
    free(client_state);
    return NULL;

  }

  client_state->out_map_count = 1;

  if (!llmp_new_page_shmem(&client_state->out_maps[0], client_state->id, LLMP_INITIAL_MAP_SIZE)) {

    DBG("Could not create sharedmem");
    afl_free(client_state->out_maps);
    free(client_state->current_broadcast_map);
    free(client_state);
    return NULL;

  }

  return client_state;

}

/* Destroys the given cient state */
void llmp_client_destroy(llmp_client_state_t *client_state) {

  size_t i;
  for (i = 0; i < client_state->out_map_count; i++) {

    afl_shmem_deinit(&client_state->out_maps[i]);

  }

  afl_free(client_state->out_maps);

  afl_shmem_deinit(client_state->current_broadcast_map);
  free(client_state->current_broadcast_map);
  free(client_state);

}

/* Creates a new client process that will connect to the given port */
llmp_client_state_t *llmp_client_new(int port) {

  int                connfd = 0;
  struct sockaddr_in servaddr = {0};

  llmp_client_state_t *client_state = llmp_client_new_unconnected();

  client_state->current_broadcast_map = calloc(1, sizeof(afl_shmem_t));
  if (!client_state->current_broadcast_map) {

    llmp_client_destroy(client_state);
    DBG("Could not allocate mem");
    return NULL;

  }

  if (!(client_state->out_maps = afl_realloc((void *)client_state->out_maps, 1 * sizeof(afl_shmem_t)))) {

    DBG("Could not allocate memory");
    free(client_state->current_broadcast_map);
    free(client_state);
    return NULL;

  }

  client_state->out_map_count = 1;

  if (!llmp_new_page_shmem(&client_state->out_maps[0], client_state->id, LLMP_INITIAL_MAP_SIZE)) {

    DBG("Could not create sharedmem");
    goto error;

  }

  // socket create and varification
  connfd = socket(AF_INET, SOCK_STREAM, 0);
  if (connfd == -1) { PFATAL("Unable to create socket"); }

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  servaddr.sin_port = htons(port);

  if (connect(connfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {

    DBG("Unable to connect to broker at localhost:%d, make sure it's running "
        "and has a port exposed",
        port);
    goto error;

  }

  llmp_payload_new_page_t client_map_msg, broker_map_msg = {0};
  client_map_msg.map_size = client_state->out_maps[0].map_size;
  memcpy(client_map_msg.shm_str, client_state->out_maps[0].shm_str, AFL_SHMEM_STRLEN_MAX);

  if (write(connfd, &client_map_msg, sizeof(llmp_payload_new_page_t)) != sizeof(llmp_payload_new_page_t)) {

    afl_shmem_deinit(&client_state->out_maps[0]);
    free(client_state);
    close(connfd);
    return NULL;
    FATAL("Socket_client: TCP server disconnected immediately");

  }

  size_t rlen_total = 0;

  while (rlen_total < sizeof(llmp_payload_new_page_t)) {

    ssize_t rlen = read(connfd, &broker_map_msg + rlen_total, sizeof(llmp_payload_new_page_t) - rlen_total);
    if (rlen < 0) {

      // TODO: Handle EINTR?
      DBG("Got short response from broker via TCP");
      close(connfd);
      afl_shmem_deinit(&client_state->out_maps[0]);
      goto error;

    }

    rlen_total += rlen;

  }

  close(connfd);

  if (!afl_shmem_by_str(client_state->current_broadcast_map, broker_map_msg.shm_str, broker_map_msg.map_size)) {

    // TODO: Handle EINTR?
    DBG("Could not allocate shmem");
    afl_shmem_deinit(&client_state->out_maps[0]);
    goto error;

  }

  return client_state;

error:
  llmp_client_destroy(client_state);
  return NULL;

}

/* Register a new forked/child client.
Client thread will be called with llmp_client_state_t client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also be added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_register_childprocess_clientloop(llmp_broker_t *broker, llmp_clientloop_func clientloop, void *data) {

  afl_shmem_t client_map = {.map = NULL};

  if (!llmp_new_page_shmem(&client_map, broker->llmp_client_count, LLMP_INITIAL_MAP_SIZE)) {

    DBG("Failed to set up shmem for new client.");
    return false;

  }

  llmp_broker_client_metadata_t *client = llmp_broker_register_client(broker, client_map.shm_str, client_map.map_size);
  if (!client) {

    DBG("Could not register threaded client");
    afl_shmem_deinit(&client_map);
    return false;

  }

  client->clientloop = clientloop;
  client->data = data;
  client->client_type = LLMP_CLIENT_TYPE_CHILD_PROCESS;

  /* Copy the already allocated shmem to the client state */
  if (!(client->client_state->out_maps = afl_realloc((void *)client->client_state->out_maps, sizeof(afl_shmem_t)))) {

    DBG("Could not alloc mem for client map");
    afl_shmem_deinit(&client_map);
    afl_shmem_deinit(client->cur_client_map);
    /* "Unregister" by subtracting the client from count */
    broker->llmp_client_count--;
    return false;

  }

  memcpy(client->client_state->out_maps, &client_map, sizeof(afl_shmem_t));
  client->client_state->out_map_count = 1;

  /* Each client starts with the very first map.
  They should then iterate through all maps once and work on all old messages.
  */
  client->client_state->current_broadcast_map = &broker->broadcast_maps[0];
  client->client_state->out_map_count = 1;

  DBG("Registered threaded client with id %d (loop func at %p)", client->client_state->id, client->clientloop);

  return true;

}

/* Register a new pthread/threaded client.
Client thread will be called with llmp_client_state_t client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_register_threaded_clientloop(llmp_broker_t *broker, llmp_clientloop_func clientloop, void *data) {

  /* We do a little dance with two sharedmaps, as the threaded clients
    reuse the client_state struct as they share the heap. If we were to
    treat threads and processes differently, it'd get too complex, so
    let's just map the sharedmem twice into this process, and be done */
  afl_shmem_t client_map = {.map = NULL};

  if (!llmp_new_page_shmem(&client_map, broker->llmp_client_count, LLMP_INITIAL_MAP_SIZE)) {

    DBG("Failed to set up shmem for new client.");
    return false;

  }

  pthread_t *pthread = calloc(1, sizeof(pthread_t));
  if (!pthread) {

    DBG("Failed to alloc pthread struct");
    afl_shmem_deinit(&client_map);
    return false;

  }

  llmp_broker_client_metadata_t *client = llmp_broker_register_client(broker, client_map.shm_str, client_map.map_size);
  if (!client) {

    DBG("Could not register threaded client");
    afl_shmem_deinit(&client_map);
    free(pthread);
    return false;

  }

  client->clientloop = clientloop;
  client->data = data;
  client->pthread = pthread;
  client->client_type = LLMP_CLIENT_TYPE_PTHREAD;

  /* Copy the already allocated shmem to the client state */
  if (!(client->client_state->out_maps = afl_realloc((void *)client->client_state->out_maps, sizeof(afl_shmem_t)))) {

    DBG("Could not alloc mem for client map");
    afl_shmem_deinit(&client_map);
    afl_shmem_deinit(client->cur_client_map);
    free(pthread);
    /* "Unregister" by subtracting the client from count */
    broker->llmp_client_count--;
    return false;

  }

  memcpy(client->client_state->out_maps, &client_map, sizeof(afl_shmem_t));
  client->client_state->out_map_count = 1;

  /* Each client starts with the very first map.
  They should then iterate through all maps once and work on all old messages.
  */
  client->client_state->current_broadcast_map = &broker->broadcast_maps[0];
  client->client_state->out_map_count = 1;

  DBG("Registered threaded client with id %d (loop func at %p)", client->client_state->id, client->clientloop);

  return true;

}

/* Register a simple tcp client that will listen for new shard map clients via
 * tcp */
bool llmp_broker_register_local_server(llmp_broker_t *broker, int port) {

  if (!llmp_broker_register_threaded_clientloop(broker, llmp_clientloop_process_server, (void *)(size_t)port)) {

    DBG("Error registering new threaded client");
    return false;

  }

  return true;

}

/* Adds a hook that gets called for each new message the broker touches.
if the callback returns false, the message is not forwarded to the clients. */
afl_ret_t llmp_broker_add_message_hook(llmp_broker_t *broker, llmp_message_hook_func *hook, void *data) {

  if (!(broker->msg_hooks =
            afl_realloc((void *)broker->msg_hooks, (broker->msg_hook_count + 1) * sizeof(llmp_message_hook_data_t)))) {

    DBG("realloc for msg hooks failed");
    return AFL_RET_ALLOC;

  }

  broker->msg_hooks[broker->msg_hook_count].func = hook;
  broker->msg_hooks[broker->msg_hook_count].data = data;
  broker->msg_hook_count++;
  return AFL_RET_SUCCESS;

}

/* Allocate and set up the new broker instance. Afterwards, run with
 * broker_run.
 */
afl_ret_t llmp_broker_init(llmp_broker_t *broker) {

  memset(broker, 0, sizeof(llmp_broker_t));

  /* let's create some space for outgoing maps */
  if (!(broker->broadcast_maps = afl_realloc(NULL, 1 * sizeof(afl_shmem_t)))) {

    DBG("Broker map realloc failed");
    return AFL_RET_ALLOC;

  }

  broker->broadcast_map_count = 1;

  broker->llmp_client_count = 0;
  broker->llmp_clients = NULL;

  if (!llmp_new_page_shmem(_llmp_broker_current_broadcast_map(broker), -1, LLMP_INITIAL_MAP_SIZE)) {

    DBG("Broker map init failed");
    afl_free(broker->broadcast_maps);
    return AFL_RET_ALLOC;

  }

  DBG("Sucess");
  return AFL_RET_SUCCESS;

}

void llmp_broker_deinit(llmp_broker_t *broker) {

  size_t i;
  for (i = 0; i < broker->broadcast_map_count; i++) {

    afl_shmem_deinit(&broker->broadcast_maps[i]);

  }

  for (i = 0; i < broker->llmp_client_count; i++) {

    afl_shmem_deinit(broker->llmp_clients[i].cur_client_map);
    free(broker->llmp_clients[i].cur_client_map);
    // TODO: Properly clean up the client

  }

  afl_free(broker->broadcast_maps);
  broker->broadcast_map_count = 0;
  afl_free(broker->llmp_clients);
  broker->llmp_client_count = 0;

}

