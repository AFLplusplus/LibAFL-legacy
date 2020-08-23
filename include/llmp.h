#ifndef LLMP_H
#define LLMP_H

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


To use, you will have to create a broker using llmp_broker_new().
Then register some clientloops using llmp_broker_register_threaded_clientloop
(or launch them as seperate processes) and call llmp_broker_run();

*/

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#include "afl-returns.h"
#include "afl-shmem.h"  // for sharedmem
#include "types.h"

// We'll start of with a megabyte of maps for now(?)
#define LLMP_INITIAL_MAP_SIZE (1 << 20)

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
  u32 message_id;

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
  /* The largest allocated element so far */
  size_t max_alloc_size;
  /* The messages start here. They can be of variable size, so don't address
   * them by array. */
  llmp_message_t messages[];

} __attribute__((__packed__)) llmp_page_t;

/* For the client: state (also used as metadata by broker) */
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

/* A convenient clientloop function that can be run threaded on llmp broker
 * startup */
typedef void (*clientloop_t)(llmp_client_state_t *client_state, void *data);

/* For the broker, internal: to keep track of the client */
typedef struct llmp_broker_client_metadata {

  /* infos about this client */
  llmp_client_state_t client_state;

  /* these are null for remote clients */

  /* The last message we/the broker received for this client. */
  llmp_message_t *last_msg_broker_read;

  /* pthread associated to this client */
  pthread_t *pthread;
  /* the client loop function */
  clientloop_t clientloop;
  /* Additional data for this client loop */
  void *data;

} llmp_broker_client_metadata_t;

/* state of the main broker. Mostly internal stuff. */
typedef struct llmp_broker_state {

  llmp_message_t *last_msg_sent;

  size_t       broadcast_map_count;
  afl_shmem_t *broadcast_maps;

  size_t                         llmp_client_count;
  llmp_broker_client_metadata_t *llmp_clients;

} llmp_broker_state_t;

/* Gets the llmp page struct from the shmem map */
llmp_page_t *llmp_page_from_shmem(afl_shmem_t *afl_shmem);

/* If a msg is contained in the current page */
bool llmp_msg_in_page(llmp_page_t *page, llmp_message_t *msg);

/* Creates a new client process that will connect to the given port */
llmp_client_state_t *llmp_client_new(int port);

/* A client receives a broadcast message. Returns null if no message is
 * availiable */
llmp_message_t *llmp_client_recv(llmp_client_state_t *client);

/* A client blocks/spins until the next message gets posted to the page,
  then returns that message. */
llmp_message_t *llmp_client_recv_blocking(llmp_client_state_t *client);

/* Alloc the next message, internally resetting the ringbuf if full */
llmp_message_t *llmp_client_alloc_next(llmp_client_state_t *client,
                                       size_t               size);

/* Commits a msg to the client's out ringbuf */
bool llmp_client_send(llmp_client_state_t *client_state, llmp_message_t *msg);

/* A simple client that, on connect, reads the new client's shmap str and writes
 * the broker's initial map str */
void llmp_clientloop_tcp(llmp_client_state_t *client_state, void *data);

/* Allocate and set up the new broker instance. Afterwards, run with broker_run.
 */
llmp_broker_state_t *llmp_broker_new();

/* Client thread will be called with llmp_client_state_t client, containing the
data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_register_threaded_clientloop(llmp_broker_state_t *broker,
                                              clientloop_t         clientloop,
                                              void *               data);

/* Kicks off all threaded clients in the brackground, using pthreads */
bool llmp_broker_launch_clientloops(llmp_broker_state_t *broker);

/* Register a simple tcp client that will listen for new shard map clients via
 * tcp */
void llmp_broker_register_local_server(llmp_broker_state_t *broker, int port);

/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page */
void llmp_broker_loop(llmp_broker_state_t *broker);

/* Start all threads and the main broker.
Same as llmp_broker_launch_threaded clients();
Never returns. */
void llmp_broker_run(llmp_broker_state_t *broker);

#endif                                                            /* LLMP_H */

