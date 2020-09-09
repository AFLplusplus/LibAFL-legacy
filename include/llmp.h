#ifndef LLMP_H
#define LLMP_H

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

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#include "afl-returns.h"
#include "afl-shmem.h"  // for sharedmem
#include "types.h"

/* We'll start of with 256 megabyte per fuzzer */
#define LLMP_INITIAL_MAP_SIZE (1 << 28)

/* What byte count llmp messages should be aligned to */
#define LLMP_ALIGNMENT (64)

/* llmp tags */
#define LLMP_TAG_NEW_QUEUE_ENTRY (0xA1B2C3D)

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

typedef struct llmp_broker_state llmp_broker_state_t;

typedef struct llmp_page {

  /* who sends messages to this page */
  u32 sender;
  /* The only variable that may be written to by the _receiver_:
  On first message receive, save_to_unmap is set to 1. This means that
  the sender can unmap this page after EOP, on exit, ...
  Using u32 for a bool as it feels more aligned. */
  volatile u32 save_to_unmap;
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
  /* Number of maps we're using */
  size_t out_map_count;
  /* The maps to write to */
  afl_shmem_t *out_maps;

} llmp_client_state_t;

/* A convenient clientloop function that can be run threaded on llmp broker
 * startup */
typedef void (*llmp_clientloop_func)(llmp_client_state_t *client_state, void *data);

/* A hook able to intercept messages arriving at the broker.
If return is false, message will not be delivered to clients.
This is synchronous, if you need long-running message handlers, register a
client instead. */
typedef bool(llmp_message_hook_func)(llmp_broker_state_t *broker, llmp_client_state_t *client, llmp_message_t *msg,
                                     void *data);

enum LLMP_CLIENT_TYPE {

  /* Unknown type, no special handling needed */
  LLMP_CLIENT_TYPE_UNKNOWN,
  /* threaded client */
  LLMP_CLIENT_TYPE_PTHREAD,
  /* child process */
  LLMP_CLIENT_TYPE_CHILD_PROCESS,
  /* foreign process, with shared local shmap */
  LLMP_CLIENT_TYPE_FOREIGN_PROCESS,

};

/* For the broker, internal: to keep track of the client */
typedef struct llmp_broker_client_metadata {

  /* client type */
  enum LLMP_CLIENT_TYPE client_type;

  /* further infos about this client */
  llmp_client_state_t *client_state;

  /* The client map we're currently reading from */
  /* We can't use the one from client_state for threaded clients
  as they share the heap with us... */
  afl_shmem_t *cur_client_map;

  /* The last message we/the broker received for this client. */
  llmp_message_t *last_msg_broker_read;

  /* pthread associated to this client, if we have a threaded client */
  pthread_t *pthread;
  /* process ID, if the client is a process */
  int pid;
  /* the client loop function */
  llmp_clientloop_func clientloop;
  /* Additional data for this client loop */
  void *data;

} llmp_broker_client_metadata_t;

/* Storage class for msg hooks */
typedef struct llmp_message_hook_data {

  llmp_message_hook_func *func;
  void *                  data;

} llmp_message_hook_data_t;

/* state of the main broker. Mostly internal stuff. */
struct llmp_broker_state {

  llmp_message_t *last_msg_sent;

  size_t       broadcast_map_count;
  afl_shmem_t *broadcast_maps;

  size_t                    msg_hook_count;
  llmp_message_hook_data_t *msg_hooks;

  size_t                         llmp_client_count;
  llmp_broker_client_metadata_t *llmp_clients;

};

/* Get a message buf as type if size matches (larger than, due to align),
else NULL */
#define LLMP_MSG_BUF_AS(msg, type)                                    \
  ({                                                                  \
                                                                      \
    llmp_message_t *_msg = msg;                                       \
    ((type *)((_msg)->buf_len >= sizeof(type) ? (_msg)->buf : NULL)); \
                                                                      \
  })

/* Get a message as type if tag matches, else NULL */
#define LLMP_MSG_BUF_IF_TAG(msg, type, tag)                                                \
  ({                                                                                       \
                                                                                           \
    llmp_message_t *_msg = msg;                                                            \
    ((type *)(((msg)->tag == tag && (msg)->buf_len >= sizeof(type)) ? (msg)->buf : NULL)); \
                                                                                           \
  })

/* If a msg is contained in the current page */
bool llmp_msg_in_page(llmp_page_t *page, llmp_message_t *msg);

/* Creates a new client process that will connect to the given port */
llmp_client_state_t *llmp_client_new(int port);

/* Creates a new, unconnected, client state */
llmp_client_state_t *llmp_client_new_unconnected();

/* Destroys the given cient state */
void llmp_client_destroy(llmp_client_state_t *client_state);

/* A client receives a broadcast message. Returns null if no message is
 * availiable */
llmp_message_t *llmp_client_recv(llmp_client_state_t *client);

/* A client blocks/spins until the next message gets posted to the page,
  then returns that message. */
llmp_message_t *llmp_client_recv_blocking(llmp_client_state_t *client);

/* Alloc the next message, internally resetting the ringbuf if full */
llmp_message_t *llmp_client_alloc_next(llmp_client_state_t *client, size_t size);

/* Commits a msg to the client's out ringbuf */
bool llmp_client_send(llmp_client_state_t *client_state, llmp_message_t *msg);

/* A simple client that, on connect, reads the new client's shmap str and writes
 the broker's initial map str */
void llmp_clientloop_tcp(llmp_client_state_t *client_state, void *data);

/* Allocate and set up the new broker instance. Afterwards, run with broker_run.
 */
llmp_broker_state_t *llmp_broker_new();

/* Register a new forked/child client.
Client thread will be called with llmp_client_state_t client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also be added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_register_childprocess_clientloop(llmp_broker_state_t *broker, llmp_clientloop_func clientloop,
                                                  void *data);

/* Client thread will be called with llmp_client_state_t client, containing the
data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_register_threaded_clientloop(llmp_broker_state_t *broker, llmp_clientloop_func clientloop, void *data);

/* Kicks off all threaded clients in the brackground, using pthreads */
bool llmp_broker_launch_clientloops(llmp_broker_state_t *broker);

/* Register a simple tcp client that will listen for new shard map clients via
 tcp */
bool llmp_broker_register_local_server(llmp_broker_state_t *broker, int port);

/* Adds a hook that gets called for each new message the broker touches.
if the callback returns false, the message is not forwarded to the clients. */
afl_ret_t llmp_broker_add_message_hook(llmp_broker_state_t *broker, llmp_message_hook_func *hook, void *data);

/* The broker walks all pages and looks for changes, then broadcasts them on
 its own shared page.
 Never returns. */
void llmp_broker_loop(llmp_broker_state_t *broker);

/* Start all threads and the main broker.
Same as llmp_broker_launch_threaded clients();
Never returns. */
void llmp_broker_run(llmp_broker_state_t *broker);

/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
void llmp_broker_once(llmp_broker_state_t *broker);

#endif                                                                                                    /* LLMP_H */

