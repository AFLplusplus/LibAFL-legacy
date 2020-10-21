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

#include "types.hpp"

#include "engine/engine.hpp"

namespace llmp {

const size_t kInitialMapSize = 1 << 28;

const int kAlignment = 4;

const u32 kTagNewCorpusEntryV1 = 0xC0ADDED1;

/* Storage class for hooks used at various places in llmp. */
struct HookData {

  void* function;
  void* data;

};

/* The actual message.
    Sender is the original client id.
    The buf can be cast to any content.
    Once committed, this should not be touched again. */
struct __attribute__((packed)) Message {

  /* Tag is the (unique) tag of a message.
  It should be unique per application and version */
  u32 tag;
  /* the sender's id */
  u32 sender;
  /* unique id for this msg */
  u32 messageId;
  /* the length of the payload, as requested by the caller */
  size_t bufLenth;
  /* the actual length of the payload, including padding to the next msg */
  size_t paddedBufLenth;
  /* the content (syntax needs c99) */
  u8 buf[];

  template<typename Type>
  Type* MessageBufferAs() {
    if (likely(sizeof(Type) <= bufLenth))
      return reinterpret_cast<Type*>(buf);
    return nullptr;
  }

  template<typename Type>
  Type* MessageBufferAsIfTag(u32 tag) {
    if (tag != this->tag)
      return nullptr;
    return MessageBufferAs<Type>();
  }

};

struct __attribute__((__packed__)) Page {

  /* who sends messages to this page */
  u32 sender;
  /* The only variable that may be written to by the _receiver_:
  On first message receive, save_to_unmap is set to 1. This means that
  the sender can unmap this page after EOP, on exit, ...
  Using u32 for a bool as it feels more aligned. */
  volatile u16 saveToUnmap;
  /* If true, client died. :( */
  volatile u16 isSenderDead;
  /* The id of the last finished message */
  volatile size_t currentMsgID;
  /* Total size of the page */
  size_t totalSize;
  /* How much of the page we already used */
  size_t usedSize;
  /* The largest allocated element so far */
  size_t maxAllocSize;
  /* The messages start here. They can be of variable size, so don't address
   * them by array. */
  Message messages[];

};

struct Client {

  /* unique ID of this client */
  u32 id;
  /* the last message we received */
  llmp_message_t *lastReceivedMsg;
  /* the current broadcast map to read from */
  afl_shmem_t *currentBroadcastMap;
  /* the last msg we sent */
  llmp_message_t *lastSentMsg;
  /* Number of maps we're using */
  size_t outMapsCount;
  /* The maps to write to */
  afl_shmem_t *outMaps;
  /* Count of the hooks we'll call for each new shared map */
  size_t newOutPageHooksCount;
  /* The hooks we'll call for each new shared map */
  HookData *newOutPageHooks;

};

enum class ClientType {
  kUnknown = 0,
  kThread,
  kChildProcess,
  kForeignProcess,
  
  kClientTypesCount
};

struct BrokerClientMetadata {

  /* client type */
  ClientType clientType;

  /* further infos about this client */
  Client *clientState;

  /* The client map we're currently reading from */
  /* We can't use the one from client_state for threaded clients
  as they share the heap with us... */
  afl_shmem_t *currentClientMap;

  /* The last message we/the broker received for this client. */
  Message *lastBrokerReceivedMsg;

  /* pthread associated to this client, if we have a threaded client */
  pthread_t *pthread;
  /* process ID, if the client is a process */
  int pid;
  /* the client loop function */
  llmp_clientloop_func clientloop;
  /* the engine */
  Engine *engine;
  /* Additional data for this client loop */
  void *data;

};

/* state of the main broker. Mostly internal stuff. */
struct BrokerState {

  Message *lastSentMsg;

  size_t broadcastMapsCount;
  afl_shmem_t *broadcastMaps;

  size_t msgHooksCount;
  HookData *msgHooks;

  size_t clientsCount;
  BrokerClientMetadata *clients;

};

};

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#include "afl-returns.h"
#include "shmem.h"  // for sharedmem
#include "types.h"

/* We'll start of with 256 megabyte per fuzzer */
#define LLMP_INITIAL_MAP_SIZE (1 << 28)

/* What byte count llmp messages should be aligned to */
#define LLMP_ALIGNMENT (64)

/* llmp tags */
#define LLMP_TAG_NEW_QUEUE_ENTRY_V1 (0xC0ADDED1)

/* Storage class for hooks used at various places in llmp. */
typedef struct llmp_hookdata_generic {

  void *func;
  void *data;

} llmp_hookdata_t;

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
  /* the length of the payload, as requested by the caller */
  size_t buf_len;
  /* the actual length of the payload, including padding to the next msg */
  size_t buf_len_padded;
  /* the content (syntax needs c99) */
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

typedef struct llmp_broker_state llmp_broker_t;

typedef struct llmp_page {

  /* who sends messages to this page */
  u32 sender;
  /* The only variable that may be written to by the _receiver_:
  On first message receive, save_to_unmap is set to 1. This means that
  the sender can unmap this page after EOP, on exit, ...
  Using u32 for a bool as it feels more aligned. */
  volatile u16 save_to_unmap;
  /* If true, client died. :( */
  volatile u16 sender_dead;
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
typedef struct llmp_client {

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
  /* Count of the hooks we'll call for each new shared map */
  size_t new_out_page_hook_count;
  /* The hooks we'll call for each new shared map */
  llmp_hookdata_t *new_out_page_hooks;

} llmp_client_t;

typedef struct llmp_broker_client_metadata llmp_broker_clientdata_t;

/* A convenient clientloop function that can be run threaded on llmp broker
 * startup */
typedef void (*llmp_clientloop_func)(llmp_client_t *client_state, void *data);

/* A hook able to intercept messages arriving at the broker.
If return is false, message will not be delivered to clients.
This is synchronous, if you need long-running message handlers, register a
client instead. */
typedef bool(llmp_message_hook_func)(llmp_broker_t *broker, llmp_broker_clientdata_t *client, llmp_message_t *msg,
                                     void *data);

/* A hook getting called for each new page this client creates.
Map points to the new map, containing the page, data point to the data passed when set up the hook. */
typedef void(llmp_client_new_page_hook_func)(llmp_client_t *client, llmp_page_t *new_out_page, void *data);

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
struct llmp_broker_client_metadata {

  /* client type */
  enum LLMP_CLIENT_TYPE client_type;

  /* further infos about this client */
  llmp_client_t *client_state;

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
  /* the engine */
  afl_engine_t *engine;
  /* Additional data for this client loop */
  void *data;

};

/* state of the main broker. Mostly internal stuff. */
struct llmp_broker_state {

  llmp_message_t *last_msg_sent;

  size_t       broadcast_map_count;
  afl_shmem_t *broadcast_maps;

  size_t           msg_hook_count;
  llmp_hookdata_t *msg_hooks;

  size_t                    llmp_client_count;
  llmp_broker_clientdata_t *llmp_clients;

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

/* Gets the llmp page struct from this shmem map */
static inline llmp_page_t *shmem2page(afl_shmem_t *afl_shmem) {

  return (llmp_page_t *)afl_shmem->map;

}

/* If a msg is contained in the current page */
bool llmp_msg_in_page(llmp_page_t *page, llmp_message_t *msg);

/* Creates a new client process that will connect to the given port */
llmp_client_t *llmp_client_new(int port);

/* Creates a new, unconnected, client state */
llmp_client_t *llmp_client_new_unconnected();

/* Destroys the given cient state */
void llmp_client_delete(llmp_client_t *client_state);

/* A client receives a broadcast message. Returns null if no message is
 * availiable */
llmp_message_t *llmp_client_recv(llmp_client_t *client);

/* A client blocks/spins until the next message gets posted to the page,
  then returns that message. */
llmp_message_t *llmp_client_recv_blocking(llmp_client_t *client);

/* Will return a ptr to the next msg buf, potentially mapping a new page automatically, if needed.
Never call alloc_next multiple times without either sending or cancelling the last allocated message for this page!
There can only ever be up to one message allocated per page at each given time. */
llmp_message_t *llmp_client_alloc_next(llmp_client_t *client, size_t size);

/* Cancels a msg previously allocated by alloc_next.
You can now allocate a new buffer on this page using alloc_next.
Don't write to the msg anymore, and don't send this message! */
bool llmp_client_send(llmp_client_t *client_state, llmp_message_t *msg);

/* Cancel send of the next message, this allows us to allocate a new message without sending this one. */
void llmp_client_cancel(llmp_client_t *client, llmp_message_t *msg);

/* Commits a msg to the client's out buf. After this, don't  write to this msg anymore! */
bool llmp_client_send(llmp_client_t *client_state, llmp_message_t *msg);

/* Adds a hook that gets called in the client for each new outgoing page the client creates (after start or EOP). */
afl_ret_t llmp_client_add_new_out_page_hook(llmp_client_t *client, llmp_client_new_page_hook_func *hook, void *data);

/* A simple client that, on connect, reads the new client's shmap str and writes
 the broker's initial map str */
void llmp_clientloop_tcp(llmp_client_t *client_state, void *data);

/* Allocate and set up the new broker instance. Afterwards, run with broker_run. */
afl_ret_t llmp_broker_init(llmp_broker_t *broker);

/* Clean up the broker instance */
void llmp_broker_deinit(llmp_broker_t *broker);

AFL_NEW_AND_DELETE_FOR(llmp_broker)

/* Register a new forked/child client.
Client thread will be called with llmp_client_t client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also be added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_register_childprocess_clientloop(llmp_broker_t *broker, llmp_clientloop_func clientloop, void *data);

/* Client thread will be called with llmp_client_t client, containing the
data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
bool llmp_broker_register_threaded_clientloop(llmp_broker_t *broker, llmp_clientloop_func clientloop, void *data);

/* launch a specific client. This function is rarely needed - all registered clients will get launched at broker_run */
bool llmp_broker_launch_client(llmp_broker_t *broker, llmp_broker_clientdata_t *clientdata);

/* Kicks off all threaded clients in the brackground, using pthreads */
bool llmp_broker_launch_clientloops(llmp_broker_t *broker);

/* Register a simple tcp client that will listen for new shard map clients via
 tcp */
bool llmp_broker_register_local_server(llmp_broker_t *broker, int port);

/* Adds a hook that gets called for each new message the broker touches.
if the callback returns false, the message is not forwarded to the clients. */
afl_ret_t llmp_broker_add_message_hook(llmp_broker_t *broker, llmp_message_hook_func *hook, void *data);

/* The broker walks all pages and looks for changes, then broadcasts them on
 its own shared page.
 Never returns. */
void llmp_broker_loop(llmp_broker_t *broker);

/* Start all threads and the main broker.
Same as llmp_broker_launch_threaded clients();
Never returns. */
void llmp_broker_run(llmp_broker_t *broker);

/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
void llmp_broker_once(llmp_broker_t *broker);

#endif                                                                                                    /* LLMP_H */

