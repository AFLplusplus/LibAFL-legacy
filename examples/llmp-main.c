/*
Example main for llmp.
*/

#include <stdio.h>

#include "aflpp.h"
#include "debug.h"
#include "types.h"
#include "llmp.h"

/* Just a u32 in a msg, for testing purposes */
#define LLMP_TAG_RANDOM_U32_V1 (0x344D011)

/* A client that randomly produces messages */
void llmp_clientloop_rand_u32(llmp_client_state_t *client, void *data) {

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


/* A client listening for new messages, then printing them */
void llmp_clientloop_print_u32(llmp_client_state_t *client_state, void *data) {

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

/* Main entry point function */
int main(int argc, char **argv) {

  int thread_count = 1;
  int port = 0xAF1;

  bool is_main = true;

  if (argc < 2 || argc > 4) {

    FATAL("Usage ./llmp_test [main|worker] <thread_count=1> <port=0xAF1>");

  }

  if (!strcmp(argv[1], "worker")) {
    is_main = false;
  } else if (strcmp(argv[1], "main")) {
    FATAL("Mode must either be main or worker!\n"
        "Usage ./llmp_test [main|worker] <thread_count=1> <port=0xAF1>");

  }

  if (argc > 2) {
    int thread_count = atoi(argv[2]);
    if (thread_count < 0) {

      FATAL("Number of clients cannot be negative.");

    }
    OKF("Spawning %d clients", thread_count);
  }

  if (argc > 3) {

    port = atoi(argv[2]);
    if (port <= 0 || port >= 1 << 16) { FATAL("illegal port"); }

  }

  if (is_main) {
    /* The main node has a broker, a tcp server, and a few worker threads */
    llmp_broker_state_t *broker = llmp_broker_new();

    llmp_broker_register_local_server(broker, port);

    if (!llmp_broker_register_threaded_clientloop(broker, llmp_clientloop_print_u32,
                                        NULL)) {

      FATAL("error adding threaded client");

    }

    int i;
    for (i = 0; i < thread_count; i++) {

      if (!llmp_broker_register_threaded_clientloop(broker, llmp_clientloop_rand_u32,
                                          NULL)) {

        FATAL("error adding threaded client");

      }

    }

    llmp_broker_run(broker);

  } else {

    if (thread_count > 1) {
      WARNF("Multiple threads not supported for clients.");
    }

    // Worker only needs to spawn client threads.
    llmp_client_state_t *client_state = llmp_client_new(port);
    llmp_clientloop_rand_u32(client_state, NULL);

  }

  FATAL("Unreachable");
}
