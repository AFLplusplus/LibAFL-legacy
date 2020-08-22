#include <stdio.h>

#include "aflpp.h"
#include "debug.h"
#include "types.h"
#include "llmp.h"

/* Just a u32 in a msg, for testing purposes */
#define LLMP_TAG_RANDOM_U32_V1 (0x344D011)

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

  if (!llmp_broker_register_threaded_clientloop(broker, llmp_client_loop_print_u32,
                                       NULL)) {

    FATAL("error adding threaded client");

  }

  int i;
  for (i = 0; i < thread_count; i++) {

    if (!llmp_broker_register_threaded_clientloop(broker, llmp_client_loop_rand_u32,
                                         NULL)) {

      FATAL("error adding threaded client");

    }

  }

  llmp_broker_run(broker);

}

