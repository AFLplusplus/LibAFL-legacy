#include "common.h"
#include "list.h"

typedef struct monitor {

  struct monitor *instance;
  list_t          engines;

  void (*handle_event)(void *object);

  struct monitor_functions *functions;

} monitor_t;

struct monitor_functions {};

