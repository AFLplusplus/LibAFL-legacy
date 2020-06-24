#include "libaflpp.h"

typedef struct test_executors {

  afl_executor_t super; //Executor struct we are "inheriting" from

  char target_name[100];  //Target to fuzz

  time_t last_exec_time;

} executor_t;

// The struct we will be using as the generic interface for the observation channel

struct obs_interface {
  afl_queue_entry_t * entry;
  time_t exec_time;
};


void init_queue_entry(afl_queue_t * queue) {
  afl_queue_entry_t * queue_entry = ck_alloc(sizeof(afl_queue_entry_t));

  queue_entry->file_name = "./testcase";

  if (!queue->queue_top) {
    queue->queue_top = queue_entry;
    queue->queue_current = queue_entry;

    return;
  }

  afl_queue_entry_t * current = queue->queue_top;

  while(true) {
    if (!(current->next_queue_entry)) {
      current->next_queue_entry = queue_entry;

      break;
    }

    current = current->next_queue_entry;

  }
  return;
}


u8 init_obs_channel(afl_observation_channel_t * obs_channel) {
  afl_queue_entry_t * current = obs_channel->queue->queue_top;

  struct obs_interface interface[20] = (struct obs_interface *)obs_channel->interface;

  int i = 0;

  while (true) {

    interface[1].entry = current;

    if (!current->next_queue_entry) return 0;

    i++;
    current = current->next_queue_entry;

  }

  return 1;

}

u8 pre_run_call(afl_observation_channel_t * obs_channel) {

  // We're dealing with timeout observation here, so leaving this function out for now.
  return 0;

}

u8 post_run_call(afl_observation_channel_t * obs_channel) {
  // whatever result we gathered from the executor, we mmodify the observation channel here.
  
  executor_t * executor = (executor_t *)obs_channel->queue->executor;
  afl_queue_entry_t * current = obs_channel->queue->queue_current;

  struct obs_interface  * interface = (struct obs_interface *)obs_channel->interface;

  for (int i = 0; i < 20; i++) {
    if (current == interface[i].entry) {
      interface[i].exec_time = executor->last_exec_time;

      break;
    }

    current = current->next_queue_entry;

  }
  
  return 0;

}


u8 place_inputs(afl_executor_t * super, u8 * mem, size_t len) {
  // Write the data to the file present in current queue entry

  FILE * f = fopen(super->current_input->file_name, "w+");
  if (!f) return 1; //Signal that file opening failed

  int ret = fwrite(mem, 1, len, f);

  fclose(f);

  if (!ret) return 1; //Shows error on writing

  super->current_input->len = ret;

  return 0;

}

u8 run_target(afl_executor_t * super, u32 opt_one, void * opt_two) {
  //Here we simply execute the target and fill up the observation channel and stuff

  executor_t * executor = (executor_t *)super;  //Since the super is the first item on the struct, this typecast is valid due to C standards

  pid_t child_pid = fork();
  int status;
  time_t start_time = time(0x0);  

  if (!child_pid) {
    // Child process

    execve(executor->target_name, NULL, NULL);

    return 1; // If execve fails, return 1

  }

  waitpid(child_pid, &status, 0);

  time_t end_time = time(0x0);

  // We calculate the execution time of the target
  time_t exec_time = end_time - start_time;

  executor->last_exec_time = exec_time;

  return 0;

}

int main() {

  afl_queue_t * queue = afl_queue_init();
  queue->queue_ops->init_queue_entry = init_queue_entry;

  // Make a few queue entries

  for (int i = 0; i < 10; i++)
  {
    init_queue_entry(queue);
  }

  // As our interface for the obs channel, we have an array of above created struct
  struct obs_interface interface[20];

  afl_observation_channel_t * channel = afl_observation_init();
  channel->interface = (void *)interface;
  channel->operations->init_cb = init_obs_channel;


  executor_t * test_executor = ck_alloc(sizeof(executor_t));
  memcpy(test_executor->target_name, "target", 6);

  test_executor->super.executor_ops = ck_alloc(sizeof(afl_executor_operations_t));
  test_executor->super.executor_ops->run_target_cb = &run_target;
  test_executor->super.executor_ops->place_inputs_cb = &place_inputs;

  test_executor->super.current_input = ck_alloc(sizeof(afl_queue_entry_t));
  test_executor->super.current_input->file_name = "./testcase";

  char mem[100] = "THIS IS TEST DATA"; 

  for (int i = 0; i < 10; i++)
  {

    // We do mutations on the data here.

    test_executor->super.executor_ops->place_inputs_cb(&test_executor->super, mem, 80);

    test_executor->super.executor_ops->run_target_cb(&test_executor->super, 0, NULL);

    //Post run stuff goes here
  }
  

}

