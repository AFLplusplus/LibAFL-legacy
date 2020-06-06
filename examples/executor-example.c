#include "libaflpp.h"

typedef struct example_executor {
    afl_executor_t super;
    char target[100];    

} example_executor;

int run_target(afl_executor_t * executor) {

    example_executor * child_executor = (example_executor *)executor;
    int status;

    pid_t x = fork();

    if (!x) {
        // Child process
        execv(child_executor->target, NULL);
    }

    //Parent process
    if (waitpid(x, &status,0) < 0) exit(1);

    return 0;

}

void write_testcase(afl_executor_t * executor) {

    afl_queue_entry_t * queue_entry = executor->current_input;

    FILE * f = fopen(queue_entry->file_name, O_RDWR);

    char s[100] = "This is a sample testcase";

    fwrite(f, 1, 25, f);

    fclose(f);

    return;
}


int main(int argc, char ** argv) {

    example_executor * executor = malloc(sizeof(example_executor));

    afl_queue_entry_t * entry = malloc(sizeof(afl_queue_entry_t));
    char fname[100];
    memset(fname, 0, 100);

    memcpy(fname, "testcase", 8);
    entry->file_name = fname;

    executor->super.current_input = entry;
    memcpy(executor->target, "target", 6);

    executor->super.executor_ops.place_input_cb = &write_testcase;
    executor->super.executor_ops.run_target_cb = &run_target;

    fuzz_start((afl_executor_t *)executor);

}
