# LibAFL

LibAFL is a fuzzing library/framework developed for building efficient fuzzers.

**Disaclaimer: LibAFL is still very WIP, likely the API will change a lot, do not use it now. However, feel free to contribute also with ideas or requests opening an issue.**

LibAFL was initially developed as GSOC project by [rishi9101](https://github.com/rish9101)
GSOC mentors: 
* [hexcoder](https://github.com/hexcoder-)
* [domenukk](https://github.com/domenukk)

## Content
1. Introduction
2. Elements of Fuzzing
3. Features
4. Getting Started with LibAFL

## Introduction

LibAFL is a framework to build fuzzers, with support for mutithreading. The main concept behind LibAFL is not to build the "best" fuzzer, but to give you the tools to craft the best fuzzer for your specific target with ease.

We write this in C so you don't have to: eventually bindings for sane languages like rust will be added.

LibAFL contains all the pieces to build fuzzers, think "LLVM of fuzzers".

## Elements of Fuzzing

LibAFL defines the pieces of fuzzer as follows (based on work by [andreafioraldi](https://github.com/andreafioraldi)):
1. *Executor* - Structure to run the target and collecct observation (code coverage, exec time, ...). One example in `./examples` uses the AFL++ forkserver, the other one an in-mem-executor.
2. *Observation Channel* - Observation channel gives information about the last run of a target, depending on the context, e.g code-coverage metric and execution time.
3. *Feedback* - Feedback is the structure which infers valuable information from the run result stored in the observation channel. It scores the input being fuzzed based on the observation channels, and adds new entries to the queue, if necessary.
4. *Queue* - LibAFL supports two major types of queues.
    - *Feedback queue* - This type of queue is feedback specific i.e it is filled by entries which performed well based on a given feedback metric (say code-coverage). It also has a scheduling policy for itself which it can use to get next entries.
    - *Global queue* - This is the global queue for the fuzzer instance, it holds all the feedback queues, schedules one of the feedback queues for the next run. Also it has it's own queue which can also hold entries.

5. *Fuzz one* - This executes the actual fuzzing - it holds all stages of the fuzz instance (see below), handles the crashes/timeouts of the target, etc.

6. *Stage* - There can be many fuzzing stages in a fuzzer (e.g AFL has three stages, deterministic, havoc and splicing) and each stage can have it's own mutators. Thus a fuzzer can have multiple stages depending on if it's finding new finds in the current stage (or for how long the stage has been running).

7. *Mutators* - Mutators have been defined to be as generic as possible with function pointers which can cover almost all mutators, (and if they don't, you can always extend them :) ). There are functions for mutating, trimming, post-process of the data which are called at appropriate places by the lib. Also, mutators also can define functions which decide if fuzzing a queue entry is beneficial or not. These mutator structures are largely inspired by AFL++'s custom mutator API.

8. *Engine* - Finally, the engine is the central cog of the fuzzer. It binds all the other pieces(like executor, feedbacks, fuzzone) together. Every engine is also associated with a global queue, whose entries can be shared with other engine instances.

## Features

As a fuzzing library, LibAFL packs with it large number of features which are very handy for fuzzing.

1. Multithreaded by nature - Imagine that you built 2 fuzzers but want to share their results,You can define these 2 fuzzers, run the first one in a thread and run, e.g., 3 instances of the second running on 3 threads. They may even share results between process boundaries with very low overhead.
There are several multithreaded fuzzers, most notably honggfuzz, but LibAFL goes even further with different configurations running in different threads and processes, not simply mutlithreading the same fuzzer. This means we are able to fuzz the same target in multiple contexts at the same time with great efficiency!

2. Modular and pluggable - LibAFL is based on multiple "parts" that we think, consitutes a fuzzer. Did you ever write a fuzzer and want to use it's target executor? Just plug in the executor into the new fuzzer with LibAFL.

## Getting Started with LibAFL

We have an example fuzzer ready at `examples/executor.c` so we can follow that.
To try it out immediately:
```bash
cd ./examples
make test
```
Other examples are listed in [./examples/README.md](./examples/README.md).

If you want to build your own fuzzer, this is how to do it:

All the "Elements" (described above) in LibAFL can be extended by the user to suit their needs. to extend a strucuture, just include it in your custom struct as the first member

```C
struct custom_executor {
    executor_t base;    // We include the base executor as the first member
    int some_extra_stuff;
    void * some_other_stuff;
}
```

Each of this structure also has a set of function pointers assigned to them (sort of like a `vtable`)
e.g 

```C
struct executor_functions {
 int (*run_target_cb)(
      executor_t *); // The first argument of each function pointer is the executor itself.
 int (*place_input_cb)(
      executor_t *,
      raw_input_t *);
}
```
So, in order to override them, you just have to take assign that function pointer to your own implementation :) (Thus, these can be easily extended) e.g 

```C

int custom_run_target(executor_t * executor) {
    /* Some Custom stuff, like a forkserver for AFL */
}

executor->funcs.run_target_cb = custom_run_target;
// We override the basic definition for run_target
```

It is not recommended to change the function signatures for these methods, as many of these function pointers are called by the library internally during fuzzing. So, if you do need some extra information for any function, it's always better to put it in an extended struct :)

The basic workflow for writing a fuzzer with LibAFL is as follows:

1. Let's decide on the input structure now. Now, this is not necessary, if raw_bytes and a length are all we need, no problem. But if your target takes a structured input (like a PNG, PDF etc), you can extend the `raw_input_t` structure to include those

2. Build a simple executor, which runs the target, places the input for the target to read. A very simple example would be an executor which `forks` and `executes` the target as a child process, also placing the input correctly (in say, stdin or a file) for target to read. AFL's forkserver is another example of an executor.

```C
// Let's build an executor.
executor_t example_executor = afl_executor_new(); // This function allocates memory for a "base" executor AND initializes it.

u8 place_input( executor_t * executor, raw_input_t * input ) {
    // We write to a file simply, this is totally user dependent
    int fd = open("some_file");
    write(fd, input->bytes, input->len);
}
exit_type_t run_target_cb(executor_t *executor) {
    pid_t child = fork();

    if (!child) {
        exec("target"); // We execute the target
    }

    return 0;

};

executor_t example_executor = afl_executor_new();
example_executor->funcs.place_input_cb = place_input
example_executor->funcs.run_target_cb = run_target;

```

3. If you're writing a greybox fuzzer, you probably want an observation channel which gains "insights" from the target's execution. An example would be the map based channel, which records the coverage (a simple map based channel is included in the library). Another observation channel could be the execution time of the target.

```C
// Let's extend the base observation channel struct to make a timeout channel

struct timeout_channel {
    observation_channel_t base;
    u64 last_run_time;
    u64 avg_exec_time;
}

// It is assumed that the observation channel is updated by the target itself (in case of coverage recording) or by the executor after running the target.

// Since we extended the structure, We allocate memory for the structure ourselves;

struct timeout_channel tmout_channel = malloc(sizeof(struct timeout_channel));

// Every structure, apart from the create function, has an init function too, which initializes the structure. You do have to initialize the rest of your extended structure yourself though.
afl_observation_channel_init(&tmout_channel->base, size_t unique_tag);

// Let's add it to the executor now, it gets added to an array of channels
executor->funcs.add_observation_channel(executor, &tmout_base);

```

4. You probably want to build a simple feedback for the observation channel, which reduces the observation channels input to a float (0.0 to 1.0) to decide the "score" of input in the context of that observation channel (e.g more code coverage, greater execution time means higher score). This feedback also decides if an input should be put in a feedback specific queue, global queue or both.

```C
feedback_t * example feedback = afl_feedback_new(NULL, timeout_channel_id);  // We can add the feedback queue instead of NULL here, but we'll add them later.

float is_interesting(feedback_t * feedback, executor_t * executor) {
    
    observation_channel_t * obs_channel = feedback->channel;
    // Every feedback "should" store the correct idx of the observation channel in the array. 
    
    //We can use the channel's unique tag to identify them. See example/executor.c for this.

    // Again completely user dependent
    if (first_condition) {
        return 0.0 
    }   else if (second_condition) {

        feedback->queue->funcs.add_to_queue(feedback->queue, executor->current_input)
        return 1.0;
    }

    return 0.5;
}

```

5. Now we create the queues for the fuzzer. If we have any feedback, and we want any feedback specific fuzzing, we can create a feedback queue and add it to the global queue. 
**But we need a global queue always.**

In case of queues, we don't expect the user to extend or do much to the queue structure itself, but the scheduling, culling etc are totally on user's choice

```C
// Let's create a global queue, one for each fuzzing "instance" we have.
global_queue_t *global_queue = afl_global_queue_new(NULL); // NULL is for the engine, if present pass a ptr to it.

// Let's create a feedback queue, for the feedback we create above.
feedback_queue_t * feedback_queue = afl_feedback_queue_new(feedback, "Timeout feedback queue");

// Let's add it to the global queue
global_queue->extra_funcs.add_feedback_queue(feedback_queue);   // Notice how we actually use extra_funcs instead of funcs, this is because global_queue is extended from base_queue and required a few extra function pointers, thus this. 

```
It's totally upto the user to redefine the queue's scheduling algorithms (both global and feedback queue's) according to their needs



6. Let's get a few mutators running now. Each mutator is part of a fuzzing stage (like AFL has three stages, deterministic, havoc and spilcing). So, every stage has it's own mutator.
```C
mutator_t * mutator = afl_mutator_new(NULL);
// We'll add it to the stage later.

void mutate(mutator_t * mutator, raw_input_t * input) {

    // Some mutation operator, bit-flip, byte flip etc.

    // We actually make a copy of the original input before sending it to mutate, so no need to worry about chaning the given input
}

void trim(mutator_t * mutator, raw_input_t * input) {
    // Trimming function for the mutator
}

mutator->funcs.mutate= mutate;
mutator->funcs.trim = trim;

fuzzing_stage_t * stage  = afl_fuzzing_stage(NULL);
// This is a fuzzing stage(mutations and stuff) so we use fuzzing_stage structure, there can be stages without mutation and mutators. 

stage->funcs.add_mutator_to_stage(stage, mutator);
// We add the mutator
```

7. Let's create a few cogs for the fuzzer, like engine and the fuzz_one. Engine is the central part of the fuzzer which holds everything else together.

```C
fuzz_one_t * fuzz_one = afl_fuzz_one_new(NULL);
// Let's add the stage to the fuzzone

fuzz_one->funcs.add_stage(fuzz_one, stage);

engine_t * engine = afl_engine_new(executor, fuzz_one, global_queue);

```

8. We're done here. Now, we can just run the fuzzer :)

```C
engine->funcs.load_testcases_from_dir(engine, dirpath); // Load the initial corpus

engine->funcs.loop()    // Fuzzing starts :)

```

Enjoy!
