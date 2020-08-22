# LibAFL

LibAFL is a fuzzing library/framework developed for building efficient fuzzers.

LibAFL is maintained by:
* Marc "van Hauser" Heuse mh@mh-sec.de,
* Heiko "hexcoder-" Eißfeldt heiko.eissfeldt@hexco.de,
* Andrea Fioraldi andreafioraldi@gmail.com and
* Dominik Maier mail@dmnk.co.

## Content
1. Introduction
2. Features
3. Getting Started with LibAFL

## Introduction

LibAFL is a framework to build fuzzers, with support for mutithreading. The main concept behind LibAFL is that we don't aim to build the "best" fuzzer, the best fuzzer is the fuzzer that you write for your target. We just want to give you all the pieces to do so easily and effectively.

LibAFL is supposed to be the fuzzing framework with all the pieces to build fuzzer, a sort of "LLVM of fuzzers".

LibAFL defines the different pieces of fuzzer as follows:
1. Executor - Structure to run the target and collecct observation (code coverage, exec time etc from it). An example would be the forkserver in AFL++
2. Observation Channel - Observation channel is the structure which holds the run result (depending on the context, e.g if we eant code-coverage metric or something else) for the last run.
3. Feedback - Feedback is the structure which infers valuable information from the run result stored in the observation channel. It can be used to give score to the input being fuzzed (based on the context, that is if it was looking to maximise code-coverage, execution time or something else) and also add new entries to the queue.
4. Queue - LibAFL supports two major types of queues.
    - Feedback queue - This type of queue is feedback specific i.e it is filled by entries which performed well based on a given feedback metric (say code-coverage). It also has a scheduling policy for itself which it can use to get next entries.
    - Global queue - This is the global queue for the fuzzer instance, it holds all the feedback queues, schedules one of the feedback queues for the next run. Also it has it's own queue which can also hold entries.

5. Fuzzone - This structure is inspired from AFL, with one fuzzone present in each fuzz instance, it holds all the stages of the fuzz instance and also handles the crashes/timeouts of the target.

6. Stage - There can be many fuzzing stages in a fuzzer (e.g AFL has three stages, deterministic, havoc and splicing) and each stage can have it's own mutator. Thus a fuzzer can have multiple stages depending on if it's finding new finds in the current stage (or for how long the stage has been running).

7. Mutators - Mutators have been defined to be as generic as possible with function pointers which can cover almost all mutators, (and if they don't, you can always extend them :) ). There are functions for mutating, trimming, post-process of the data which are called at appropriate places by the lib. Also, mutators also can define functions which decide if fuzzing a queue entry is beneficial or not. These mutator structures are largely inspired from AFL++ custom mutator API.

8. Engine - Finally, the engine is the central cog of the fuzzer. It binds all the other pieces(like executor, feedbacks, fuzzone) together. Every engine is also associated with a global queue, whose entries can be shared with other engine instances.

## Features

As a fuzzing library, LibAFL packs with it large number of features which are very handy for fuzzing.

1. Multithreaded in nature - Imagine that you built 2 fuzzers but want to share their results,You can define these 2 fuzzers, run the first one in a thread and run, e.g., 3 instances of the second running on 3 threads. All in the same process sharing results immediately.
There are several multithreaded fuzzers, most notably honggfuzz, but our idea is to go further and have different configurations running in different threads, not simply a multithreaded fuzzer. This leads to fuzzing the same target in multiple contexts at the same time with great efficiency!

2. Modular and pluggable - LibAFL is based on multiple "parts" that we think, consitute a fuzzer. Wrote a fuzzer and want to use it's target executor? Its' easy with LibAFL as you can just plug in the executor into the new fuzzer.

## Getting Started with LibAFL

We have an example fuzzer ready at `example/executor.c` so we can follow that. All the "parts"(described above) in LibAFL can be extended by the user to suit their needs. to extend a strucuture, just include it in your custom struct as the first member

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
executor_t example_executor = afl_executor_create(); // This function allocates memory for a "base" executor AND initializes it.

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

executor_t example_executor = afl_executor_create();
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

// Let's add it to the executor now, it gets added to an array of channels, with max number being decided by MAX_OBS_CHANNELS (default 5)
executor->funcs.add_observation_channel(executor, &tmout_base);

```

4. You probably want to build a simple feedback for the observation channel, which reduces the observation channels input to a float (0.0 to 1.0) to decide the "score" of input in the context of that observation channel (e.g more code coverage, greater execution time means higher score). This feedback also decides if an input should be put in a feedback specific queue, global queue or both.

```C
feedback_t * example feedback = afl_feedback_create(NULL);  // We can add the feedback queue instead of NULL here, but we'll add them later.

float is_interesting(feedback_t * feedback, executor_t * executor) {
    // First we grab the correct observation channel from the executor.

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
global_queue_t *global_queue = afl_global_queue_create(NULL); // NULL is for the engine, if present pass a ptr to it.

// Let's create a feedback queue, for the feedback we create above.
feedback_queue_t * feedback_queue = afl_feedback_queue_create(feedback, "Timeout feedback queue");

// Let's add it to the global queue
global_queue->extra_funcs.add_feedback_queue(feedback_queue);   // Notice how we actually use extra_funcs instead of funcs, this is because global_queue is extended from base_queue and required a few extra function pointers, thus this. 

```
It's totally upto the user to redefine the queue's scheduling algorithms (both global and feedback queue's) according to their needs



6. Let's get a few mutators running now. Each mutator is part of a fuzzing stage (like AFL has three stages, deterministic, havoc and spilcing). So, every stage has it's own mutator.
```C
mutator_t * mutator = afl_mutator_create(NULL);
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
// We add the mutator, max mutators defined as MAX_STAGE_MUTATORS (10, can be changed)
```

7. Let's create a few cogs for the fuzzer, like engine and the fuzz_one. Engine is the central part of the fuzzer which holds everything else together.

```C
fuzz_one_t * fuzz_one = afl_fuzz_one_create(NULL);
// Let's add the stage to the fuzzone

fuzz_one->funcs.add_stage(fuzz_one, stage);

engine_t * engine = afl_engine_create(executor, fuzz_one, global_queue);

```

8. We're done here. Now, we can just run the fuzzer :)

```C
engine->funcs.load_testcases_from_dir(engine, dirpath); // Load the initial corpus

engine->funcs.loop()    // Fuzzing starts :)

```
