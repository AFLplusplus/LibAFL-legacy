use ::libc;
extern "C" {
    #[no_mangle]
    static mut stdout: *mut _IO_FILE;
    #[no_mangle]
    static mut stderr: *mut _IO_FILE;
    #[no_mangle]
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn kill(__pid: __pid_t, __sig: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn sigemptyset(__set: *mut sigset_t) -> libc::c_int;
    #[no_mangle]
    fn sigaction(__sig: libc::c_int, __act: *const sigaction,
                 __oact: *mut sigaction) -> libc::c_int;
    #[no_mangle]
    fn waitpid(__pid: __pid_t, __stat_loc: *mut libc::c_int,
               __options: libc::c_int) -> __pid_t;
    #[no_mangle]
    fn afl_entry_init(_: *mut afl_entry_t, _: *mut afl_input_t,
                      _: *mut afl_entry_info_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_queue_feedback_init(_: *mut afl_queue_feedback_t,
                               _: *mut afl_feedback_t, _: *mut libc::c_char)
     -> afl_ret_t;
    // "constructor" for the above feedback queue
    #[no_mangle]
    fn afl_queue_feedback_deinit(_: *mut afl_queue_feedback_t);
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    #[no_mangle]
    fn usleep(__useconds: __useconds_t) -> libc::c_int;
    #[no_mangle]
    fn dup2(__fd: libc::c_int, __fd2: libc::c_int) -> libc::c_int;
    /* Get unix time in microseconds */
    #[no_mangle]
    fn afl_get_cur_time() -> u64_0;
    /* Get unix time in seconds */
    #[no_mangle]
    fn afl_get_cur_time_s() -> u64_0;
    /* returns true, if the given dir exists, else false */
    #[no_mangle]
    fn afl_dir_exists(dirpath: *mut libc::c_char) -> bool;
    #[no_mangle]
    fn afl_shmem_by_str(shm: *mut afl_shmem_t, shm_str: *mut libc::c_char,
                        map_size: size_t) -> *mut u8_0;
    #[no_mangle]
    fn afl_shmem_deinit(sharedmem: *mut afl_shmem_t);
    // Functions to initialize and delete a map based observation channel
    #[no_mangle]
    fn afl_observer_covmap_init(_: *mut afl_observer_covmap_t,
                                map_size: size_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_observer_covmap_deinit(_: *mut afl_observer_covmap_t);
    #[no_mangle]
    fn afl_input_init(input: *mut afl_input_t) -> afl_ret_t;
    /* Write the contents of the input to a timeoutfile */
    #[no_mangle]
    fn afl_input_dump_to_timeoutfile(data: *mut afl_input_t,
                                     _: *mut libc::c_char) -> afl_ret_t;
    /* Write the contents of the input which causes a crash in the target to a crashfile */
    #[no_mangle]
    fn afl_input_dump_to_crashfile(_: *mut afl_input_t, _: *mut libc::c_char)
     -> afl_ret_t;
    // "Constructors" and "destructors" for the feedback
    #[no_mangle]
    fn afl_feedback_deinit(_: *mut afl_feedback_t);
    #[no_mangle]
    fn afl_feedback_cov_init(feedback: *mut afl_feedback_cov_t,
                             queue: *mut afl_queue_feedback_t,
                             map_observer: *mut afl_observer_covmap_t)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_feedback_cov_deinit(feedback: *mut afl_feedback_cov_t);
    /* Set virgin bits according to the map passed into the func */
    #[no_mangle]
    fn afl_feedback_cov_set_virgin_bits(feedback: *mut afl_feedback_cov_t,
                                        virgin_bits_copy_from: *mut u8_0,
                                        size: size_t) -> afl_ret_t;
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    /* TODO: ADD defualt implementation for the schedule function based on random.
 */
    #[no_mangle]
    fn afl_queue_global_init(_: *mut afl_queue_global_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_queue_global_deinit(_: *mut afl_queue_global_t);
    #[no_mangle]
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...)
     -> libc::c_int;
    // afl executor_ops;
    // Function used to create an executor, we alloc the memory ourselves and
// initialize the executor
    /* Forkserver executor */
    /* executer struct to inherit from */
    /* SHM with instrumentation bitmap  */
    /* use stdin for sending data       */
    /* PID of the fork server           */
    /* PID of the fuzzed program        */
    /* waitpid result for the child     */
    /* FD of the lock file              */
    /* Persistent fd for fsrv->out_file */
    /* Fork server control pipe (write) */
    /* Fork server status pipe (read)   */
    /* Configurable exec timeout (ms)   */
    /* map size used by the target      */
    /* How often run_target was called  */
    /* File to fuzz, if any             */
    /* Path of the target               */
    /* Traced process timed out?        */
    /* Time this exec took to execute   */
    /* Signal that killed the child     */
    /* Functions related to the forkserver defined above */
    /* In-memory executor */
    /* Function ptr for the harness */
    // These are to support the libfuzzer harnesses
    // To support libfuzzer harnesses
    #[no_mangle]
    fn in_memory_executor_init(in_memory_executor: *mut in_memory_executor_t,
                               harness: harness_function_type);
    #[no_mangle]
    fn afl_executor_deinit(_: *mut afl_executor_t);
    #[no_mangle]
    fn bind_to_cpu() -> afl_ret_t;
    #[no_mangle]
    fn afl_stage_deinit(_: *mut afl_stage_t);
    #[no_mangle]
    fn afl_stage_init(_: *mut afl_stage_t, _: *mut afl_engine_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_stage_is_interesting(_: *mut afl_stage_t) -> libc::c_float;
    #[no_mangle]
    fn afl_stage_run(_: *mut afl_stage_t, _: *mut afl_input_t, _: bool)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_fuzz_one_deinit(_: *mut afl_fuzz_one_t);
    #[no_mangle]
    fn afl_fuzz_one_init(_: *mut afl_fuzz_one_t, _: *mut afl_engine_t)
     -> afl_ret_t;
    /* Creates a new, unconnected, client state */
    #[no_mangle]
    fn llmp_client_new_unconnected() -> *mut llmp_client_t;
    /* Destroys the given cient state */
    #[no_mangle]
    fn llmp_client_delete(client_state: *mut llmp_client_t);
    /* Will return a ptr to the next msg buf, potentially mapping a new page automatically, if needed.
Never call alloc_next multiple times without either sending or cancelling the last allocated message for this page!
There can only ever be up to one message allocated per page at each given time. */
    #[no_mangle]
    fn llmp_client_alloc_next(client: *mut llmp_client_t, size: size_t)
     -> *mut llmp_message_t;
    /* Cancels a msg previously allocated by alloc_next.
You can now allocate a new buffer on this page using alloc_next.
Don't write to the msg anymore, and don't send this message! */
    /* Commits a msg to the client's out buf. After this, don't  write to this msg anymore! */
    #[no_mangle]
    fn llmp_client_send(client_state: *mut llmp_client_t,
                        msg: *mut llmp_message_t) -> bool;
    /* Cancel send of the next message, this allows us to allocate a new message without sending this one. */
    #[no_mangle]
    fn llmp_client_cancel(client: *mut llmp_client_t,
                          msg: *mut llmp_message_t);
    /* Allocate and set up the new broker instance. Afterwards, run with broker_run. */
    #[no_mangle]
    fn llmp_broker_init(broker: *mut llmp_broker_t) -> afl_ret_t;
    /* Register a new forked/child client.
Client thread will be called with llmp_client_t client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also be added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
    #[no_mangle]
    fn llmp_broker_register_childprocess_clientloop(broker:
                                                        *mut llmp_broker_t,
                                                    clientloop:
                                                        llmp_clientloop_func,
                                                    data: *mut libc::c_void)
     -> bool;
    /* launch a specific client. This function is rarely needed - all registered clients will get launched at broker_run */
    #[no_mangle]
    fn llmp_broker_launch_client(broker: *mut llmp_broker_t,
                                 clientdata: *mut llmp_broker_clientdata_t)
     -> bool;
    /* Kicks off all threaded clients in the brackground, using pthreads */
    #[no_mangle]
    fn llmp_broker_launch_clientloops(broker: *mut llmp_broker_t) -> bool;
    /* Register a simple tcp client that will listen for new shard map clients via
 tcp */
    #[no_mangle]
    fn llmp_broker_register_local_server(broker: *mut llmp_broker_t,
                                         port: libc::c_int) -> bool;
    /* Adds a hook that gets called for each new message the broker touches.
if the callback returns false, the message is not forwarded to the clients. */
    #[no_mangle]
    fn llmp_broker_add_message_hook(broker: *mut llmp_broker_t,
                                    hook: Option<llmp_message_hook_func>,
                                    data: *mut libc::c_void) -> afl_ret_t;
    /* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
    #[no_mangle]
    fn llmp_broker_once(broker: *mut llmp_broker_t);
    // Not sure about this functions
                                            // use-case. Was in FFF though.
    #[no_mangle]
    fn afl_engine_init(_: *mut afl_engine_t, _: *mut afl_executor_t,
                       _: *mut afl_fuzz_one_t, _: *mut afl_queue_global_t)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_engine_deinit(_: *mut afl_engine_t);
    #[no_mangle]
    fn afl_mutator_scheduled_add_havoc_funcs(mutator:
                                                 *mut afl_mutator_scheduled_t)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_mutator_scheduled_init(sched_mut: *mut afl_mutator_scheduled_t,
                                  engine: *mut afl_engine_t,
                                  max_iterations: size_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_mutator_scheduled_deinit(_: *mut afl_mutator_scheduled_t);
    #[no_mangle]
    fn LLVMFuzzerTestOneInput(_: *const uint8_t, _: size_t) -> libc::c_int;
    #[no_mangle]
    fn LLVMFuzzerInitialize(argc: *mut libc::c_int,
                            argv: *mut *mut *mut libc::c_char) -> libc::c_int;
    /* That's where the target's intrumentation feedback gets reported to */
    #[no_mangle]
    static mut __afl_area_ptr: *mut u8_0;
    #[no_mangle]
    static mut __afl_map_size: u32_0;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __clock_t = libc::c_long;
pub type __useconds_t = libc::c_uint;
pub type __ssize_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub __pad1: *mut libc::c_void,
    pub __pad2: *mut libc::c_void,
    pub __pad3: *mut libc::c_void,
    pub __pad4: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_marker {
    pub _next: *mut _IO_marker,
    pub _sbuf: *mut _IO_FILE,
    pub _pos: libc::c_int,
}
pub type FILE = _IO_FILE;
pub type ssize_t = __ssize_t;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type sigset_t = __sigset_t;
pub type pthread_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub union sigval {
    pub sival_int: libc::c_int,
    pub sival_ptr: *mut libc::c_void,
}
pub type __sigval_t = sigval;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct siginfo_t {
    pub si_signo: libc::c_int,
    pub si_errno: libc::c_int,
    pub si_code: libc::c_int,
    pub __pad0: libc::c_int,
    pub _sifields: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub _pad: [libc::c_int; 28],
    pub _kill: C2RustUnnamed_8,
    pub _timer: C2RustUnnamed_7,
    pub _rt: C2RustUnnamed_6,
    pub _sigchld: C2RustUnnamed_5,
    pub _sigfault: C2RustUnnamed_2,
    pub _sigpoll: C2RustUnnamed_1,
    pub _sigsys: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub _call_addr: *mut libc::c_void,
    pub _syscall: libc::c_int,
    pub _arch: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub si_band: libc::c_long,
    pub si_fd: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub si_addr: *mut libc::c_void,
    pub si_addr_lsb: libc::c_short,
    pub _bounds: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub _addr_bnd: C2RustUnnamed_4,
    pub _pkey: __uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub _lower: *mut libc::c_void,
    pub _upper: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_status: libc::c_int,
    pub si_utime: __clock_t,
    pub si_stime: __clock_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_6 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_7 {
    pub si_tid: libc::c_int,
    pub si_overrun: libc::c_int,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_8 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
}
pub type __sighandler_t = Option<unsafe extern "C" fn(_: libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigaction {
    pub __sigaction_handler: C2RustUnnamed_9,
    pub sa_mask: __sigset_t,
    pub sa_flags: libc::c_int,
    pub sa_restorer: Option<unsafe extern "C" fn() -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub sa_handler: __sighandler_t,
    pub sa_sigaction: Option<unsafe extern "C" fn(_: libc::c_int,
                                                  _: *mut siginfo_t,
                                                  _: *mut libc::c_void)
                                 -> ()>,
}
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
/* This file includes return codes for libafl. */
/* Shorthand to check for RET_SUCCESS */
/* If expr != AFL_RET_SUCCESS, run block, error is in err. Return from here will return the parent func */
/* Shorthand to check for RET_SUCCESS and assign to ret */
pub type afl_ret = libc::c_uint;
pub const AFL_RET_EMPTY: afl_ret = 20;
pub const AFL_RET_ERROR_INPUT_COPY: afl_ret = 19;
pub const AFL_RET_TRIM_FAIL: afl_ret = 18;
pub const AFL_RET_NO_FUZZ_WORKERS: afl_ret = 17;
pub const AFL_RET_ERROR_INITIALIZE: afl_ret = 16;
pub const AFL_RET_QUEUE_ENDS: afl_ret = 15;
pub const AFL_RET_WRITE_TO_CRASH: afl_ret = 14;
pub const AFL_RET_NULL_QUEUE_ENTRY: afl_ret = 13;
pub const AFL_RET_ERRNO: afl_ret = 12;
pub const AFL_RET_NULL_PTR: afl_ret = 11;
pub const AFL_RET_BROKEN_TARGET: afl_ret = 10;
pub const AFL_RET_EXEC_ERROR: afl_ret = 9;
pub const AFL_RET_ARRAY_END: afl_ret = 8;
pub const AFL_RET_SHORT_WRITE: afl_ret = 7;
pub const AFL_RET_SHORT_READ: afl_ret = 6;
pub const AFL_RET_FILE_SIZE: afl_ret = 5;
pub const AFL_RET_FILE_OPEN_ERROR: afl_ret = 4;
pub const AFL_RET_ALLOC: afl_ret = 3;
pub const AFL_RET_FILE_DUPLICATE: afl_ret = 2;
pub const AFL_RET_UNKNOWN_ERROR: afl_ret = 1;
pub const AFL_RET_SUCCESS: afl_ret = 0;
pub type afl_ret_t = afl_ret;
/*
   american fuzzy lop++ - type definitions and minor macros
   --------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */
pub type u8_0 = uint8_t;
pub type u16_0 = uint16_t;
pub type u32_0 = uint32_t;
/* Extended forkserver option values */
/* Reporting errors */
/* Reporting options */
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
pub type u64_0 = libc::c_ulonglong;
pub type s32 = int32_t;
pub type s64 = int64_t;
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0



 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_fuzz_one {
    pub engine: *mut afl_engine_t,
    pub stages: *mut *mut afl_stage_t,
    pub stages_count: size_t,
    pub funcs: afl_fuzz_one_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_fuzz_one_funcs {
    pub perform: Option<unsafe extern "C" fn(_: *mut afl_fuzz_one_t)
                            -> afl_ret_t>,
    pub add_stage: Option<unsafe extern "C" fn(_: *mut afl_fuzz_one_t,
                                               _: *mut afl_stage_t)
                              -> afl_ret_t>,
    pub set_engine: Option<unsafe extern "C" fn(_: *mut afl_fuzz_one_t,
                                                _: *mut afl_engine_t)
                               -> afl_ret_t>,
}
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */
/* This file contains commonly used functionality for libafl */
// We're declaring a few structs here which have an interdependency between them
pub type afl_engine_t = afl_engine;
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   The Engine is the main and central part of the fuzzer. It contains the
   queues, feedbacks, executor and the fuzz_one (which in turn has stages)

 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_engine {
    pub fuzz_one: *mut afl_fuzz_one_t,
    pub global_queue: *mut afl_queue_global_t,
    pub executor: *mut afl_executor_t,
    pub current_feedback_queue: *mut afl_queue_feedback_t,
    pub feedbacks: *mut *mut afl_feedback_t,
    pub executions: u64_0,
    pub start_time: u64_0,
    pub last_update: u64_0,
    pub crashes: u64_0,
    pub feedbacks_count: u64_0,
    pub id: u32_0,
    pub verbose: u8_0,
    pub cpu_bound: s32,
    pub in_dir: *mut libc::c_char,
    pub rand: afl_rand_t,
    pub buf: *mut u8_0,
    pub funcs: afl_engine_func,
    pub llmp_client: *mut llmp_client_t,
}
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
// for sharedmem
/* We'll start of with 256 megabyte per fuzzer */
/* What byte count llmp messages should be aligned to */
/* llmp tags */
/* Storage class for hooks used at various places in llmp. */
/* The actual message.
    Sender is the original client id.
    The buf can be cast to any content.
    Once committed, this should not be touched again. */
/* Tag is the (unique) tag of a message.
  It should be unique per application and version */
/* the sender's id */
/* unique id for this msg */
/* the length of the payload, as requested by the caller */
/* the actual length of the payload, including padding to the next msg */
/* the content (syntax needs c99) */
/* A sharedmap page, used for unidirectional data flow.
   After a new message is added, current_msg_id should be set to the messages'
   unique id. Will then be read by the connected clients. If the page is full, a
   LLMP_TAG_END_OF_PAGE_V1 packet must be placed. In case of the broker, the
   sharedmap id of the next page must be included. The connected clients will
   instead reuse the ring buffer. Each client page needs to be large enough for
   the broker to consume all messages in the given time. Only the sender should
   ever write to this, and never remove anything.
*/
/* who sends messages to this page */
/* The only variable that may be written to by the _receiver_:
  On first message receive, save_to_unmap is set to 1. This means that
  the sender can unmap this page after EOP, on exit, ...
  Using u32 for a bool as it feels more aligned. */
/* If true, client died. :( */
/* The id of the last finished message */
/* Total size of the page */
/* How much of the page we already used */
/* The largest allocated element so far */
/* The messages start here. They can be of variable size, so don't address
   * them by array. */
/* For the client: state (also used as metadata by broker) */
pub type llmp_client_t = llmp_client;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_client {
    pub id: u32_0,
    pub last_msg_recvd: *mut llmp_message_t,
    pub current_broadcast_map: *mut afl_shmem_t,
    pub last_msg_sent: *mut llmp_message_t,
    pub out_map_count: size_t,
    pub out_maps: *mut afl_shmem_t,
    pub new_out_page_hook_count: size_t,
    pub new_out_page_hooks: *mut llmp_hookdata_t,
}
pub type llmp_hookdata_t = llmp_hookdata_generic;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_hookdata_generic {
    pub func: *mut libc::c_void,
    pub data: *mut libc::c_void,
}
/* unique ID of this client */
/* the last message we received */
/* the current broadcast map to read from */
/* the last msg we sent */
/* Number of maps we're using */
/* The maps to write to */
/* Count of the hooks we'll call for each new shared map */
/* The hooks we'll call for each new shared map */
// A generic sharememory region to be used by any functions (queues or feedbacks
// too.)
pub type afl_shmem_t = afl_shmem;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_shmem {
    pub shm_str: [libc::c_char; 20],
    pub shm_id: libc::c_int,
    pub map: *mut u8_0,
    pub map_size: size_t,
}
pub type llmp_message_t = llmp_message;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct llmp_message {
    pub tag: u32_0,
    pub sender: u32_0,
    pub message_id: u32_0,
    pub buf_len: size_t,
    pub buf_len_padded: size_t,
    pub buf: [u8_0; 0],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_engine_func {
    pub get_queue: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                              -> *mut afl_queue_global_t>,
    pub get_fuzz_one: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                                 -> *mut afl_fuzz_one_t>,
    pub get_execs: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                              -> u64_0>,
    pub get_start_time: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                                   -> u64_0>,
    pub set_fuzz_one: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                                  _: *mut afl_fuzz_one_t)
                                 -> ()>,
    pub add_feedback: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                                  _: *mut afl_feedback_t)
                                 -> afl_ret_t>,
    pub set_global_queue: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                                      _:
                                                          *mut afl_queue_global_t)
                                     -> ()>,
    pub execute: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                             _: *mut afl_input_t) -> u8_0>,
    pub handle_new_message: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                                        _:
                                                            *mut llmp_message_t)
                                       -> afl_ret_t>,
    pub load_testcases_from_dir: Option<unsafe extern "C" fn(_:
                                                                 *mut afl_engine_t,
                                                             _:
                                                                 *mut libc::c_char)
                                            -> afl_ret_t>,
    pub load_zero_testcase: Option<unsafe extern "C" fn(_: size_t) -> ()>,
    pub loop_0: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                           -> afl_ret_t>,
}
/* Serialized map id */
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */
pub type afl_input_t = afl_input;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_input {
    pub bytes: *mut u8_0,
    pub len: size_t,
    pub copy_buf: *mut u8_0,
    pub funcs: afl_input_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_input_funcs {
    pub deserialize: Option<unsafe extern "C" fn(_: *mut afl_input_t,
                                                 _: *mut u8_0, _: size_t)
                                -> ()>,
    pub serialize: Option<unsafe extern "C" fn(_: *mut afl_input_t)
                              -> *mut u8_0>,
    pub copy: Option<unsafe extern "C" fn(_: *mut afl_input_t)
                         -> *mut afl_input_t>,
    pub restore: Option<unsafe extern "C" fn(_: *mut afl_input_t,
                                             _: *mut afl_input_t) -> ()>,
    pub load_from_file: Option<unsafe extern "C" fn(_: *mut afl_input_t,
                                                    _: *mut libc::c_char)
                                   -> afl_ret_t>,
    pub save_to_file: Option<unsafe extern "C" fn(_: *mut afl_input_t,
                                                  _: *mut libc::c_char)
                                 -> afl_ret_t>,
    pub clear: Option<unsafe extern "C" fn(_: *mut afl_input_t) -> ()>,
    pub get_bytes: Option<unsafe extern "C" fn(_: *mut afl_input_t)
                              -> *mut u8_0>,
    pub delete: Option<unsafe extern "C" fn(_: *mut afl_input_t) -> ()>,
}
pub type afl_queue_global_t = afl_queue_global;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue_global {
    pub base: afl_queue_t,
    pub feedback_queues: *mut *mut afl_queue_feedback_t,
    pub feedback_queues_count: size_t,
    pub funcs: afl_queue_global_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue_global_funcs {
    pub schedule: Option<unsafe extern "C" fn(_: *mut afl_queue_global_t)
                             -> libc::c_int>,
    pub add_feedback_queue: Option<unsafe extern "C" fn(_:
                                                            *mut afl_queue_global_t,
                                                        _:
                                                            *mut afl_queue_feedback_t)
                                       -> afl_ret_t>,
}
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */
pub type afl_queue_feedback_t = afl_queue_feedback;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue_feedback {
    pub base: afl_queue_t,
    pub feedback: *mut afl_feedback_t,
    pub name: *mut libc::c_char,
}
pub type afl_feedback_t = afl_feedback;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_feedback {
    pub queue: *mut afl_queue_feedback_t,
    pub funcs: afl_feedback_funcs,
    pub tag: u32_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_feedback_funcs {
    pub is_interesting: Option<unsafe extern "C" fn(_: *mut afl_feedback_t,
                                                    _: *mut afl_executor_t)
                                   -> libc::c_float>,
    pub set_feedback_queue: Option<unsafe extern "C" fn(_:
                                                            *mut afl_feedback_t,
                                                        _:
                                                            *mut afl_queue_feedback_t)
                                       -> ()>,
    pub get_feedback_queue: Option<unsafe extern "C" fn(_:
                                                            *mut afl_feedback_t)
                                       -> *mut afl_queue_feedback_t>,
}
pub type afl_executor_t = afl_executor;
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */
/*
This is the generic forkserver interface that we have, in order to use the
library to build something, agin "inherit" from this struct (yes, we'll be
trying OO design principles here :D) and then extend adding your own fields to
it. See the example forksever executor that we have in examples/
*/
// can be NULL
// can be NULL
// Similar to afl_fsrv_run_target we have in afl
// similar to the write_to_testcase function in afl.
// Add an observtion channel to the list
// Getter function for the current input
// Reset the observation channels
// This is like the generic vtable for the executor.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_executor {
    pub observors: *mut *mut afl_observer_t,
    pub observors_count: u32_0,
    pub current_input: *mut afl_input_t,
    pub funcs: afl_executor_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_executor_funcs {
    pub init_cb: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                            -> afl_ret_t>,
    pub destroy_cb: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                               -> u8_0>,
    pub run_target_cb: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                                  -> afl_exit_t>,
    pub place_input_cb: Option<unsafe extern "C" fn(_: *mut afl_executor_t,
                                                    _: *mut afl_input_t)
                                   -> u8_0>,
    pub observer_add: Option<unsafe extern "C" fn(_: *mut afl_executor_t,
                                                  _: *mut afl_observer_t)
                                 -> afl_ret_t>,
    pub input_get: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                              -> *mut afl_input_t>,
    pub observers_reset: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                                    -> ()>,
}
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */
pub type afl_observer_t = afl_observer;
// vtable for the observation channel
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_observer {
    pub tag: u32_0,
    pub funcs: afl_observer_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_observer_funcs {
    pub flush: Option<unsafe extern "C" fn(_: *mut afl_observer_t) -> ()>,
    pub reset: Option<unsafe extern "C" fn(_: *mut afl_observer_t) -> ()>,
    pub post_exec: Option<unsafe extern "C" fn(_: *mut afl_observer_t,
                                               _: *mut afl_engine_t) -> ()>,
}
// This has a few parts, the first deals with crash handling.
/* afl_exit_t is for the fuzzed target, as opposed to afl_ret_t
which is for internal functions. */
pub type afl_exit_t = afl_exit;
pub type afl_exit = libc::c_uint;
pub const AFL_EXIT_OOM: afl_exit = 9;
pub const AFL_EXIT_TIMEOUT: afl_exit = 8;
pub const AFL_EXIT_FPE: afl_exit = 7;
pub const AFL_EXIT_ILL: afl_exit = 6;
pub const AFL_EXIT_ABRT: afl_exit = 5;
pub const AFL_EXIT_BUS: afl_exit = 4;
pub const AFL_EXIT_SEGV: afl_exit = 3;
pub const AFL_EXIT_CRASH: afl_exit = 2;
pub const AFL_EXIT_STOP: afl_exit = 1;
pub const AFL_EXIT_OK: afl_exit = 0;
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */
/*
This is the generic interface implementation for the queue and queue entries.
We've tried to keep it generic and yet including, but if you want to extend the
queue/entry, simply "inherit" this struct by including it in your custom struct
and keeping it as the first member of your struct.
*/
pub type afl_queue_t = afl_queue;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue {
    pub entries: *mut *mut afl_entry_t,
    pub entries_count: size_t,
    pub base: *mut afl_entry_t,
    pub current: u64_0,
    pub engine_id: libc::c_int,
    pub engine: *mut afl_engine_t,
    pub end: *mut afl_entry_t,
    pub dirpath: [libc::c_char; 4096],
    pub names_id: size_t,
    pub save_to_files: bool,
    pub fuzz_started: bool,
    pub funcs: afl_queue_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue_funcs {
    pub insert: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                            _: *mut afl_entry_t)
                           -> afl_ret_t>,
    pub remove_from_queue: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                      -> ()>,
    pub get: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                        -> *mut afl_entry_t>,
    pub get_next_in_queue: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                                       _: libc::c_int)
                                      -> *mut afl_entry_t>,
    pub get_queue_entry: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                                     _: u32_0)
                                    -> *mut afl_entry_t>,
    pub get_queue_base: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                   -> *mut afl_entry_t>,
    pub get_size: Option<unsafe extern "C" fn(_: *mut afl_queue_t) -> size_t>,
    pub get_dirpath: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                -> *mut libc::c_char>,
    pub get_names_id: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                 -> size_t>,
    pub get_save_to_files: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                      -> bool>,
    pub set_dirpath: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                                 _: *mut libc::c_char) -> ()>,
    pub set_engine: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                                _: *mut afl_engine_t) -> ()>,
}
pub type afl_entry_t = afl_entry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_entry {
    pub info: *mut afl_entry_info_t,
    pub input: *mut afl_input_t,
    pub map: *mut u8_0,
    pub on_disk: bool,
    pub info_calloc: bool,
    pub filename: [libc::c_char; 4120],
    pub queue: *mut afl_queue,
    pub next: *mut afl_entry,
    pub prev: *mut afl_entry,
    pub parent: *mut afl_entry,
    pub funcs: afl_entry_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_entry_funcs {
    pub get_input: Option<unsafe extern "C" fn(_: *mut afl_entry_t)
                              -> *mut afl_input_t>,
    pub is_on_disk: Option<unsafe extern "C" fn(_: *mut afl_entry_t) -> bool>,
    pub get_next: Option<unsafe extern "C" fn(_: *mut afl_entry_t)
                             -> *mut afl_entry_t>,
    pub get_prev: Option<unsafe extern "C" fn(_: *mut afl_entry_t)
                             -> *mut afl_entry_t>,
    pub get_parent: Option<unsafe extern "C" fn(_: *mut afl_entry_t)
                               -> *mut afl_entry_t>,
    pub get_child: Option<unsafe extern "C" fn(_: *mut afl_entry_t, _: size_t)
                              -> *mut afl_entry_t>,
}
/*TODO: Still need to add a base implementation for this.*/
pub type afl_entry_info_t = afl_entry_info;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct afl_entry_info {
    pub hash: u64_0,
    pub exec_us: u64_0,
    pub bytes_set: u32_0,
    pub bits_set: u32_0,
    pub trimmed: u8_0,
    pub has_new_coverage: u8_0,
    pub variable: u8_0,
    pub skip_entry: u8_0,
}
pub type afl_fuzz_one_t = afl_fuzz_one;
pub type afl_rand_t = afl_rand;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_rand {
    pub rand_cnt: u32_0,
    pub rand_seed: [u64_0; 4],
    pub dev_urandom_fd: s32,
    pub init_seed: s64,
    pub fixed_seed: bool,
}
pub type afl_stage_t = afl_stage;
/* Random number counter*/
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */
// A function which tells how many mutated
                                       // inputs to generate out of a given input
/* Change the void pointer to a mutator * once it is ready */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_stage {
    pub engine: *mut afl_engine_t,
    pub funcs: afl_stage_funcs,
    pub mutators: *mut *mut afl_mutator_t,
    pub mutators_count: size_t,
}
pub type afl_mutator_t = afl_mutator;
/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0


 */
// Mutator struct will have many internal functions like mutate, trimming etc.
// This is based on both the FFF prototype and the custom mutators that we have
// in AFL++ without the AFL++ specific parts
// The params here are in_buf and out_buf.
// Mutate function
// Checks if the queue entry is to be fuzzed or not
// Post process API AFL++
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_mutator {
    pub engine: *mut afl_engine_t,
    pub mutate_buf: *mut u8_0,
    pub funcs: afl_mutator_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_mutator_funcs {
    pub init: Option<unsafe extern "C" fn(_: *mut afl_mutator_t) -> ()>,
    pub trim: Option<unsafe extern "C" fn(_: *mut afl_mutator_t,
                                          _: *mut afl_input_t) -> size_t>,
    pub mutate: Option<unsafe extern "C" fn(_: *mut afl_mutator_t,
                                            _: *mut afl_input_t) -> size_t>,
    pub custom_queue_get: Option<unsafe extern "C" fn(_: *mut afl_mutator_t,
                                                      _: *mut afl_input_t)
                                     -> afl_ret_t>,
    pub custom_queue_new_entry: Option<unsafe extern "C" fn(_:
                                                                *mut afl_mutator_t,
                                                            _:
                                                                *mut afl_entry_t)
                                           -> ()>,
    pub post_process: Option<unsafe extern "C" fn(_: *mut afl_mutator_t,
                                                  _: *mut afl_input_t) -> ()>,
    pub get_stage: Option<unsafe extern "C" fn(_: *mut afl_mutator_t)
                              -> *mut afl_stage_t>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_stage_funcs {
    pub perform: Option<unsafe extern "C" fn(_: *mut afl_stage_t,
                                             _: *mut afl_input_t)
                            -> afl_ret_t>,
    pub get_iters: Option<unsafe extern "C" fn(_: *mut afl_stage_t)
                              -> size_t>,
    pub add_mutator_to_stage: Option<unsafe extern "C" fn(_: *mut afl_stage_t,
                                                          _:
                                                              *mut afl_mutator_t)
                                         -> afl_ret_t>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_observer_covmap {
    pub base: afl_observer_t,
    pub shared_map: afl_shmem_t,
    pub funcs: afl_observer_covmap_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_observer_covmap_funcs {
    pub get_trace_bits: Option<unsafe extern "C" fn(_:
                                                        *mut afl_observer_covmap_t)
                                   -> *mut u8_0>,
    pub get_map_size: Option<unsafe extern "C" fn(_:
                                                      *mut afl_observer_covmap_t)
                                 -> size_t>,
}
pub type afl_observer_covmap_t = afl_observer_covmap;
/* Simple MaximizeMapFeedback implementation */
/* Coverage Feedback */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_feedback_cov {
    pub base: afl_feedback_t,
    pub observer_cov: *mut afl_observer_covmap_t,
    pub virgin_bits: *mut u8_0,
    pub size: size_t,
}
pub type afl_feedback_cov_t = afl_feedback_cov;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_broker_state {
    pub last_msg_sent: *mut llmp_message_t,
    pub broadcast_map_count: size_t,
    pub broadcast_maps: *mut afl_shmem_t,
    pub msg_hook_count: size_t,
    pub msg_hooks: *mut llmp_hookdata_t,
    pub llmp_client_count: size_t,
    pub llmp_clients: *mut llmp_broker_clientdata_t,
}
pub type llmp_broker_clientdata_t = llmp_broker_client_metadata;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_broker_client_metadata {
    pub client_type: LLMP_CLIENT_TYPE,
    pub client_state: *mut llmp_client_t,
    pub cur_client_map: *mut afl_shmem_t,
    pub last_msg_broker_read: *mut llmp_message_t,
    pub pthread: *mut pthread_t,
    pub pid: libc::c_int,
    pub clientloop: llmp_clientloop_func,
    pub engine: *mut afl_engine_t,
    pub data: *mut libc::c_void,
}
pub type llmp_clientloop_func
    =
    Option<unsafe extern "C" fn(_: *mut llmp_client_t, _: *mut libc::c_void)
               -> ()>;
pub type LLMP_CLIENT_TYPE = libc::c_uint;
pub const LLMP_CLIENT_TYPE_FOREIGN_PROCESS: LLMP_CLIENT_TYPE = 3;
pub const LLMP_CLIENT_TYPE_CHILD_PROCESS: LLMP_CLIENT_TYPE = 2;
pub const LLMP_CLIENT_TYPE_PTHREAD: LLMP_CLIENT_TYPE = 1;
pub const LLMP_CLIENT_TYPE_UNKNOWN: LLMP_CLIENT_TYPE = 0;
pub type llmp_broker_t = llmp_broker_state;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct llmp_page {
    pub sender: u32_0,
    pub save_to_unmap: u16_0,
    pub sender_dead: u16_0,
    pub current_msg_id: size_t,
    pub size_total: size_t,
    pub size_used: size_t,
    pub max_alloc_size: size_t,
    pub messages: [llmp_message_t; 0],
}
pub type llmp_page_t = llmp_page;
pub type llmp_message_hook_func
    =
    unsafe extern "C" fn(_: *mut llmp_broker_t,
                         _: *mut llmp_broker_clientdata_t,
                         _: *mut llmp_message_t, _: *mut libc::c_void)
        -> bool;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_mutator_scheduled {
    pub base: afl_mutator_t,
    pub mutations: *mut afl_mutator_func,
    pub mutators_count: size_t,
    pub funcs: afl_mutator_scheduled_funcs,
    pub max_iterations: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_mutator_scheduled_funcs {
    pub schedule: Option<unsafe extern "C" fn(_: *mut afl_mutator_scheduled_t)
                             -> size_t>,
    pub add_func: Option<unsafe extern "C" fn(_: *mut afl_mutator_scheduled_t,
                                              _: afl_mutator_func)
                             -> afl_ret_t>,
    pub add_default_funcs: Option<unsafe extern "C" fn(_:
                                                           *mut afl_mutator_scheduled_t)
                                      -> afl_ret_t>,
    pub get_iters: Option<unsafe extern "C" fn(_:
                                                   *mut afl_mutator_scheduled_t)
                              -> size_t>,
}
pub type afl_mutator_scheduled_t = afl_mutator_scheduled;
pub type afl_mutator_func
    =
    Option<unsafe extern "C" fn(_: *mut afl_mutator_t, _: *mut afl_input_t)
               -> ()>;
pub type harness_function_type
    =
    Option<unsafe extern "C" fn(_: *mut afl_executor_t, _: *mut u8_0,
                                _: size_t) -> afl_exit_t>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_memory_executor {
    pub base: afl_executor_t,
    pub harness: harness_function_type,
    pub argv: *mut *mut libc::c_char,
    pub argc: libc::c_int,
    pub stage: *mut afl_stage_t,
    pub global_queue: *mut afl_queue_global_t,
}
pub type in_memory_executor_t = in_memory_executor;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cur_state {
    pub calibration_idx: ssize_t,
    pub new_execs: u64_0,
    pub map_size: size_t,
    pub current_input_len: size_t,
    pub payload: [u8_0; 0],
}
pub type cur_state_t = cur_state;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct broker_client_stats {
    pub total_execs: u64_0,
    pub crashes: u64_0,
    pub last_msg_time: u32_0,
}
/* Stats message the client will send every once in a while */
pub type broker_client_stats_t = broker_client_stats;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fuzzer_stats {
    pub queue_entry_count: u64_0,
    pub crashes: u64_0,
    pub timeouts: u64_0,
    pub clients: *mut broker_client_stats,
}
/* all stats about the current run */
pub type fuzzer_stats_t = fuzzer_stats;
#[inline]
unsafe extern "C" fn afl_entry_new(mut input: *mut afl_input_t,
                                   mut info: *mut afl_entry_info_t)
 -> *mut afl_entry_t {
    let mut ret: *mut afl_entry_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_entry_t>() as libc::c_ulong) as
            *mut afl_entry_t;
    if ret.is_null() { return 0 as *mut afl_entry_t }
    if afl_entry_init(ret, input, info) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_entry_t
    }
    return ret;
}
/* Returns a string representation of afl_ret_t or of the errno if applicable */
#[inline]
unsafe extern "C" fn afl_ret_stringify(mut afl_ret: afl_ret_t)
 -> *mut libc::c_char {
    let mut current_block_17: u64;
    match afl_ret as libc::c_uint {
        0 => {
            return b"Success\x00" as *const u8 as *const libc::c_char as
                       *mut libc::c_char
        }
        8 => {
            return b"No more elements in array\x00" as *const u8 as
                       *const libc::c_char as *mut libc::c_char
        }
        9 => {
            return b"Could not execute target\x00" as *const u8 as
                       *const libc::c_char as *mut libc::c_char
        }
        10 => {
            return b"Target did not behave as expected\x00" as *const u8 as
                       *const libc::c_char as *mut libc::c_char
        }
        19 => {
            return b"Error creating input copy\x00" as *const u8 as
                       *const libc::c_char as *mut libc::c_char
        }
        20 => {
            return b"Empty data\x00" as *const u8 as *const libc::c_char as
                       *mut libc::c_char
        }
        2 => {
            return b"File exists\x00" as *const u8 as *const libc::c_char as
                       *mut libc::c_char
        }
        3 => {
            if *__errno_location() == 0 {
                return b"Allocation failed\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
            current_block_17 = 5980888513698675880;
        }
        4 => { current_block_17 = 5980888513698675880; }
        6 => { current_block_17 = 10931362511637487823; }
        12 => { current_block_17 = 646501306906594405; }
        _ => {
            return b"Unknown error. Please report this bug!\x00" as *const u8
                       as *const libc::c_char as *mut libc::c_char
        }
    }
    match current_block_17 {
        5980888513698675880 =>
        /* fall-through */
        {
            if *__errno_location() == 0 {
                return b"Error opening file\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
            current_block_17 = 10931362511637487823;
        }
        _ => { }
    }
    match current_block_17 {
        10931362511637487823 =>
        /* fall-through */
        {
            if *__errno_location() == 0 {
                return b"Got less bytes than expected\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
        }
        _ => { }
    }
    /* fall-through */
    return strerror(*__errno_location());
}
#[inline]
unsafe extern "C" fn afl_argv_cpy_dup(mut argc: libc::c_int,
                                      mut argv: *mut *mut libc::c_char)
 -> *mut *mut libc::c_char {
    let mut i: libc::c_int = 0 as libc::c_int;
    let mut ret: *mut *mut libc::c_char =
        calloc(1 as libc::c_int as libc::c_ulong,
               ((argc + 1 as libc::c_int) as
                    libc::c_ulong).wrapping_mul(::std::mem::size_of::<*mut libc::c_char>()
                                                    as libc::c_ulong)) as
            *mut *mut libc::c_char;
    if ret.is_null() { return 0 as *mut *mut libc::c_char }
    i = 0 as libc::c_int;
    while i < argc {
        let ref mut fresh0 = *ret.offset(i as isize);
        *fresh0 = strdup(*argv.offset(i as isize));
        if (*ret.offset(i as isize)).is_null() {
            let mut k: libc::c_int = 0;
            k = 0 as libc::c_int;
            while k < i {
                free(*ret.offset(k as isize) as *mut libc::c_void);
                k += 1
            }
            free(ret as *mut libc::c_void);
            return 0 as *mut *mut libc::c_char
        }
        i += 1
    }
    let ref mut fresh1 = *ret.offset(i as isize);
    *fresh1 = 0 as *mut libc::c_char;
    return ret;
}
#[inline]
unsafe extern "C" fn afl_observer_covmap_new(mut map_size: size_t)
 -> *mut afl_observer_covmap_t {
    let mut ret: *mut afl_observer_covmap_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_observer_covmap_t>() as
                   libc::c_ulong) as *mut afl_observer_covmap_t;
    if ret.is_null() { return 0 as *mut afl_observer_covmap_t }
    if afl_observer_covmap_init(ret, map_size) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_observer_covmap_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_observer_covmap_delete(mut afl_observer_covmap:
                                                    *mut afl_observer_covmap_t) {
    afl_observer_covmap_deinit(afl_observer_covmap);
    free(afl_observer_covmap as *mut libc::c_void);
}
/* Function to create and destroy a new input, allocates memory and initializes
  it. In destroy, it first deinitializes the struct and then frees it. */
#[inline]
unsafe extern "C" fn afl_input_new() -> *mut afl_input_t {
    let mut ret: *mut afl_input_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_input_t>() as libc::c_ulong) as
            *mut afl_input_t;
    if ret.is_null() { return 0 as *mut afl_input_t }
    if afl_input_init(ret) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_input_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_feedback_delete(mut afl_feedback:
                                             *mut afl_feedback_t) {
    afl_feedback_deinit(afl_feedback);
    free(afl_feedback as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_feedback_cov_new(mut queue:
                                              *mut afl_queue_feedback_t,
                                          mut map_observer:
                                              *mut afl_observer_covmap_t)
 -> *mut afl_feedback_cov_t {
    let mut ret: *mut afl_feedback_cov_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_feedback_cov_t>() as libc::c_ulong)
            as *mut afl_feedback_cov_t;
    if ret.is_null() { return 0 as *mut afl_feedback_cov_t }
    if afl_feedback_cov_init(ret, queue, map_observer) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_feedback_cov_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_feedback_cov_delete(mut afl_feedback_cov:
                                                 *mut afl_feedback_cov_t) {
    afl_feedback_cov_deinit(afl_feedback_cov);
    free(afl_feedback_cov as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_queue_feedback_new(mut feedback: *mut afl_feedback_t,
                                            mut name: *mut libc::c_char)
 -> *mut afl_queue_feedback_t {
    let mut ret: *mut afl_queue_feedback_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_queue_feedback_t>() as libc::c_ulong)
            as *mut afl_queue_feedback_t;
    if ret.is_null() { return 0 as *mut afl_queue_feedback_t }
    if afl_queue_feedback_init(ret, feedback, name) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_queue_feedback_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_queue_feedback_delete(mut afl_queue_feedback:
                                                   *mut afl_queue_feedback_t) {
    afl_queue_feedback_deinit(afl_queue_feedback);
    free(afl_queue_feedback as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_queue_global_new() -> *mut afl_queue_global_t {
    let mut ret: *mut afl_queue_global_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_queue_global_t>() as libc::c_ulong)
            as *mut afl_queue_global_t;
    if ret.is_null() { return 0 as *mut afl_queue_global_t }
    if afl_queue_global_init(ret) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_queue_global_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_queue_global_delete(mut afl_queue_global:
                                                 *mut afl_queue_global_t) {
    afl_queue_global_deinit(afl_queue_global);
    free(afl_queue_global as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_executor_delete(mut afl_executor:
                                             *mut afl_executor_t) {
    afl_executor_deinit(afl_executor);
    free(afl_executor as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_stage_delete(mut afl_stage: *mut afl_stage_t) {
    afl_stage_deinit(afl_stage);
    free(afl_stage as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_stage_new(mut engine: *mut afl_engine_t)
 -> *mut afl_stage_t {
    let mut ret: *mut afl_stage_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_stage_t>() as libc::c_ulong) as
            *mut afl_stage_t;
    if ret.is_null() { return 0 as *mut afl_stage_t }
    if afl_stage_init(ret, engine) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_stage_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_fuzz_one_delete(mut afl_fuzz_one:
                                             *mut afl_fuzz_one_t) {
    afl_fuzz_one_deinit(afl_fuzz_one);
    free(afl_fuzz_one as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_fuzz_one_new(mut engine: *mut afl_engine_t)
 -> *mut afl_fuzz_one_t {
    let mut ret: *mut afl_fuzz_one_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_fuzz_one_t>() as libc::c_ulong) as
            *mut afl_fuzz_one_t;
    if ret.is_null() { return 0 as *mut afl_fuzz_one_t }
    if afl_fuzz_one_init(ret, engine) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_fuzz_one_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_rand_rotl(x: u64_0, mut k: libc::c_int) -> u64_0 {
    return x << k | x >> 64 as libc::c_int - k;
}
/* get the next random number */
#[inline]
unsafe extern "C" fn afl_rand_next(mut rnd: *mut afl_rand_t) -> u64_0 {
    let result: uint64_t =
        afl_rand_rotl((*rnd).rand_seed[0 as libc::c_int as
                                           usize].wrapping_add((*rnd).rand_seed[3
                                                                                    as
                                                                                    libc::c_int
                                                                                    as
                                                                                    usize]),
                      23 as
                          libc::c_int).wrapping_add((*rnd).rand_seed[0 as
                                                                         libc::c_int
                                                                         as
                                                                         usize])
            as uint64_t;
    let t: uint64_t =
        ((*rnd).rand_seed[1 as libc::c_int as usize] << 17 as libc::c_int) as
            uint64_t;
    (*rnd).rand_seed[2 as libc::c_int as usize] ^=
        (*rnd).rand_seed[0 as libc::c_int as usize];
    (*rnd).rand_seed[3 as libc::c_int as usize] ^=
        (*rnd).rand_seed[1 as libc::c_int as usize];
    (*rnd).rand_seed[1 as libc::c_int as usize] ^=
        (*rnd).rand_seed[2 as libc::c_int as usize];
    (*rnd).rand_seed[0 as libc::c_int as usize] ^=
        (*rnd).rand_seed[3 as libc::c_int as usize];
    (*rnd).rand_seed[2 as libc::c_int as usize] ^= t as libc::c_ulonglong;
    (*rnd).rand_seed[3 as libc::c_int as usize] =
        afl_rand_rotl((*rnd).rand_seed[3 as libc::c_int as usize],
                      45 as libc::c_int);
    return result as u64_0;
}
/* Get a message as type if tag matches, else NULL */
/* Gets the llmp page struct from this shmem map */
#[inline]
unsafe extern "C" fn shmem2page(mut afl_shmem: *mut afl_shmem_t)
 -> *mut llmp_page_t {
    return (*afl_shmem).map as *mut llmp_page_t;
}
#[inline]
unsafe extern "C" fn llmp_broker_new() -> *mut llmp_broker_t {
    let mut ret: *mut llmp_broker_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<llmp_broker_t>() as libc::c_ulong) as
            *mut llmp_broker_t;
    if ret.is_null() { return 0 as *mut llmp_broker_t }
    if llmp_broker_init(ret) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut llmp_broker_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_engine_new(mut executor: *mut afl_executor_t,
                                    mut fuzz_one: *mut afl_fuzz_one_t,
                                    mut global_queue_0:
                                        *mut afl_queue_global_t)
 -> *mut afl_engine_t {
    let mut ret: *mut afl_engine_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_engine_t>() as libc::c_ulong) as
            *mut afl_engine_t;
    if ret.is_null() { return 0 as *mut afl_engine_t }
    if afl_engine_init(ret, executor, fuzz_one, global_queue_0) as
           libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_engine_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_engine_delete(mut afl_engine: *mut afl_engine_t) {
    afl_engine_deinit(afl_engine);
    free(afl_engine as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_mutator_scheduled_new(mut engine: *mut afl_engine_t,
                                               mut max_iterations: size_t)
 -> *mut afl_mutator_scheduled_t {
    let mut ret: *mut afl_mutator_scheduled_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_mutator_scheduled_t>() as
                   libc::c_ulong) as *mut afl_mutator_scheduled_t;
    if ret.is_null() { return 0 as *mut afl_mutator_scheduled_t }
    if afl_mutator_scheduled_init(ret, engine, max_iterations) as libc::c_uint
           != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_mutator_scheduled_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_mutator_scheduled_delete(mut afl_mutator_scheduled:
                                                      *mut afl_mutator_scheduled_t) {
    afl_mutator_scheduled_deinit(afl_mutator_scheduled);
    free(afl_mutator_scheduled as *mut libc::c_void);
}
/* pointer to the bitmap used by map-absed feedback, we'll report it if we crash. */
static mut virgin_bits: *mut u8_0 = 0 as *const u8_0 as *mut u8_0;
/* The current client this process works on. We need this for our segfault handler */
static mut current_client: *mut llmp_client_t =
    0 as *const llmp_client_t as *mut llmp_client_t;
/* Ptr to the message we're trying to fuzz right now - in case we crash... */
static mut current_fuzz_input_msg: *mut llmp_message_t =
    0 as *const llmp_message_t as *mut llmp_message_t;
static mut global_queue: *mut afl_queue_global_t =
    0 as *const afl_queue_global_t as *mut afl_queue_global_t;
static mut broker_queue: *mut afl_queue_global_t =
    0 as *const afl_queue_global_t as *mut afl_queue_global_t;
static mut current_input: *mut afl_input_t =
    0 as *const afl_input_t as *mut afl_input_t;
static mut debug: libc::c_int = 0 as libc::c_int;
static mut queue_dirpath: *mut libc::c_char =
    0 as *const libc::c_char as *mut libc::c_char;
static mut calibration_idx: ssize_t = -(1 as libc::c_int) as ssize_t;
#[no_mangle]
pub unsafe extern "C" fn debug_LLVMFuzzerTestOneInput(mut data:
                                                          *const uint8_t,
                                                      mut size: size_t)
 -> libc::c_int {
    let mut i: u32_0 = 0;
    fprintf(stderr,
            b"Enter harness function %p %lu\n\x00" as *const u8 as
                *const libc::c_char, data, size);
    i = 0 as libc::c_int as u32_0;
    while i < __afl_map_size {
        if *__afl_area_ptr.offset(i as isize) != 0 {
            fprintf(stderr,
                    b"Error: map unclean before harness: map[%04x]=0x%02x\n\x00"
                        as *const u8 as *const libc::c_char, i,
                    *__afl_area_ptr.offset(i as isize) as libc::c_int);
        }
        i = i.wrapping_add(1)
    }
    let mut ret: libc::c_int = LLVMFuzzerTestOneInput(data, size);
    fprintf(stderr, b"MAP:\x00" as *const u8 as *const libc::c_char);
    i = 0 as libc::c_int as u32_0;
    while i < __afl_map_size {
        if *__afl_area_ptr.offset(i as isize) != 0 {
            fprintf(stderr,
                    b" map[%04x]=0x%02x\x00" as *const u8 as
                        *const libc::c_char, i,
                    *__afl_area_ptr.offset(i as isize) as libc::c_int);
        }
        i = i.wrapping_add(1)
    }
    fprintf(stderr, b"\n\x00" as *const u8 as *const libc::c_char);
    return ret;
}
/* The actual harness call: LLVMFuzzerTestOneInput */
#[no_mangle]
pub unsafe extern "C" fn harness_func(mut executor: *mut afl_executor_t,
                                      mut input: *mut u8_0, mut len: size_t)
 -> afl_exit_t {
    LLVMFuzzerTestOneInput(input, len);
    return AFL_EXIT_OK;
}
/* The actual harness call: LLVMFuzzerTestOneInput */
#[no_mangle]
pub unsafe extern "C" fn debug_harness_func(mut executor: *mut afl_executor_t,
                                            mut input: *mut u8_0,
                                            mut len: size_t) -> afl_exit_t {
    debug_LLVMFuzzerTestOneInput(input, len);
    return AFL_EXIT_OK;
}
/* Initializer: run initial seeds and run LLVMFuzzerInitialize */
unsafe extern "C" fn in_memory_fuzzer_initialize(mut executor:
                                                     *mut afl_executor_t)
 -> afl_ret_t {
    let mut in_memory_fuzzer: *mut in_memory_executor_t =
        executor as *mut in_memory_executor_t;
    if Some(LLVMFuzzerInitialize as
                unsafe extern "C" fn(_: *mut libc::c_int,
                                     _: *mut *mut *mut libc::c_char)
                    -> libc::c_int).is_some() {
        LLVMFuzzerInitialize(&mut (*in_memory_fuzzer).argc,
                             &mut (*in_memory_fuzzer).argv);
    }
    global_queue = (*in_memory_fuzzer).global_queue;
    if calibration_idx > 0 as libc::c_int as libc::c_long {
        if debug != 0 {
            fprintf(stderr,
                    b"\nCalibrations to check: %ld\n\x00" as *const u8 as
                        *const libc::c_char, calibration_idx);
        }
        while calibration_idx > 0 as libc::c_int as libc::c_long {
            calibration_idx -= 1;
            if debug != 0 {
                fprintf(stderr,
                        b"Seed %ld\n\x00" as *const u8 as *const libc::c_char,
                        calibration_idx);
            }
            let mut queue_entry: *mut afl_entry_t =
                (*(*in_memory_fuzzer).global_queue).base.funcs.get_queue_entry.expect("non-null function pointer")((*in_memory_fuzzer).global_queue
                                                                                                                       as
                                                                                                                       *mut afl_queue_t,
                                                                                                                   calibration_idx
                                                                                                                       as
                                                                                                                       u32_0);
            if !queue_entry.is_null() &&
                   (*(*queue_entry).info).skip_entry == 0 {
                if debug != 0 {
                    fprintf(stderr,
                            b"Seed %ld testing ...\n\x00" as *const u8 as
                                *const libc::c_char, calibration_idx);
                }
                (*(*queue_entry).info).skip_entry = 1 as libc::c_int as u8_0;
                if afl_stage_run((*in_memory_fuzzer).stage,
                                 (*queue_entry).input, 0 as libc::c_int != 0)
                       as libc::c_uint ==
                       AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                    // We want to clear from the virgin bits what is already in the seeds
                    afl_stage_is_interesting((*in_memory_fuzzer).stage);
                    (*(*queue_entry).info).skip_entry =
                        0 as libc::c_int as u8_0
                } else {
                    printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mQueue entry %ld misbehaved, disabling...\x00"
                               as *const u8 as *const libc::c_char,
                           calibration_idx);
                    printf(b"\x1b[0m\n\x00" as *const u8 as
                               *const libc::c_char);
                }
            }
        }
    }
    if calibration_idx == 0 as libc::c_int as libc::c_long {
        if debug != 0 {
            fprintf(stderr,
                    b"Calibration checks done.\n\x00" as *const u8 as
                        *const libc::c_char);
            let mut i: u32_0 = 0;
            fprintf(stderr,
                    b"%u seeds:\n\x00" as *const u8 as *const libc::c_char,
                    (*((*in_memory_fuzzer).global_queue as
                           *mut afl_queue_t)).entries_count as u32_0);
            i = 0 as libc::c_int as u32_0;
            while i <
                      (*((*in_memory_fuzzer).global_queue as
                             *mut afl_queue_t)).entries_count as u32_0 {
                let mut queue_entry_0: *mut afl_entry_t =
                    (*(*in_memory_fuzzer).global_queue).base.funcs.get_queue_entry.expect("non-null function pointer")((*in_memory_fuzzer).global_queue
                                                                                                                           as
                                                                                                                           *mut afl_queue_t,
                                                                                                                       i);
                if !queue_entry_0.is_null() &&
                       (*(*queue_entry_0).info).skip_entry as libc::c_int != 0
                   {
                    fprintf(stderr,
                            b"Seed #%u is disabled\n\x00" as *const u8 as
                                *const libc::c_char, i);
                }
                i = i.wrapping_add(1)
            }
        }
        calibration_idx = -(1 as libc::c_int) as ssize_t
        // we are done
    }
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn write_cur_state(mut out_msg: *mut llmp_message_t) {
    if (*out_msg).buf_len <
           (::std::mem::size_of::<cur_state_t>() as
                libc::c_ulong).wrapping_add(__afl_map_size as
                                                libc::c_ulong).wrapping_add((*current_input).len)
       {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mMessage not large enough for our state!\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 16],
                                         &[libc::c_char; 16]>(b"write_cur_state\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 180 as libc::c_int);
        exit(1 as libc::c_int);
    }
    /* first virgin bits[map_size], then the crasing/timeouting input buf */
    let mut state: *mut cur_state_t =
        ({
             let mut _msg: *mut llmp_message_t = out_msg;
             (if (*_msg).buf_len >=
                     ::std::mem::size_of::<cur_state_t>() as libc::c_ulong {
                  (*_msg).buf.as_mut_ptr()
              } else { 0 as *mut u8_0 }) as *mut cur_state_t
         });
    (*state).map_size = __afl_map_size as size_t;
    memcpy((*state).payload.as_mut_ptr() as *mut libc::c_void,
           virgin_bits as *const libc::c_void, (*state).map_size);
    (*state).current_input_len = (*current_input).len;
    (*state).calibration_idx = calibration_idx;
    memcpy((*state).payload.as_mut_ptr().offset((*state).map_size as isize) as
               *mut libc::c_void,
           (*current_input).bytes as *const libc::c_void,
           (*current_input).len);
}
unsafe extern "C" fn handle_timeout(mut sig: libc::c_int,
                                    mut info: *mut siginfo_t,
                                    mut ucontext: *mut libc::c_void) {
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:200] \x1b[0mTIMEOUT/SIGUSR2 received.\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    if current_fuzz_input_msg.is_null() {
        if debug != 0 {
            printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mSIGUSR/timeout happened, but not currently fuzzing!\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        }
        return
    }
    if (*current_fuzz_input_msg).buf_len !=
           (::std::mem::size_of::<cur_state_t>() as
                libc::c_ulong).wrapping_add(__afl_map_size as
                                                libc::c_ulong).wrapping_add((*current_input).len)
       {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mUnexpected current_fuzz_input_msg length during timeout handling!\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 15],
                                         &[libc::c_char; 15]>(b"handle_timeout\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 211 as libc::c_int);
        exit(1 as libc::c_int);
    }
    if calibration_idx != 0 && !global_queue.is_null() {
        let mut queue_entry: *mut afl_entry_t =
            (*global_queue).base.funcs.get_queue_entry.expect("non-null function pointer")(global_queue
                                                                                               as
                                                                                               *mut afl_queue_t,
                                                                                           calibration_idx
                                                                                               as
                                                                                               u32_0);
        if !queue_entry.is_null() && (*(*queue_entry).info).skip_entry == 0 {
            printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mSeed entry %ld timed out, disabling...\x00"
                       as *const u8 as *const libc::c_char, calibration_idx);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            (*(*queue_entry).info).skip_entry = 1 as libc::c_int as u8_0
        }
    }
    write_cur_state(current_fuzz_input_msg);
    (*current_fuzz_input_msg).tag = 0xa51ee851 as libc::c_uint;
    if !llmp_client_send(current_client, current_fuzz_input_msg) {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError sending timeout info!\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 15],
                                         &[libc::c_char; 15]>(b"handle_timeout\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 230 as libc::c_int);
        exit(1 as libc::c_int);
    }
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:231] \x1b[0mWe sent off the timeout at %p. Now waiting for broker to kill us :)\x00"
               as *const u8 as *const libc::c_char,
           (*info)._sifields._sigfault.si_addr);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    let mut current_out_map: *mut llmp_page_t =
        shmem2page(&mut *(*current_client).out_maps.offset((*current_client).out_map_count.wrapping_sub(1
                                                                                                            as
                                                                                                            libc::c_int
                                                                                                            as
                                                                                                            libc::c_ulong)
                                                               as isize));
    /* Wait for broker to map this page, so our work is done. Broker will restart this fuzzer */
    while (*current_out_map).save_to_unmap == 0 {
        usleep(10 as libc::c_int as __useconds_t);
    }
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:242] \x1b[0mExiting client.\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mTIMOUT\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00" as
               *const u8 as *const libc::c_char,
           (*::std::mem::transmute::<&[u8; 15],
                                     &[libc::c_char; 15]>(b"handle_timeout\x00")).as_ptr(),
           b"examples/libaflfuzzer.c\x00" as *const u8 as *const libc::c_char,
           243 as libc::c_int);
    exit(1 as libc::c_int);
}
unsafe extern "C" fn handle_crash(mut sig: libc::c_int,
                                  mut info: *mut siginfo_t,
                                  mut ucontext: *mut libc::c_void) {
    /* TODO: write info and ucontext to sharedmap */
    if current_client.is_null() {
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mWe died accessing addr %p, but are not in a client...\x00"
                   as *const u8 as *const libc::c_char,
               (*info)._sifields._sigfault.si_addr);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        /* let's crash */
        return
    }
    if calibration_idx != 0 && !global_queue.is_null() {
        let mut queue_entry: *mut afl_entry_t =
            (*global_queue).base.funcs.get_queue_entry.expect("non-null function pointer")(global_queue
                                                                                               as
                                                                                               *mut afl_queue_t,
                                                                                           calibration_idx
                                                                                               as
                                                                                               u32_0);
        if !queue_entry.is_null() && (*(*queue_entry).info).skip_entry == 0 {
            printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mSeed entry %ld crashed, disabling...\x00"
                       as *const u8 as *const libc::c_char, calibration_idx);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            (*(*queue_entry).info).skip_entry = 1 as libc::c_int as u8_0
        }
    }
    let mut current_out_map: *mut llmp_page_t =
        shmem2page(&mut *(*current_client).out_maps.offset((*current_client).out_map_count.wrapping_sub(1
                                                                                                            as
                                                                                                            libc::c_int
                                                                                                            as
                                                                                                            libc::c_ulong)
                                                               as isize));
    /* TODO: Broker should probably check for sender_dead and restart us? */
    ::std::ptr::write_volatile(&mut (*current_out_map).sender_dead as
                                   *mut u16_0, 1 as libc::c_int as u16_0);
    if !current_fuzz_input_msg.is_null() {
        if current_input.is_null() ||
               (*current_fuzz_input_msg).buf_len !=
                   (::std::mem::size_of::<cur_state_t>() as
                        libc::c_ulong).wrapping_add(__afl_map_size as
                                                        libc::c_ulong).wrapping_add((*current_input).len)
           {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mUnexpected current_fuzz_input_msg length during crash handling!\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 13],
                                             &[libc::c_char; 13]>(b"handle_crash\x00")).as_ptr(),
                   b"examples/libaflfuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 285 as libc::c_int);
            exit(1 as libc::c_int);
        }
        write_cur_state(current_fuzz_input_msg);
        llmp_client_send(current_client, current_fuzz_input_msg);
        printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:291] \x1b[0mWe sent off the crash at %p. Now waiting for broker...\x00"
                   as *const u8 as *const libc::c_char,
               (*info)._sifields._sigfault.si_addr);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
    } else {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:295] \x1b[0mWe died at %p, but didn\'t crash in the target :( - Waiting for the broker.\x00"
                   as *const u8 as *const libc::c_char,
               (*info)._sifields._sigfault.si_addr);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
    }
    /* Wait for broker to map this page, so our work is done. Broker will restart this fuzzer */
    while (*current_out_map).save_to_unmap == 0 {
        usleep(10 as libc::c_int as __useconds_t);
    }
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:306] \x1b[0mReturning from crash handler.\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    /* let's crash */
}
unsafe extern "C" fn setup_signal_handlers() {
    let mut sa: sigaction =
        sigaction{__sigaction_handler: C2RustUnnamed_9{sa_handler: None,},
                  sa_mask: __sigset_t{__val: [0; 16],},
                  sa_flags: 0,
                  sa_restorer: None,};
    sa.__sigaction_handler.sa_sigaction = None;
    memset(&mut sa as *mut sigaction as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<unsafe extern "C" fn(_: libc::c_int,
                                                      _: *const sigaction,
                                                      _: *mut sigaction)
                                     -> libc::c_int>() as libc::c_ulong);
    sigemptyset(&mut sa.sa_mask);
    sa.sa_flags = 0x40000000 as libc::c_int | 4 as libc::c_int;
    sa.__sigaction_handler.sa_sigaction =
        Some(handle_crash as
                 unsafe extern "C" fn(_: libc::c_int, _: *mut siginfo_t,
                                      _: *mut libc::c_void) -> ());
    /* Handle segfaults by writing the crashing input to the shared map, then exiting */
    if sigaction(11 as libc::c_int, &mut sa, 0 as *mut sigaction) <
           0 as libc::c_int {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not set segfault handler\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 22],
                                         &[libc::c_char; 22]>(b"setup_signal_handlers\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 323 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    if sigaction(7 as libc::c_int, &mut sa, 0 as *mut sigaction) <
           0 as libc::c_int {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not set sigbus handler\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 22],
                                         &[libc::c_char; 22]>(b"setup_signal_handlers\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 324 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    if sigaction(6 as libc::c_int, &mut sa, 0 as *mut sigaction) <
           0 as libc::c_int {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not set abort handler\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 22],
                                         &[libc::c_char; 22]>(b"setup_signal_handlers\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 325 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    if sigaction(4 as libc::c_int, &mut sa, 0 as *mut sigaction) <
           0 as libc::c_int {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not set illegal instruction handler\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 22],
                                         &[libc::c_char; 22]>(b"setup_signal_handlers\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 326 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    if sigaction(8 as libc::c_int, &mut sa, 0 as *mut sigaction) <
           0 as libc::c_int {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not set fp exception handler\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 22],
                                         &[libc::c_char; 22]>(b"setup_signal_handlers\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 327 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    /* If the broker notices we didn't send anything for a long time, it kills us using SIGUSR2 */
    sa.__sigaction_handler.sa_sigaction =
        Some(handle_timeout as
                 unsafe extern "C" fn(_: libc::c_int, _: *mut siginfo_t,
                                      _: *mut libc::c_void) -> ());
    if sigaction(12 as libc::c_int, &mut sa, 0 as *mut sigaction) <
           0 as libc::c_int {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not set sigusr handler\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 22],
                                         &[libc::c_char; 22]>(b"setup_signal_handlers\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 331 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    };
}
#[no_mangle]
pub unsafe extern "C" fn client_send_stats(mut engine: *mut afl_engine_t) {
    let mut llmp_client: *mut llmp_client_t = (*engine).llmp_client;
    let mut msg: *mut llmp_message_t =
        llmp_client_alloc_next(llmp_client,
                               ::std::mem::size_of::<u64_0>() as
                                   libc::c_ulong);
    (*msg).tag = 0xec574751 as libc::c_uint;
    let mut x: *mut u64_0 = (*msg).buf.as_mut_ptr() as *mut u64_0;
    *x = (*engine).executions;
    (*engine).executions = 0 as libc::c_int as u64_0;
    llmp_client_send(llmp_client, msg);
    (*engine).last_update = afl_get_cur_time_s();
}
#[no_mangle]
pub unsafe extern "C" fn execute(mut engine: *mut afl_engine_t,
                                 mut input: *mut afl_input_t) -> u8_0 {
    let mut i: size_t = 0;
    let mut executor: *mut afl_executor_t = (*engine).executor;
    /* Check for engine to be configured properly. Only to check setup in newly forked threads so debug only */
  // AFL_TRY(afl_engine_check_configuration(engine), { FATAL("Engine configured incompletely"); });
    (*executor).funcs.observers_reset.expect("non-null function pointer")(executor);
    (*executor).funcs.place_input_cb.expect("non-null function pointer")(executor,
                                                                         input);
    // TODO move to execute_init()
    if (*engine).start_time == 0 as libc::c_int as libc::c_ulonglong {
        (*engine).executions = 0 as libc::c_int as u64_0;
        (*engine).start_time = afl_get_cur_time();
        (*engine).last_update = afl_get_cur_time_s();
        client_send_stats(engine);
    }
    /* TODO: use the msg buf in input directly */
    current_input = input;
    current_fuzz_input_msg =
        llmp_client_alloc_next((*engine).llmp_client,
                               (::std::mem::size_of::<cur_state_t>() as
                                    libc::c_ulong).wrapping_add(__afl_map_size
                                                                    as
                                                                    libc::c_ulong).wrapping_add((*input).len));
    if current_fuzz_input_msg.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mCould not allocate crash message. Quitting!\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 8],
                                         &[libc::c_char; 8]>(b"execute\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 373 as libc::c_int);
        exit(1 as libc::c_int);
    }
    /* we may crash, who knows.
  TODO: Actually use this buffer to mutate and fuzz, saves us copy time. */
    (*current_fuzz_input_msg).tag = 0x101dead1 as libc::c_int as u32_0;
    let mut run_result: afl_exit_t =
        (*executor).funcs.run_target_cb.expect("non-null function pointer")(executor);
    (*engine).executions = (*engine).executions.wrapping_add(1);
    /* we didn't crash. Cancle msg sending.
  TODO: Reuse this msg in case the testacse is interesting! */
    llmp_client_cancel((*engine).llmp_client, current_fuzz_input_msg);
    current_fuzz_input_msg = 0 as *mut llmp_message_t;
    /* We've run the target with the executor, we can now simply postExec call the
   * observation channels*/
    i = 0 as libc::c_int as size_t;
    while i < (*executor).observors_count as libc::c_ulong {
        let mut obs_channel: *mut afl_observer_t =
            *(*executor).observors.offset(i as isize);
        if (*obs_channel).funcs.post_exec.is_some() {
            (*obs_channel).funcs.post_exec.expect("non-null function pointer")(*(*executor).observors.offset(i
                                                                                                                 as
                                                                                                                 isize),
                                                                               engine);
        }
        i = i.wrapping_add(1)
    }
    // Now based on the return of executor's run target, we basically return an
  // afl_ret_t type to the callee
    /* Gather some stats */
    if (*engine).executions.wrapping_rem(123 as libc::c_int as
                                             libc::c_ulonglong) != 0 &&
           (*engine).last_update < afl_get_cur_time_s() {
        client_send_stats(engine);
    }
    match run_result as libc::c_uint {
        0 | 8 => { return AFL_RET_SUCCESS as libc::c_int as u8_0 }
        _ => {
            /* TODO: We'll never reach this, actually... */
            if afl_input_dump_to_crashfile((*executor).current_input,
                                           queue_dirpath) as libc::c_uint ==
                   AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                (*engine).crashes = (*engine).crashes.wrapping_add(1)
            }
            return AFL_RET_WRITE_TO_CRASH as libc::c_int as u8_0
        }
    };
}
/* This initializes the fuzzer */
#[no_mangle]
pub unsafe extern "C" fn initialize_broker(mut in_dir: *mut libc::c_char,
                                           mut queue_dir: *mut libc::c_char,
                                           mut argc: libc::c_int,
                                           mut argv: *mut *mut libc::c_char,
                                           mut instance: u32_0)
 -> *mut afl_engine_t {
    /* Let's create an in-memory executor */
    let mut in_memory_executor: *mut in_memory_executor_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<in_memory_executor_t>() as libc::c_ulong)
            as *mut in_memory_executor_t;
    if in_memory_executor.is_null() {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mUnable to allocate mem.\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 426 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    if debug == 1234 as libc::c_int {
        // TODO FIXME
        in_memory_executor_init(in_memory_executor,
                                Some(debug_harness_func as
                                         unsafe extern "C" fn(_:
                                                                  *mut afl_executor_t,
                                                              _: *mut u8_0,
                                                              _: size_t)
                                             -> afl_exit_t));
    } else {
        in_memory_executor_init(in_memory_executor,
                                Some(harness_func as
                                         unsafe extern "C" fn(_:
                                                                  *mut afl_executor_t,
                                                              _: *mut u8_0,
                                                              _: size_t)
                                             -> afl_exit_t));
    }
    (*in_memory_executor).argc = argc;
    (*in_memory_executor).argv = afl_argv_cpy_dup(argc, argv);
    // in_memory_executor->base.funcs.init_cb = in_memory_fuzzer_initialize;
    /* Observation channel, map based, we initialize this ourselves since we don't
   * actually create a shared map */
    let mut observer_covmap: *mut afl_observer_covmap_t =
        afl_observer_covmap_new(__afl_map_size as size_t);
    if observer_covmap.is_null() {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mTrace bits channel error\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 444 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    /* covmap new creates a covmap automatically. deinit here. */
    afl_shmem_deinit(&mut (*observer_covmap).shared_map); // Coverage "Map" we have
    (*observer_covmap).shared_map.map = __afl_area_ptr;
    (*observer_covmap).shared_map.map_size = __afl_map_size as size_t;
    (*observer_covmap).shared_map.shm_id = -(1 as libc::c_int);
    (*in_memory_executor).base.funcs.observer_add.expect("non-null function pointer")(&mut (*in_memory_executor).base,
                                                                                      &mut (*observer_covmap).base);
    /* We create a simple feedback queue for coverage here*/
    let mut coverage_feedback_queue: *mut afl_queue_feedback_t =
        afl_queue_feedback_new(0 as *mut afl_feedback_t,
                               b"Coverage feedback queue\x00" as *const u8 as
                                   *const libc::c_char as *mut libc::c_char);
    if coverage_feedback_queue.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing feedback queue\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 456 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*coverage_feedback_queue).base.funcs.set_dirpath.expect("non-null function pointer")(&mut (*coverage_feedback_queue).base,
                                                                                          queue_dir);
    /* Global queue creation */
    let mut new_global_queue: *mut afl_queue_global_t =
        afl_queue_global_new();
    if new_global_queue.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing global queue\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 461 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*new_global_queue).funcs.add_feedback_queue.expect("non-null function pointer")(new_global_queue,
                                                                                     coverage_feedback_queue);
    (*new_global_queue).base.funcs.set_dirpath.expect("non-null function pointer")(&mut (*new_global_queue).base,
                                                                                   queue_dir);
    /* Coverage Feedback initialization */
    let mut coverage_feedback: *mut afl_feedback_cov_t =
        afl_feedback_cov_new(coverage_feedback_queue, observer_covmap);
    if coverage_feedback.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing feedback\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 467 as libc::c_int);
        exit(1 as libc::c_int);
    }
    /* Let's build an engine now */
    let mut engine: *mut afl_engine_t =
        afl_engine_new(&mut (*in_memory_executor).base,
                       0 as *mut afl_fuzz_one_t, new_global_queue);
    if engine.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing Engine\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 471 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*engine).verbose = 1 as libc::c_int as u8_0;
    (*engine).funcs.add_feedback.expect("non-null function pointer")(engine,
                                                                     &mut (*coverage_feedback).base);
    (*engine).funcs.set_global_queue.expect("non-null function pointer")(engine,
                                                                         new_global_queue);
    (*engine).in_dir = in_dir;
    (*engine).funcs.execute =
        Some(execute as
                 unsafe extern "C" fn(_: *mut afl_engine_t,
                                      _: *mut afl_input_t) -> u8_0);
    let mut fuzz_one: *mut afl_fuzz_one_t = afl_fuzz_one_new(engine);
    if fuzz_one.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing fuzz_one\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 479 as libc::c_int);
        exit(1 as libc::c_int);
    }
    // We also add the fuzzone to the engine here.
    (*engine).funcs.set_fuzz_one.expect("non-null function pointer")(engine,
                                                                     fuzz_one);
    let mut mutators_havoc: *mut afl_mutator_scheduled_t =
        afl_mutator_scheduled_new(engine, 8 as libc::c_int as size_t);
    if mutators_havoc.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing Mutators\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 485 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut err: afl_ret_t =
        afl_mutator_scheduled_add_havoc_funcs(mutators_havoc);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:488] \x1b[0mAFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError adding mutators: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 488 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut stage: *mut afl_stage_t = afl_stage_new(engine);
    if stage.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError creating fuzzing stage\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 491 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut err_0: afl_ret_t =
        (*stage).funcs.add_mutator_to_stage.expect("non-null function pointer")(stage,
                                                                                &mut (*mutators_havoc).base);
    if err_0 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:493] \x1b[0mAFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err_0));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError adding mutator: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err_0));
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 18],
                                         &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 493 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*in_memory_executor).stage = stage;
    (*in_memory_executor).global_queue = new_global_queue;
    /* Now add the testcases */
  /* first we want to support restarts and read the queue */
    if !queue_dirpath.is_null() &&
           *queue_dirpath.offset(0 as libc::c_int as isize) as libc::c_int !=
               0 as libc::c_int {
        (*engine).funcs.load_testcases_from_dir.expect("non-null function pointer")(engine,
                                                                                    queue_dirpath); // ignore if it fails.
    }
    /* Now we read the seeds from an input directory */
    if !(*engine).in_dir.is_null() &&
           *(*engine).in_dir.offset(0 as libc::c_int as isize) as libc::c_int
               != 0 as libc::c_int {
        let mut err_1: afl_ret_t =
            (*engine).funcs.load_testcases_from_dir.expect("non-null function pointer")(engine,
                                                                                        (*engine).in_dir);
        if err_1 as libc::c_uint !=
               AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
            printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:504] \x1b[0mAFL_TRY returning error: %s\x00"
                       as *const u8 as *const libc::c_char,
                   afl_ret_stringify(err_1));
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mError loading testcase dir: %s\x00"
                       as *const u8 as *const libc::c_char,
                   afl_ret_stringify(err_1));
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        }
    }
    // no seeds? add a dummy one
    if (*((*engine).global_queue as *mut afl_queue_t)).entries_count ==
           0 as libc::c_int as libc::c_ulong {
        let mut input: *mut afl_input_t = afl_input_new();
        if input.is_null() {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mCould not create input\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 18],
                                             &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
                   b"examples/libaflfuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 510 as libc::c_int);
            exit(1 as libc::c_int);
        }
        let mut cnt: u32_0 = 0;
        let mut input_len: u32_0 = 64 as libc::c_int as u32_0;
        (*input).len = input_len as size_t;
        (*input).bytes =
            calloc(input_len.wrapping_add(1 as libc::c_int as libc::c_uint) as
                       libc::c_ulong, 1 as libc::c_int as libc::c_ulong) as
                *mut u8_0;
        if (*input).bytes.is_null() {
            fflush(stdout);
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not allocate input bytes\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 18],
                                             &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
                   b"examples/libaflfuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 515 as libc::c_int);
            printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as
                       *const u8 as *const libc::c_char,
                   strerror(*__errno_location()));
            exit(1 as libc::c_int);
        }
        cnt = 0 as libc::c_int as u32_0;
        while cnt < input_len {
            *(*input).bytes.offset(cnt as isize) =
                (' ' as i32 as libc::c_uint).wrapping_add(cnt) as u8_0;
            cnt = cnt.wrapping_add(1)
            // values: 0x20 ... 0x60
        }
        *(*input).bytes.offset(input_len as isize) = 0 as libc::c_int as u8_0;
        let mut new_entry: *mut afl_entry_t =
            afl_entry_new(input, 0 as *mut afl_entry_info_t);
        if new_entry.is_null() {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mCould not create new entry\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 18],
                                             &[libc::c_char; 18]>(b"initialize_broker\x00")).as_ptr(),
                   b"examples/libaflfuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 526 as libc::c_int);
            exit(1 as libc::c_int);
        }
        (*(*engine).global_queue).base.funcs.insert.expect("non-null function pointer")(&mut (*(*engine).global_queue).base,
                                                                                        new_entry);
    }
    broker_queue = (*engine).global_queue;
    calibration_idx =
        (*((*engine).global_queue as *mut afl_queue_t)).entries_count as
            ssize_t;
    printf(b"\x1b[1;92m[+] \x1b[0mStarting seed count: %lu\x00" as *const u8
               as *const libc::c_char, calibration_idx);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    return engine;
}
#[no_mangle]
pub unsafe extern "C" fn fuzzer_process_main(mut llmp_client:
                                                 *mut llmp_client_t,
                                             mut data: *mut libc::c_void) {
    let mut i: size_t = 0;
    /* global variable (ugh) for our signal handler */
    current_client = llmp_client;
    /* We're in the child, capture segfaults and SIGUSR2 from here on.
  (We SIGUSR2 = timeout, delived by the broker when no new messages reached him for a while) */
    setup_signal_handlers();
    let mut engine: *mut afl_engine_t = data as *mut afl_engine_t;
    (*engine).llmp_client = llmp_client;
    (*engine).cpu_bound = bind_to_cpu() as s32;
    if (*engine).cpu_bound == -(1 as libc::c_int) {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError binding to CPU :(\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 20],
                                         &[libc::c_char; 20]>(b"fuzzer_process_main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 554 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut observer_covmap: *mut afl_observer_covmap_t =
        0 as *mut afl_observer_covmap_t;
    i = 0 as libc::c_int as size_t;
    while i < (*(*engine).executor).observors_count as libc::c_ulong {
        if (**(*(*engine).executor).observors.offset(i as isize)).tag ==
               0xb5ec0fe as libc::c_int as libc::c_uint {
            observer_covmap =
                *(*(*engine).executor).observors.offset(0 as libc::c_int as
                                                            isize) as
                    *mut afl_observer_covmap_t
        }
        i = i.wrapping_add(1)
    }
    if observer_covmap.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mGot no covmap observer\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 20],
                                         &[libc::c_char; 20]>(b"fuzzer_process_main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 567 as libc::c_int);
        exit(1 as libc::c_int);
    }
    /* set the global virgin_bits for error handlers, so we can restore them after a crash */
    virgin_bits = (*observer_covmap).shared_map.map;
    let mut stage: *mut afl_stage_t =
        *(*(*engine).fuzz_one).stages.offset(0 as libc::c_int as isize);
    let mut mutators_havoc: *mut afl_mutator_scheduled_t =
        *(*stage).mutators.offset(0 as libc::c_int as isize) as
            *mut afl_mutator_scheduled_t;
    let mut coverage_feedback: *mut afl_feedback_cov_t =
        0 as *mut afl_feedback_cov_t;
    i = 0 as libc::c_int as size_t;
    while (i as libc::c_ulonglong) < (*engine).feedbacks_count {
        if (**(*engine).feedbacks.offset(i as isize)).tag ==
               0xfeedc0f8 as libc::c_uint {
            coverage_feedback =
                *(*engine).feedbacks.offset(i as isize) as
                    *mut afl_feedback_cov_t;
            break ;
        } else { i = i.wrapping_add(1) }
    }
    if coverage_feedback.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mNo coverage feedback added to engine\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 20],
                                         &[libc::c_char; 20]>(b"fuzzer_process_main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 586 as libc::c_int);
        exit(1 as libc::c_int);
    }
    in_memory_fuzzer_initialize((*engine).executor);
    /* The actual fuzzing */
    let mut err: afl_ret_t =
        (*engine).funcs.loop_0.expect("non-null function pointer")(engine);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:591] \x1b[0mAFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mError fuzzing the target: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 20],
                                         &[libc::c_char; 20]>(b"fuzzer_process_main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 591 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    printf(b"Fuzzing ends with all the queue entries fuzzed. No of executions %llu\n\x00"
               as *const u8 as *const libc::c_char, (*engine).executions);
    /* Let's free everything now. Note that if you've extended any structure,
   * which now contains pointers to any dynamically allocated region, you have
   * to free them yourselves, but the extended structure itself can be de
   * initialized using the deleted functions provided */
    afl_executor_delete((*engine).executor);
    afl_feedback_cov_delete(coverage_feedback);
    afl_observer_covmap_delete(observer_covmap);
    afl_mutator_scheduled_delete(mutators_havoc);
    afl_stage_delete(stage);
    afl_fuzz_one_delete((*engine).fuzz_one);
    i = 0 as libc::c_int as size_t;
    while (i as libc::c_ulonglong) < (*engine).feedbacks_count {
        afl_feedback_delete(*(*engine).feedbacks.offset(i as isize));
        i = i.wrapping_add(1)
    }
    i = 0 as libc::c_int as size_t;
    while i < (*(*engine).global_queue).feedback_queues_count {
        afl_queue_feedback_delete(*(*(*engine).global_queue).feedback_queues.offset(i
                                                                                        as
                                                                                        isize));
        i = i.wrapping_add(1)
    }
    afl_queue_global_delete((*engine).global_queue);
    afl_engine_delete(engine);
}
/* In the broker, if we find out a client crashed, write the crashing testcase and respawn the child */
#[no_mangle]
pub unsafe extern "C" fn broker_handle_client_restart(mut broker:
                                                          *mut llmp_broker_t,
                                                      mut clientdata:
                                                          *mut llmp_broker_clientdata_t,
                                                      mut state:
                                                          *mut cur_state_t)
 -> bool {
    let mut client_id: u32_0 = (*(*clientdata).client_state).id;
    if state.is_null() {
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mIllegal state received during crash\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int != 0
        // don't forward
    }
    /* Remove this client, then spawn a new client with the current state.*/
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:636] \x1b[0mRemoving old/crashed client\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    /* TODO: We should probably waite for the old client pid to finish (or kill it?) before creating a new one */
    (*(*clientdata).client_state).current_broadcast_map =
        0 as *mut afl_shmem_t; // Don't kill our map :)
    llmp_client_delete((*clientdata).client_state);
    afl_shmem_deinit((*clientdata).cur_client_map);
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:643] \x1b[0mCreating new client #phoenix\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    (*clientdata).client_state = llmp_client_new_unconnected();
    if (*clientdata).client_state.is_null() {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mError allocating replacement client after crash\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 29],
                                         &[libc::c_char; 29]>(b"broker_handle_client_restart\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 645 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    /* restore old client id */
    (*(*clientdata).client_state).id = client_id;
    /* link the new broker to the client at the position of the old client by connecting shmems. */
  /* TODO: Do this inside the forked thread instead? Right now, we're mapping it twice... */
    let mut broadcast_map: *mut afl_shmem_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_shmem_t>() as libc::c_ulong) as
            *mut afl_shmem_t;
    if broadcast_map.is_null() {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not alloc mem for broadcast map\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 29],
                                         &[libc::c_char; 29]>(b"broker_handle_client_restart\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 651 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    afl_shmem_by_str(broadcast_map,
                     (*(*broker).broadcast_maps.offset(0 as libc::c_int as
                                                           isize)).shm_str.as_mut_ptr(),
                     (*(*broker).broadcast_maps.offset(0 as libc::c_int as
                                                           isize)).map_size);
    (*(*clientdata).client_state).current_broadcast_map = broadcast_map;
    afl_shmem_by_str((*clientdata).cur_client_map,
                     (*(*(*clientdata).client_state).out_maps.offset(0 as
                                                                         libc::c_int
                                                                         as
                                                                         isize)).shm_str.as_mut_ptr(),
                     (*(*(*clientdata).client_state).out_maps.offset(0 as
                                                                         libc::c_int
                                                                         as
                                                                         isize)).map_size);
    /* restore the old virgin_bits for this fuzzer before reforking */
    let mut engine: *mut afl_engine_t =
        (*clientdata).data as *mut afl_engine_t;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while (i as libc::c_ulonglong) < (*engine).feedbacks_count {
        if (**(*engine).feedbacks.offset(i as isize)).tag ==
               0xfeedc0f8 as libc::c_uint {
            afl_feedback_cov_set_virgin_bits(*(*engine).feedbacks.offset(i as
                                                                             isize)
                                                 as *mut afl_feedback_cov_t,
                                             (*state).payload.as_mut_ptr(),
                                             (*state).map_size);
        }
        i = i.wrapping_add(1)
    }
    (*clientdata).last_msg_broker_read = 0 as *mut llmp_message_t;
    /* Get ready for a new child. TODO: Collect old ones... */
    (*clientdata).pid = 0 as libc::c_int;
    /* Make sure the next fork won't start in the same rnd state as the last... */
    afl_rand_next(&mut (*engine).rand);
    /* fork off the new child */
    if !llmp_broker_launch_client(broker, clientdata) {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError spawning new client after crash\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 29],
                                         &[libc::c_char; 29]>(b"broker_handle_client_restart\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 679 as libc::c_int);
        exit(1 as libc::c_int);
    }
    return 1 as libc::c_int != 0;
}
/* A hook to keep stats in the broker thread */
#[no_mangle]
pub unsafe extern "C" fn broker_message_hook(mut broker: *mut llmp_broker_t,
                                             mut clientdata:
                                                 *mut llmp_broker_clientdata_t,
                                             mut msg: *mut llmp_message_t,
                                             mut data: *mut libc::c_void)
 -> bool {
    let mut fuzzer_stats: *mut fuzzer_stats_t =
        data as *mut fuzzer_stats_t; // Forward this to the clients
    let mut client_stats: *mut broker_client_stats_t =
        &mut *(*fuzzer_stats).clients.offset((*(*clientdata).client_state).id.wrapping_sub(1
                                                                                               as
                                                                                               libc::c_int
                                                                                               as
                                                                                               libc::c_uint)
                                                 as isize) as
            *mut broker_client_stats; // don't forward this to the clients
    (*client_stats).last_msg_time = afl_get_cur_time() as u32_0;
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:692] \x1b[0mBroker: msg hook called with msg tag %X\x00"
               as *const u8 as *const libc::c_char, (*msg).tag);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    let mut state: *mut cur_state_t = 0 as *mut cur_state_t;
    let mut timeout_input: afl_input_t =
        afl_input_t{bytes: 0 as *mut u8_0,
                    len: 0,
                    copy_buf: 0 as *mut u8_0,
                    funcs:
                        afl_input_funcs{deserialize: None,
                                        serialize: None,
                                        copy: None,
                                        restore: None,
                                        load_from_file: None,
                                        save_to_file: None,
                                        clear: None,
                                        get_bytes: None,
                                        delete: None,},};
    let mut crashing_input: afl_input_t =
        afl_input_t{bytes: 0 as *mut u8_0,
                    len: 0,
                    copy_buf: 0 as *mut u8_0,
                    funcs:
                        afl_input_funcs{deserialize: None,
                                        serialize: None,
                                        copy: None,
                                        restore: None,
                                        load_from_file: None,
                                        save_to_file: None,
                                        clear: None,
                                        get_bytes: None,
                                        delete: None,},};
    match (*msg).tag {
        3232620241 => {
            (*fuzzer_stats).queue_entry_count =
                (*fuzzer_stats).queue_entry_count.wrapping_add(1);
            return 1 as libc::c_int != 0
        }
        3965142865 => {
            (*client_stats).total_execs =
                ((*client_stats).total_execs as
                     libc::c_ulonglong).wrapping_add(*({
                                                           let mut _msg:
                                                                   *mut llmp_message_t =
                                                               msg;
                                                           (if (*_msg).buf_len
                                                                   >=
                                                                   ::std::mem::size_of::<u64_0>()
                                                                       as
                                                                       libc::c_ulong
                                                               {
                                                                (*_msg).buf.as_mut_ptr()
                                                            } else {
                                                                0 as *mut u8_0
                                                            }) as *mut u64_0
                                                       })) as u64_0 as u64_0;
            return 0 as libc::c_int != 0
        }
        2770266193 => {
            printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:705] \x1b[0mWe found a timeout...\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            /* write timeout output */
            state =
                ({
                     let mut _msg: *mut llmp_message_t = msg;
                     (if (*_msg).buf_len >=
                             ::std::mem::size_of::<cur_state_t>() as
                                 libc::c_ulong {
                          (*_msg).buf.as_mut_ptr()
                      } else { 0 as *mut u8_0 }) as *mut cur_state_t
                 });
            if (*state).calibration_idx < calibration_idx {
                calibration_idx = (*state).calibration_idx
            }
            if (*state).calibration_idx >= 0 as libc::c_int as libc::c_long {
                let mut queue_entry: *mut afl_entry_t =
                    (*broker_queue).base.funcs.get_queue_entry.expect("non-null function pointer")(broker_queue
                                                                                                       as
                                                                                                       *mut afl_queue_t,
                                                                                                   (*state).calibration_idx
                                                                                                       as
                                                                                                       u32_0);
                if !queue_entry.is_null() &&
                       (*(*queue_entry).info).skip_entry == 0 {
                    printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mSeed entry %ld timed out, disabling...\x00"
                               as *const u8 as *const libc::c_char,
                           (*state).calibration_idx);
                    printf(b"\x1b[0m\n\x00" as *const u8 as
                               *const libc::c_char);
                    (*(*queue_entry).info).skip_entry =
                        1 as libc::c_int as u8_0
                }
            }
            timeout_input =
                {
                    let mut init =
                        afl_input{bytes: 0 as *mut u8_0,
                                  len: 0,
                                  copy_buf: 0 as *mut u8_0,
                                  funcs:
                                      afl_input_funcs{deserialize: None,
                                                      serialize: None,
                                                      copy: None,
                                                      restore: None,
                                                      load_from_file: None,
                                                      save_to_file: None,
                                                      clear: None,
                                                      get_bytes: None,
                                                      delete: None,},};
                    init
                };
            let mut err: afl_ret_t = afl_input_init(&mut timeout_input);
            if err as libc::c_uint !=
                   AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:726] \x1b[0mAFL_TRY returning error: %s\x00"
                           as *const u8 as *const libc::c_char,
                       afl_ret_stringify(err));
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing input for crash: %s\x00"
                           as *const u8 as *const libc::c_char,
                       afl_ret_stringify(err));
                printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                           as *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 20],
                                                 &[libc::c_char; 20]>(b"broker_message_hook\x00")).as_ptr(),
                       b"examples/libaflfuzzer.c\x00" as *const u8 as
                           *const libc::c_char, 726 as libc::c_int);
                exit(1 as libc::c_int);
            }
            timeout_input.bytes =
                (*state).payload.as_mut_ptr().offset((*state).map_size as
                                                         isize);
            timeout_input.len = (*state).current_input_len;
            if timeout_input.len != 0 {
                if afl_input_dump_to_timeoutfile(&mut timeout_input,
                                                 queue_dirpath) as
                       libc::c_uint ==
                       AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                    (*fuzzer_stats).timeouts =
                        (*fuzzer_stats).timeouts.wrapping_add(1)
                }
            } else {
                printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mCrash input has zero length, this cannot happen.\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            }
            broker_handle_client_restart(broker, clientdata, state);
            (*client_stats).total_execs =
                ((*client_stats).total_execs as
                     libc::c_ulonglong).wrapping_add((*state).new_execs) as
                    u64_0 as u64_0;
            // Reset timeout
            (*client_stats).last_msg_time =
                0 as libc::c_int as
                    u32_0; // Don't foward this msg to clients.
            return 0 as libc::c_int != 0
        }
        270396113 => {
            printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:751] \x1b[0mWe found a crash!\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            /* write crash output */
            state =
                ({
                     let mut _msg: *mut llmp_message_t = msg;
                     (if (*_msg).buf_len >=
                             ::std::mem::size_of::<cur_state_t>() as
                                 libc::c_ulong {
                          (*_msg).buf.as_mut_ptr()
                      } else { 0 as *mut u8_0 }) as *mut cur_state_t
                 });
            if (*state).calibration_idx < calibration_idx {
                calibration_idx = (*state).calibration_idx
            }
            if (*state).calibration_idx >= 0 as libc::c_int as libc::c_long {
                let mut queue_entry_0: *mut afl_entry_t =
                    (*broker_queue).base.funcs.get_queue_entry.expect("non-null function pointer")(broker_queue
                                                                                                       as
                                                                                                       *mut afl_queue_t,
                                                                                                   (*state).calibration_idx
                                                                                                       as
                                                                                                       u32_0);
                if !queue_entry_0.is_null() &&
                       (*(*queue_entry_0).info).skip_entry == 0 {
                    printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mSeed entry %ld crashed, disabling...\x00"
                               as *const u8 as *const libc::c_char,
                           (*state).calibration_idx);
                    printf(b"\x1b[0m\n\x00" as *const u8 as
                               *const libc::c_char);
                    (*(*queue_entry_0).info).skip_entry =
                        1 as libc::c_int as u8_0
                }
            }
            crashing_input =
                {
                    let mut init =
                        afl_input{bytes: 0 as *mut u8_0,
                                  len: 0,
                                  copy_buf: 0 as *mut u8_0,
                                  funcs:
                                      afl_input_funcs{deserialize: None,
                                                      serialize: None,
                                                      copy: None,
                                                      restore: None,
                                                      load_from_file: None,
                                                      save_to_file: None,
                                                      clear: None,
                                                      get_bytes: None,
                                                      delete: None,},};
                    init
                };
            let mut err_0: afl_ret_t = afl_input_init(&mut crashing_input);
            if err_0 as libc::c_uint !=
                   AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:772] \x1b[0mAFL_TRY returning error: %s\x00"
                           as *const u8 as *const libc::c_char,
                       afl_ret_stringify(err_0));
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing input for crash: %s\x00"
                           as *const u8 as *const libc::c_char,
                       afl_ret_stringify(err_0));
                printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                           as *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 20],
                                                 &[libc::c_char; 20]>(b"broker_message_hook\x00")).as_ptr(),
                       b"examples/libaflfuzzer.c\x00" as *const u8 as
                           *const libc::c_char, 772 as libc::c_int);
                exit(1 as libc::c_int);
            }
            crashing_input.bytes =
                (*state).payload.as_mut_ptr().offset((*state).map_size as
                                                         isize);
            crashing_input.len = (*state).current_input_len;
            if crashing_input.len != 0 {
                if afl_input_dump_to_crashfile(&mut crashing_input,
                                               queue_dirpath) as libc::c_uint
                       == AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                    (*fuzzer_stats).crashes =
                        (*fuzzer_stats).crashes.wrapping_add(1)
                }
            } else {
                printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mCrash input has zero length, this cannot happen.\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            }
            broker_handle_client_restart(broker, clientdata, state);
            (*client_stats).total_execs =
                ((*client_stats).total_execs as
                     libc::c_ulonglong).wrapping_add((*state).new_execs) as
                    u64_0 as u64_0;
            // Reset timeout
            (*client_stats).last_msg_time =
                0 as libc::c_int as
                    u32_0; // no need to foward this to clients.
            return 0 as libc::c_int != 0
        }
        _ => {
            /* We'll foward anything else we don't know. */
            printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:796] \x1b[0mUnknown message id: %X\x00"
                       as *const u8 as *const libc::c_char, (*msg).tag);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            return 1 as libc::c_int != 0
        }
    };
}
/*
 ****************
 ***** MAIN *****
 ****************
 */
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    if argc < 4 as libc::c_int {
        printf(b"Usage: %s number_of_threads /path/to/input/dir /path/to/queue/dir\n\x00"
                   as *const u8 as *const libc::c_char,
               *argv.offset(0 as libc::c_int as isize));
        exit(0 as libc::c_int);
    }
    let mut i: s32 = 0 as libc::c_int;
    let mut status: libc::c_int = 0 as libc::c_int;
    let mut pid: libc::c_int = 0 as libc::c_int;
    let mut thread_count: libc::c_int =
        atoi(*argv.offset(1 as libc::c_int as isize));
    let mut in_dir: *mut libc::c_char =
        *argv.offset(2 as libc::c_int as isize);
    queue_dirpath = *argv.offset(3 as libc::c_int as isize);
    if !getenv(b"DEBUG\x00" as *const u8 as *const libc::c_char).is_null() ||
           !getenv(b"AFL_DEBUG\x00" as *const u8 as
                       *const libc::c_char).is_null() {
        debug = 1 as libc::c_int
    }
    if debug != 0 {
        printf(b"libaflfuzzer running as:\x00" as *const u8 as
                   *const libc::c_char);
        i = 0 as libc::c_int;
        while i < argc {
            printf(b" %s\x00" as *const u8 as *const libc::c_char,
                   *argv.offset(i as isize));
            i += 1
        }
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
    }
    printf(b"\x1b[1;92m[+] \x1b[0mTarget coverage map size: %u\x00" as
               *const u8 as *const libc::c_char, __afl_map_size);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    if thread_count <= 0 as libc::c_int {
        // we cannot use FATAL because some build scripts fail otherwise
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] ERROR : \x1b[0mNumber of threads should be greater than 0, exiting gracefully.\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 841 as libc::c_int);
        exit(0 as libc::c_int);
    }
    let mut broker_port: libc::c_int = 0xaf1 as libc::c_int;
    if !afl_dir_exists(in_dir) {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mOops, seed input directory %s does not seem to be valid.\x00"
                   as *const u8 as *const libc::c_char, in_dir);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 848 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut engines: *mut *mut afl_engine_t =
        malloc((::std::mem::size_of::<*mut afl_engine_t>() as
                    libc::c_ulong).wrapping_mul(thread_count as
                                                    libc::c_ulong)) as
            *mut *mut afl_engine_t;
    if engines.is_null() {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not allocate engine buffer!\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 851 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    let mut llmp_broker: *mut llmp_broker_t = llmp_broker_new();
    if llmp_broker.is_null() {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mBroker creation failed\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 854 as libc::c_int);
        exit(1 as libc::c_int);
    }
    /* This is not necessary but gives us the option to add additional processes to the fuzzer at runtime. */
    if !llmp_broker_register_local_server(llmp_broker, broker_port) {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mBroker register failed\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 857 as libc::c_int);
        exit(1 as libc::c_int);
    }
    printf(b"\x1b[1;92m[+] \x1b[0mCreated broker.\x00" as *const u8 as
               *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    /* The message hook will intercept all messages from all clients - and listen for stats. */
    let mut fuzzer_stats: fuzzer_stats_t =
        {
            let mut init =
                fuzzer_stats{queue_entry_count: 0 as libc::c_int as u64_0,
                             crashes: 0,
                             timeouts: 0,
                             clients: 0 as *mut broker_client_stats,};
            init
        };
    llmp_broker_add_message_hook(llmp_broker,
                                 Some(broker_message_hook as
                                          unsafe extern "C" fn(_:
                                                                   *mut llmp_broker_t,
                                                               _:
                                                                   *mut llmp_broker_clientdata_t,
                                                               _:
                                                                   *mut llmp_message_t,
                                                               _:
                                                                   *mut libc::c_void)
                                              -> bool),
                                 &mut fuzzer_stats as *mut fuzzer_stats_t as
                                     *mut libc::c_void);
    fuzzer_stats.clients =
        malloc((thread_count as
                    libc::c_ulong).wrapping_mul(::std::mem::size_of::<broker_client_stats_t>()
                                                    as libc::c_ulong)) as
            *mut broker_client_stats;
    if fuzzer_stats.clients.is_null() {
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mUnable to alloc memory\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00" as
                   *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"examples/libaflfuzzer.c\x00" as *const u8 as
                   *const libc::c_char, 865 as libc::c_int);
        printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as *const u8
                   as *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    while i < thread_count {
        let mut engine: *mut afl_engine_t =
            initialize_broker(in_dir, queue_dirpath, argc, argv,
                              thread_count as u32_0);
        if engine.is_null() {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError initializing broker fuzzing engine\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"examples/libaflfuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 870 as libc::c_int);
            exit(1 as libc::c_int);
        }
        let ref mut fresh2 = *engines.offset(i as isize);
        *fresh2 = engine;
        /* All fuzzers get their own process.
    This call only allocs the data structures, but not fork yet. */
        if !llmp_broker_register_childprocess_clientloop(llmp_broker,
                                                         Some(fuzzer_process_main
                                                                  as
                                                                  unsafe extern "C" fn(_:
                                                                                           *mut llmp_client_t,
                                                                                       _:
                                                                                           *mut libc::c_void)
                                                                      -> ()),
                                                         engine as
                                                             *mut libc::c_void)
           {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError registering client\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"examples/libaflfuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 877 as libc::c_int);
            exit(1 as libc::c_int);
        }
        (*fuzzer_stats.clients.offset(i as isize)).total_execs =
            0 as libc::c_int as u64_0;
        i += 1
    }
    // Before we start the broker, we close the stderr file. Since the in-mem
  // fuzzer runs in the same process, this is necessary for stats collection.
    let mut dev_null_fd: s32 =
        open(b"/dev/null\x00" as *const u8 as *const libc::c_char,
             0o1 as libc::c_int);
    if getenv(b"DEBUG\x00" as *const u8 as *const libc::c_char).is_null() &&
           getenv(b"AFL_DEBUG\x00" as *const u8 as
                      *const libc::c_char).is_null() {
        dup2(dev_null_fd, 2 as libc::c_int);
    }
    let mut time_prev: u64_0 = 0 as libc::c_int as u64_0;
    let mut time_initial: u64_0 = afl_get_cur_time_s();
    let mut time_cur: u64_0 = time_initial;
    /* This spawns all registered clientloops:
  - The tcp server to add more clients (pthreads)
  - all fuzzer instances (using fork()) */
    llmp_broker_launch_clientloops(llmp_broker);
    printf(b"\x1b[1;92m[+] \x1b[0m%u client%s started running.\x00" as
               *const u8 as *const libc::c_char, thread_count,
           if thread_count == 1 as libc::c_int {
               b"\x00" as *const u8 as *const libc::c_char
           } else { b"s\x00" as *const u8 as *const libc::c_char });
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    sleep(1 as libc::c_int as libc::c_uint);
    loop  {
        /* Chill a bit */
        usleep(175 as libc::c_int as __useconds_t);
        /* Forward all messages that arrived in the meantime */
        llmp_broker_once(llmp_broker);
        /* Paint ui every second */
        time_cur = afl_get_cur_time_s();
        if time_cur > time_prev {
            let mut time_cur_ms: u32_0 = afl_get_cur_time() as u32_0;
            let mut time_elapsed: u64_0 = time_cur.wrapping_sub(time_initial);
            time_prev = time_cur;
            let mut total_execs: u64_0 = 0 as libc::c_int as u64_0;
            i = 0 as libc::c_int;
            while i < thread_count {
                let mut client_status: *mut broker_client_stats_t =
                    &mut *fuzzer_stats.clients.offset(i as isize) as
                        *mut broker_client_stats;
                total_execs =
                    (total_execs as
                         libc::c_ulonglong).wrapping_add((*client_status).total_execs)
                        as u64_0 as u64_0;
                if (*client_status).last_msg_time != 0 &&
                       time_cur_ms.wrapping_sub((*client_status).last_msg_time)
                           > 10000 as libc::c_int as libc::c_uint {
                    /* Note that the interesting client_ids start with 1 as 0 is the broker tcp server. */
                    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:929] \x1b[0mDetected timeout for client %d\x00"
                               as *const u8 as *const libc::c_char,
                           i + 1 as libc::c_int);
                    printf(b"\x1b[0m\n\x00" as *const u8 as
                               *const libc::c_char);
                    fflush(stdout);
                    kill((*(*llmp_broker).llmp_clients.offset((i +
                                                                   1 as
                                                                       libc::c_int)
                                                                  as
                                                                  isize)).pid,
                         12 as libc::c_int);
                }
                i += 1
            }
            printf(b"paths=%llu crashes=%llu timeouts=%llu elapsed=%llu execs=%llu exec/s=%llu\r\x00"
                       as *const u8 as *const libc::c_char,
                   fuzzer_stats.queue_entry_count, fuzzer_stats.crashes,
                   fuzzer_stats.timeouts, time_elapsed, total_execs,
                   total_execs.wrapping_div(time_elapsed));
            fflush(stdout);
            pid = waitpid(-(1 as libc::c_int), &mut status, 1 as libc::c_int);
            if pid > 0 as libc::c_int {
                // this pid is gone
        // TODO: Check if we missed a crash via llmp?
                printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer.c:946] \x1b[0mChild with pid %d is gone.\x00"
                           as *const u8 as *const libc::c_char, pid);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
            }
        }
    };
}
#[main]
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(::std::ffi::CString::new(arg).expect("Failed to convert argument into CString.").into_raw());
    };
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0((args.len() - 1) as libc::c_int,
                                    args.as_mut_ptr() as
                                        *mut *mut libc::c_char) as i32)
    }
}
