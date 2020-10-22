use ::libc;
extern "C" {
    pub type __dirstream;
    #[no_mangle]
    fn kill(__pid: __pid_t, __sig: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char,
               _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char,
              _: libc::c_int) -> libc::c_long;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn access(__name: *const libc::c_char, __type: libc::c_int)
     -> libc::c_int;
    #[no_mangle]
    fn sysconf(__name: libc::c_int) -> libc::c_long;
    #[no_mangle]
    fn fork() -> __pid_t;
    #[no_mangle]
    fn opendir(__name: *const libc::c_char) -> *mut DIR;
    #[no_mangle]
    fn closedir(__dirp: *mut DIR) -> libc::c_int;
    #[no_mangle]
    fn readdir(__dirp: *mut DIR) -> *mut dirent;
    #[no_mangle]
    fn waitpid(__pid: __pid_t, __stat_loc: *mut libc::c_int,
               __options: libc::c_int) -> __pid_t;
    #[no_mangle]
    fn __xstat(__ver: libc::c_int, __filename: *const libc::c_char,
               __stat_buf: *mut stat) -> libc::c_int;
    #[no_mangle]
    fn sched_setaffinity(__pid: __pid_t, __cpusetsize: size_t,
                         __cpuset: *const cpu_set_t) -> libc::c_int;
    #[no_mangle]
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    #[no_mangle]
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn fgets(__s: *mut libc::c_char, __n: libc::c_int, __stream: *mut FILE)
     -> *mut libc::c_char;
}
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type pid_t = __pid_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type size_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub type u32_0 = uint32_t;
pub type s32 = int32_t;
pub type s64 = int64_t;
pub type C2RustUnnamed = libc::c_uint;
pub const _SC_THREAD_ROBUST_PRIO_PROTECT: C2RustUnnamed = 248;
pub const _SC_THREAD_ROBUST_PRIO_INHERIT: C2RustUnnamed = 247;
pub const _SC_XOPEN_STREAMS: C2RustUnnamed = 246;
pub const _SC_TRACE_USER_EVENT_MAX: C2RustUnnamed = 245;
pub const _SC_TRACE_SYS_MAX: C2RustUnnamed = 244;
pub const _SC_TRACE_NAME_MAX: C2RustUnnamed = 243;
pub const _SC_TRACE_EVENT_NAME_MAX: C2RustUnnamed = 242;
pub const _SC_SS_REPL_MAX: C2RustUnnamed = 241;
pub const _SC_V7_LPBIG_OFFBIG: C2RustUnnamed = 240;
pub const _SC_V7_LP64_OFF64: C2RustUnnamed = 239;
pub const _SC_V7_ILP32_OFFBIG: C2RustUnnamed = 238;
pub const _SC_V7_ILP32_OFF32: C2RustUnnamed = 237;
pub const _SC_RAW_SOCKETS: C2RustUnnamed = 236;
pub const _SC_IPV6: C2RustUnnamed = 235;
pub const _SC_LEVEL4_CACHE_LINESIZE: C2RustUnnamed = 199;
pub const _SC_LEVEL4_CACHE_ASSOC: C2RustUnnamed = 198;
pub const _SC_LEVEL4_CACHE_SIZE: C2RustUnnamed = 197;
pub const _SC_LEVEL3_CACHE_LINESIZE: C2RustUnnamed = 196;
pub const _SC_LEVEL3_CACHE_ASSOC: C2RustUnnamed = 195;
pub const _SC_LEVEL3_CACHE_SIZE: C2RustUnnamed = 194;
pub const _SC_LEVEL2_CACHE_LINESIZE: C2RustUnnamed = 193;
pub const _SC_LEVEL2_CACHE_ASSOC: C2RustUnnamed = 192;
pub const _SC_LEVEL2_CACHE_SIZE: C2RustUnnamed = 191;
pub const _SC_LEVEL1_DCACHE_LINESIZE: C2RustUnnamed = 190;
pub const _SC_LEVEL1_DCACHE_ASSOC: C2RustUnnamed = 189;
pub const _SC_LEVEL1_DCACHE_SIZE: C2RustUnnamed = 188;
pub const _SC_LEVEL1_ICACHE_LINESIZE: C2RustUnnamed = 187;
pub const _SC_LEVEL1_ICACHE_ASSOC: C2RustUnnamed = 186;
pub const _SC_LEVEL1_ICACHE_SIZE: C2RustUnnamed = 185;
pub const _SC_TRACE_LOG: C2RustUnnamed = 184;
pub const _SC_TRACE_INHERIT: C2RustUnnamed = 183;
pub const _SC_TRACE_EVENT_FILTER: C2RustUnnamed = 182;
pub const _SC_TRACE: C2RustUnnamed = 181;
pub const _SC_HOST_NAME_MAX: C2RustUnnamed = 180;
pub const _SC_V6_LPBIG_OFFBIG: C2RustUnnamed = 179;
pub const _SC_V6_LP64_OFF64: C2RustUnnamed = 178;
pub const _SC_V6_ILP32_OFFBIG: C2RustUnnamed = 177;
pub const _SC_V6_ILP32_OFF32: C2RustUnnamed = 176;
pub const _SC_2_PBS_CHECKPOINT: C2RustUnnamed = 175;
pub const _SC_STREAMS: C2RustUnnamed = 174;
pub const _SC_SYMLOOP_MAX: C2RustUnnamed = 173;
pub const _SC_2_PBS_TRACK: C2RustUnnamed = 172;
pub const _SC_2_PBS_MESSAGE: C2RustUnnamed = 171;
pub const _SC_2_PBS_LOCATE: C2RustUnnamed = 170;
pub const _SC_2_PBS_ACCOUNTING: C2RustUnnamed = 169;
pub const _SC_2_PBS: C2RustUnnamed = 168;
pub const _SC_USER_GROUPS_R: C2RustUnnamed = 167;
pub const _SC_USER_GROUPS: C2RustUnnamed = 166;
pub const _SC_TYPED_MEMORY_OBJECTS: C2RustUnnamed = 165;
pub const _SC_TIMEOUTS: C2RustUnnamed = 164;
pub const _SC_SYSTEM_DATABASE_R: C2RustUnnamed = 163;
pub const _SC_SYSTEM_DATABASE: C2RustUnnamed = 162;
pub const _SC_THREAD_SPORADIC_SERVER: C2RustUnnamed = 161;
pub const _SC_SPORADIC_SERVER: C2RustUnnamed = 160;
pub const _SC_SPAWN: C2RustUnnamed = 159;
pub const _SC_SIGNALS: C2RustUnnamed = 158;
pub const _SC_SHELL: C2RustUnnamed = 157;
pub const _SC_REGEX_VERSION: C2RustUnnamed = 156;
pub const _SC_REGEXP: C2RustUnnamed = 155;
pub const _SC_SPIN_LOCKS: C2RustUnnamed = 154;
pub const _SC_READER_WRITER_LOCKS: C2RustUnnamed = 153;
pub const _SC_NETWORKING: C2RustUnnamed = 152;
pub const _SC_SINGLE_PROCESS: C2RustUnnamed = 151;
pub const _SC_MULTI_PROCESS: C2RustUnnamed = 150;
pub const _SC_MONOTONIC_CLOCK: C2RustUnnamed = 149;
pub const _SC_FILE_SYSTEM: C2RustUnnamed = 148;
pub const _SC_FILE_LOCKING: C2RustUnnamed = 147;
pub const _SC_FILE_ATTRIBUTES: C2RustUnnamed = 146;
pub const _SC_PIPE: C2RustUnnamed = 145;
pub const _SC_FIFO: C2RustUnnamed = 144;
pub const _SC_FD_MGMT: C2RustUnnamed = 143;
pub const _SC_DEVICE_SPECIFIC_R: C2RustUnnamed = 142;
pub const _SC_DEVICE_SPECIFIC: C2RustUnnamed = 141;
pub const _SC_DEVICE_IO: C2RustUnnamed = 140;
pub const _SC_THREAD_CPUTIME: C2RustUnnamed = 139;
pub const _SC_CPUTIME: C2RustUnnamed = 138;
pub const _SC_CLOCK_SELECTION: C2RustUnnamed = 137;
pub const _SC_C_LANG_SUPPORT_R: C2RustUnnamed = 136;
pub const _SC_C_LANG_SUPPORT: C2RustUnnamed = 135;
pub const _SC_BASE: C2RustUnnamed = 134;
pub const _SC_BARRIERS: C2RustUnnamed = 133;
pub const _SC_ADVISORY_INFO: C2RustUnnamed = 132;
pub const _SC_XOPEN_REALTIME_THREADS: C2RustUnnamed = 131;
pub const _SC_XOPEN_REALTIME: C2RustUnnamed = 130;
pub const _SC_XOPEN_LEGACY: C2RustUnnamed = 129;
pub const _SC_XBS5_LPBIG_OFFBIG: C2RustUnnamed = 128;
pub const _SC_XBS5_LP64_OFF64: C2RustUnnamed = 127;
pub const _SC_XBS5_ILP32_OFFBIG: C2RustUnnamed = 126;
pub const _SC_XBS5_ILP32_OFF32: C2RustUnnamed = 125;
pub const _SC_NL_TEXTMAX: C2RustUnnamed = 124;
pub const _SC_NL_SETMAX: C2RustUnnamed = 123;
pub const _SC_NL_NMAX: C2RustUnnamed = 122;
pub const _SC_NL_MSGMAX: C2RustUnnamed = 121;
pub const _SC_NL_LANGMAX: C2RustUnnamed = 120;
pub const _SC_NL_ARGMAX: C2RustUnnamed = 119;
pub const _SC_USHRT_MAX: C2RustUnnamed = 118;
pub const _SC_ULONG_MAX: C2RustUnnamed = 117;
pub const _SC_UINT_MAX: C2RustUnnamed = 116;
pub const _SC_UCHAR_MAX: C2RustUnnamed = 115;
pub const _SC_SHRT_MIN: C2RustUnnamed = 114;
pub const _SC_SHRT_MAX: C2RustUnnamed = 113;
pub const _SC_SCHAR_MIN: C2RustUnnamed = 112;
pub const _SC_SCHAR_MAX: C2RustUnnamed = 111;
pub const _SC_SSIZE_MAX: C2RustUnnamed = 110;
pub const _SC_NZERO: C2RustUnnamed = 109;
pub const _SC_MB_LEN_MAX: C2RustUnnamed = 108;
pub const _SC_WORD_BIT: C2RustUnnamed = 107;
pub const _SC_LONG_BIT: C2RustUnnamed = 106;
pub const _SC_INT_MIN: C2RustUnnamed = 105;
pub const _SC_INT_MAX: C2RustUnnamed = 104;
pub const _SC_CHAR_MIN: C2RustUnnamed = 103;
pub const _SC_CHAR_MAX: C2RustUnnamed = 102;
pub const _SC_CHAR_BIT: C2RustUnnamed = 101;
pub const _SC_XOPEN_XPG4: C2RustUnnamed = 100;
pub const _SC_XOPEN_XPG3: C2RustUnnamed = 99;
pub const _SC_XOPEN_XPG2: C2RustUnnamed = 98;
pub const _SC_2_UPE: C2RustUnnamed = 97;
pub const _SC_2_C_VERSION: C2RustUnnamed = 96;
pub const _SC_2_CHAR_TERM: C2RustUnnamed = 95;
pub const _SC_XOPEN_SHM: C2RustUnnamed = 94;
pub const _SC_XOPEN_ENH_I18N: C2RustUnnamed = 93;
pub const _SC_XOPEN_CRYPT: C2RustUnnamed = 92;
pub const _SC_XOPEN_UNIX: C2RustUnnamed = 91;
pub const _SC_XOPEN_XCU_VERSION: C2RustUnnamed = 90;
pub const _SC_XOPEN_VERSION: C2RustUnnamed = 89;
pub const _SC_PASS_MAX: C2RustUnnamed = 88;
pub const _SC_ATEXIT_MAX: C2RustUnnamed = 87;
pub const _SC_AVPHYS_PAGES: C2RustUnnamed = 86;
pub const _SC_PHYS_PAGES: C2RustUnnamed = 85;
pub const _SC_NPROCESSORS_ONLN: C2RustUnnamed = 84;
pub const _SC_NPROCESSORS_CONF: C2RustUnnamed = 83;
pub const _SC_THREAD_PROCESS_SHARED: C2RustUnnamed = 82;
pub const _SC_THREAD_PRIO_PROTECT: C2RustUnnamed = 81;
pub const _SC_THREAD_PRIO_INHERIT: C2RustUnnamed = 80;
pub const _SC_THREAD_PRIORITY_SCHEDULING: C2RustUnnamed = 79;
pub const _SC_THREAD_ATTR_STACKSIZE: C2RustUnnamed = 78;
pub const _SC_THREAD_ATTR_STACKADDR: C2RustUnnamed = 77;
pub const _SC_THREAD_THREADS_MAX: C2RustUnnamed = 76;
pub const _SC_THREAD_STACK_MIN: C2RustUnnamed = 75;
pub const _SC_THREAD_KEYS_MAX: C2RustUnnamed = 74;
pub const _SC_THREAD_DESTRUCTOR_ITERATIONS: C2RustUnnamed = 73;
pub const _SC_TTY_NAME_MAX: C2RustUnnamed = 72;
pub const _SC_LOGIN_NAME_MAX: C2RustUnnamed = 71;
pub const _SC_GETPW_R_SIZE_MAX: C2RustUnnamed = 70;
pub const _SC_GETGR_R_SIZE_MAX: C2RustUnnamed = 69;
pub const _SC_THREAD_SAFE_FUNCTIONS: C2RustUnnamed = 68;
pub const _SC_THREADS: C2RustUnnamed = 67;
pub const _SC_T_IOV_MAX: C2RustUnnamed = 66;
pub const _SC_PII_OSI_M: C2RustUnnamed = 65;
pub const _SC_PII_OSI_CLTS: C2RustUnnamed = 64;
pub const _SC_PII_OSI_COTS: C2RustUnnamed = 63;
pub const _SC_PII_INTERNET_DGRAM: C2RustUnnamed = 62;
pub const _SC_PII_INTERNET_STREAM: C2RustUnnamed = 61;
pub const _SC_IOV_MAX: C2RustUnnamed = 60;
pub const _SC_UIO_MAXIOV: C2RustUnnamed = 60;
pub const _SC_SELECT: C2RustUnnamed = 59;
pub const _SC_POLL: C2RustUnnamed = 58;
pub const _SC_PII_OSI: C2RustUnnamed = 57;
pub const _SC_PII_INTERNET: C2RustUnnamed = 56;
pub const _SC_PII_SOCKET: C2RustUnnamed = 55;
pub const _SC_PII_XTI: C2RustUnnamed = 54;
pub const _SC_PII: C2RustUnnamed = 53;
pub const _SC_2_LOCALEDEF: C2RustUnnamed = 52;
pub const _SC_2_SW_DEV: C2RustUnnamed = 51;
pub const _SC_2_FORT_RUN: C2RustUnnamed = 50;
pub const _SC_2_FORT_DEV: C2RustUnnamed = 49;
pub const _SC_2_C_DEV: C2RustUnnamed = 48;
pub const _SC_2_C_BIND: C2RustUnnamed = 47;
pub const _SC_2_VERSION: C2RustUnnamed = 46;
pub const _SC_CHARCLASS_NAME_MAX: C2RustUnnamed = 45;
pub const _SC_RE_DUP_MAX: C2RustUnnamed = 44;
pub const _SC_LINE_MAX: C2RustUnnamed = 43;
pub const _SC_EXPR_NEST_MAX: C2RustUnnamed = 42;
pub const _SC_EQUIV_CLASS_MAX: C2RustUnnamed = 41;
pub const _SC_COLL_WEIGHTS_MAX: C2RustUnnamed = 40;
pub const _SC_BC_STRING_MAX: C2RustUnnamed = 39;
pub const _SC_BC_SCALE_MAX: C2RustUnnamed = 38;
pub const _SC_BC_DIM_MAX: C2RustUnnamed = 37;
pub const _SC_BC_BASE_MAX: C2RustUnnamed = 36;
pub const _SC_TIMER_MAX: C2RustUnnamed = 35;
pub const _SC_SIGQUEUE_MAX: C2RustUnnamed = 34;
pub const _SC_SEM_VALUE_MAX: C2RustUnnamed = 33;
pub const _SC_SEM_NSEMS_MAX: C2RustUnnamed = 32;
pub const _SC_RTSIG_MAX: C2RustUnnamed = 31;
pub const _SC_PAGESIZE: C2RustUnnamed = 30;
pub const _SC_VERSION: C2RustUnnamed = 29;
pub const _SC_MQ_PRIO_MAX: C2RustUnnamed = 28;
pub const _SC_MQ_OPEN_MAX: C2RustUnnamed = 27;
pub const _SC_DELAYTIMER_MAX: C2RustUnnamed = 26;
pub const _SC_AIO_PRIO_DELTA_MAX: C2RustUnnamed = 25;
pub const _SC_AIO_MAX: C2RustUnnamed = 24;
pub const _SC_AIO_LISTIO_MAX: C2RustUnnamed = 23;
pub const _SC_SHARED_MEMORY_OBJECTS: C2RustUnnamed = 22;
pub const _SC_SEMAPHORES: C2RustUnnamed = 21;
pub const _SC_MESSAGE_PASSING: C2RustUnnamed = 20;
pub const _SC_MEMORY_PROTECTION: C2RustUnnamed = 19;
pub const _SC_MEMLOCK_RANGE: C2RustUnnamed = 18;
pub const _SC_MEMLOCK: C2RustUnnamed = 17;
pub const _SC_MAPPED_FILES: C2RustUnnamed = 16;
pub const _SC_FSYNC: C2RustUnnamed = 15;
pub const _SC_SYNCHRONIZED_IO: C2RustUnnamed = 14;
pub const _SC_PRIORITIZED_IO: C2RustUnnamed = 13;
pub const _SC_ASYNCHRONOUS_IO: C2RustUnnamed = 12;
pub const _SC_TIMERS: C2RustUnnamed = 11;
pub const _SC_PRIORITY_SCHEDULING: C2RustUnnamed = 10;
pub const _SC_REALTIME_SIGNALS: C2RustUnnamed = 9;
pub const _SC_SAVED_IDS: C2RustUnnamed = 8;
pub const _SC_JOB_CONTROL: C2RustUnnamed = 7;
pub const _SC_TZNAME_MAX: C2RustUnnamed = 6;
pub const _SC_STREAM_MAX: C2RustUnnamed = 5;
pub const _SC_OPEN_MAX: C2RustUnnamed = 4;
pub const _SC_NGROUPS_MAX: C2RustUnnamed = 3;
pub const _SC_CLK_TCK: C2RustUnnamed = 2;
pub const _SC_CHILD_MAX: C2RustUnnamed = 1;
pub const _SC_ARG_MAX: C2RustUnnamed = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dirent {
    pub d_ino: __ino_t,
    pub d_off: __off_t,
    pub d_reclen: libc::c_ushort,
    pub d_type: libc::c_uchar,
    pub d_name: [libc::c_char; 256],
}
pub type DIR = __dirstream;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
pub type __cpu_mask = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cpu_set_t {
    pub __bits: [__cpu_mask; 16],
}
pub type C2RustUnnamed_0 = libc::c_uint;
pub const _ISalnum: C2RustUnnamed_0 = 8;
pub const _ISpunct: C2RustUnnamed_0 = 4;
pub const _IScntrl: C2RustUnnamed_0 = 2;
pub const _ISblank: C2RustUnnamed_0 = 1;
pub const _ISgraph: C2RustUnnamed_0 = 32768;
pub const _ISprint: C2RustUnnamed_0 = 16384;
pub const _ISspace: C2RustUnnamed_0 = 8192;
pub const _ISxdigit: C2RustUnnamed_0 = 4096;
pub const _ISdigit: C2RustUnnamed_0 = 2048;
pub const _ISalpha: C2RustUnnamed_0 = 1024;
pub const _ISlower: C2RustUnnamed_0 = 512;
pub const _ISupper: C2RustUnnamed_0 = 256;
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
pub type afl_exit_t = afl_exit;
pub type afl_fork_result = libc::c_uint;
pub const PARENT: afl_fork_result = 2;
pub const CHILD: afl_fork_result = 1;
pub const FORK_FAILED: afl_fork_result = 0;
pub type afl_fork_result_t = afl_fork_result;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_os {
    pub current: Option<unsafe extern "C" fn(_: *mut afl_os) -> *mut afl_os>,
    pub fork: Option<unsafe extern "C" fn(_: *mut afl_os)
                         -> afl_fork_result_t>,
    pub suspend: Option<unsafe extern "C" fn(_: *mut afl_os) -> ()>,
    pub resume: Option<unsafe extern "C" fn(_: *mut afl_os) -> ()>,
    pub wait: Option<unsafe extern "C" fn(_: *mut afl_os, _: bool)
                         -> afl_exit_t>,
    pub handler_process: pid_t,
}
pub type afl_os_t = afl_os;
#[inline]
unsafe extern "C" fn atoi(mut __nptr: *const libc::c_char) -> libc::c_int {
    return strtol(__nptr, 0 as *mut libc::c_void as *mut *mut libc::c_char,
                  10 as libc::c_int) as libc::c_int;
}
#[inline]
unsafe extern "C" fn stat(mut __path: *const libc::c_char,
                          mut __statbuf: *mut stat) -> libc::c_int {
    return __xstat(1 as libc::c_int, __path, __statbuf);
}
/* __APPLE__ || __FreeBSD__ || __OpenBSD__ */
/* __linux__ */
// Process related functions
#[no_mangle]
pub unsafe extern "C" fn _afl_process_init_internal(mut afl_os:
                                                        *mut afl_os_t) {
    (*afl_os).fork =
        Some(afl_proc_fork as
                 unsafe extern "C" fn(_: *mut afl_os_t)
                     ->
                         afl_fork_result_t); // Waitpid fails here, how should we handle this?
    (*afl_os).resume =
        Some(afl_proc_resume as unsafe extern "C" fn(_: *mut afl_os_t) -> ());
    (*afl_os).wait =
        Some(afl_proc_wait as
                 unsafe extern "C" fn(_: *mut afl_os_t, _: bool)
                     -> afl_exit_t);
    (*afl_os).suspend =
        Some(afl_proc_suspend as
                 unsafe extern "C" fn(_: *mut afl_os_t) -> ());
}
#[no_mangle]
pub unsafe extern "C" fn afl_proc_fork(mut afl_os: *mut afl_os_t)
 -> afl_fork_result_t {
    let mut child: pid_t = fork();
    if child == 0 as libc::c_int {
        return CHILD
    } else { if child < 0 as libc::c_int { return FORK_FAILED } }
    (*afl_os).handler_process = child;
    return PARENT;
}
#[no_mangle]
pub unsafe extern "C" fn afl_proc_suspend(mut afl_os: *mut afl_os_t) {
    kill((*afl_os).handler_process, 19 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn afl_proc_resume(mut afl_os: *mut afl_os_t) {
    kill((*afl_os).handler_process, 18 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn afl_proc_wait(mut afl_os: *mut afl_os_t,
                                       mut untraced: bool) -> afl_exit_t {
    let mut status: libc::c_int = 0 as libc::c_int;
    if waitpid((*afl_os).handler_process, &mut status,
               (if untraced as libc::c_int != 0 {
                    2 as libc::c_int
                } else { 0 as libc::c_int })) < 0 as libc::c_int {
        return 4294967295 as afl_exit_t
    }
    if status & 0x7f as libc::c_int == 0 as libc::c_int { return AFL_EXIT_OK }
    // If the afl_os was simply stopped , we return AFL_EXIT_STOP
    if status & 0xff as libc::c_int == 0x7f as libc::c_int {
        return AFL_EXIT_STOP
    }
    // If the afl_os exited with a signal, we check the corresponsing signum of
  // the afl_os and return values correspondingly
    if ((status & 0x7f as libc::c_int) + 1 as libc::c_int) as libc::c_schar as
           libc::c_int >> 1 as libc::c_int > 0 as libc::c_int {
        let mut signal_num: libc::c_int =
            status & 0x7f as libc::c_int; // signal number
        match signal_num {
            9 => { return AFL_EXIT_TIMEOUT }
            11 => { return AFL_EXIT_SEGV }
            6 => { return AFL_EXIT_ABRT }
            7 => { return AFL_EXIT_BUS }
            4 => { return AFL_EXIT_ILL }
            _ => {
                /* Any other SIGNAL we need to take care of? */
                return AFL_EXIT_CRASH
            }
        }
    } else {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mBUG: Currently Unhandled\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 14],
                                         &[libc::c_char; 14]>(b"afl_proc_wait\x00")).as_ptr(),
               b"src/os.c\x00" as *const u8 as *const libc::c_char,
               124 as libc::c_int);
        exit(1 as libc::c_int);
    };
}
unsafe extern "C" fn __afl_for_each_file(mut dirpath: *mut libc::c_char,
                                         mut handle_file:
                                             Option<unsafe extern "C" fn(_:
                                                                             *mut libc::c_char,
                                                                         _:
                                                                             *mut libc::c_void)
                                                        -> bool>,
                                         mut data: *mut libc::c_void)
 -> afl_ret_t {
    let mut dir_in: *mut DIR = 0 as *mut DIR;
    let mut dir_ent: *mut dirent = 0 as *mut dirent;
    let mut infile: [libc::c_char; 4096] = [0; 4096];
    let mut ok: uint32_t = 0 as libc::c_int as uint32_t;
    dir_in = opendir(dirpath);
    if dir_in.is_null() { return AFL_RET_FILE_OPEN_ERROR }
    loop  {
        dir_ent = readdir(dir_in);
        if dir_ent.is_null() {
            break ;
            // skip anything that starts with '.'
        }
        if (*dir_ent).d_name[0 as libc::c_int as usize] as libc::c_int ==
               '.' as i32 {
            continue ;
        }
        snprintf(infile.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 4096]>() as
                     libc::c_ulong,
                 b"%s/%s\x00" as *const u8 as *const libc::c_char, dirpath,
                 (*dir_ent).d_name.as_mut_ptr());
        infile[(::std::mem::size_of::<[libc::c_char; 4096]>() as
                    libc::c_ulong).wrapping_sub(1 as libc::c_int as
                                                    libc::c_ulong) as usize] =
            '\u{0}' as i32 as libc::c_char;
        /* TODO: Error handling? */
        let mut st: stat =
            stat{st_dev: 0,
                 st_ino: 0,
                 st_nlink: 0,
                 st_mode: 0,
                 st_uid: 0,
                 st_gid: 0,
                 __pad0: 0,
                 st_rdev: 0,
                 st_size: 0,
                 st_blksize: 0,
                 st_blocks: 0,
                 st_atim: timespec{tv_sec: 0, tv_nsec: 0,},
                 st_mtim: timespec{tv_sec: 0, tv_nsec: 0,},
                 st_ctim: timespec{tv_sec: 0, tv_nsec: 0,},
                 __glibc_reserved: [0; 3],};
        if access(infile.as_mut_ptr(), 4 as libc::c_int) != 0 as libc::c_int
               || stat(infile.as_mut_ptr(), &mut st) != 0 as libc::c_int {
            continue ;
        }
        if st.st_mode & 0o170000 as libc::c_int as libc::c_uint ==
               0o40000 as libc::c_int as libc::c_uint {
            if __afl_for_each_file(infile.as_mut_ptr(), handle_file, data) as
                   libc::c_uint ==
                   AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                ok = 1 as libc::c_int as uint32_t
            }
        } else {
            if !(st.st_mode & 0o170000 as libc::c_int as libc::c_uint ==
                     0o100000 as libc::c_int as libc::c_uint) ||
                   st.st_size == 0 as libc::c_int as libc::c_long {
                continue ;
            }
            if handle_file.expect("non-null function pointer")(infile.as_mut_ptr(),
                                                               data) as
                   libc::c_int == 1 as libc::c_int {
                ok = 1 as libc::c_int as uint32_t
            }
        }
    }
    closedir(dir_in);
    if ok != 0 { return AFL_RET_SUCCESS } else { return AFL_RET_EMPTY };
}
/* Run `handle_file` for each file in the dirpath, recursively.
void *data will be passed to handle_file as 2nd param.
if handle_file returns false, further execution stops. */
/* Run `handle_file` for each file in the dirpath, recursively.
void *data will be passed to handle_file as 2nd param.
if handle_file returns false, further execution stops. */
#[no_mangle]
pub unsafe extern "C" fn afl_for_each_file(mut dirpath: *mut libc::c_char,
                                           mut handle_file:
                                               Option<unsafe extern "C" fn(_:
                                                                               *mut libc::c_char,
                                                                           _:
                                                                               *mut libc::c_void)
                                                          -> bool>,
                                           mut data: *mut libc::c_void)
 -> afl_ret_t {
    let mut dir_name_size: size_t = strlen(dirpath);
    if *dirpath.offset(dir_name_size.wrapping_sub(1 as libc::c_int as
                                                      libc::c_ulong) as isize)
           as libc::c_int == '/' as i32 {
        *dirpath.offset(dir_name_size.wrapping_sub(1 as libc::c_int as
                                                       libc::c_ulong) as
                            isize) = '\u{0}' as i32 as libc::c_char
    }
    if access(dirpath, 4 as libc::c_int | 1 as libc::c_int) !=
           0 as libc::c_int {
        return AFL_RET_FILE_OPEN_ERROR
    }
    return __afl_for_each_file(dirpath, handle_file, data);
}
/* WIP: Let's implement a simple function which binds the cpu to the current process
   The code is very similar to how we do it in AFL++ */
/* bind process to a specific cpu. Returns 0 on failure. */
unsafe extern "C" fn bind_cpu(mut cpuid: s32) -> u8_0 {
    let mut c: cpu_set_t = cpu_set_t{__bits: [0; 16],};
    libc::memset(&mut c as *mut cpu_set_t as *mut libc::c_void,
                 '\u{0}' as i32,
                 ::std::mem::size_of::<cpu_set_t>() as libc::c_ulong as
                     libc::size_t);
    let mut __cpu: size_t = cpuid as size_t;
    if __cpu.wrapping_div(8 as libc::c_int as libc::c_ulong) <
           ::std::mem::size_of::<cpu_set_t>() as libc::c_ulong {
        let ref mut fresh0 =
            *c.__bits.as_mut_ptr().offset(__cpu.wrapping_div((8 as libc::c_int
                                                                  as
                                                                  libc::c_ulong).wrapping_mul(::std::mem::size_of::<__cpu_mask>()
                                                                                                  as
                                                                                                  libc::c_ulong))
                                              as isize);
        *fresh0 |=
            (1 as libc::c_int as __cpu_mask) <<
                __cpu.wrapping_rem((8 as libc::c_int as
                                        libc::c_ulong).wrapping_mul(::std::mem::size_of::<__cpu_mask>()
                                                                        as
                                                                        libc::c_ulong))
    } else { };
    return (sched_setaffinity(0 as libc::c_int,
                              ::std::mem::size_of::<cpu_set_t>() as
                                  libc::c_ulong, &mut c) == 0 as libc::c_int)
               as libc::c_int as u8_0;
}
/* Get the number of runnable processes, with some simple smoothing. */
#[no_mangle]
pub unsafe extern "C" fn get_runnable_processes() -> libc::c_double {
    let mut res: libc::c_double = 0 as libc::c_int as libc::c_double;
    /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */
    let mut f: *mut FILE =
        fopen(b"/proc/stat\x00" as *const u8 as *const libc::c_char,
              b"r\x00" as *const u8 as *const libc::c_char);
    let mut tmp: [libc::c_char; 1024] = [0; 1024];
    let mut val: u32_0 = 0 as libc::c_int as u32_0;
    if f.is_null() { return 0 as libc::c_int as libc::c_double }
    while !fgets(tmp.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 1024]>() as
                     libc::c_ulong as libc::c_int, f).is_null() {
        if strncmp(tmp.as_mut_ptr(),
                   b"procs_running \x00" as *const u8 as *const libc::c_char,
                   14 as libc::c_int as libc::c_ulong) == 0 ||
               strncmp(tmp.as_mut_ptr(),
                       b"procs_blocked \x00" as *const u8 as
                           *const libc::c_char,
                       14 as libc::c_int as libc::c_ulong) == 0 {
            val =
                (val as
                     libc::c_uint).wrapping_add(atoi(tmp.as_mut_ptr().offset(14
                                                                                 as
                                                                                 libc::c_int
                                                                                 as
                                                                                 isize))
                                                    as libc::c_uint) as u32_0
                    as u32_0
        }
    }
    fclose(f);
    if res == 0. {
        res = val as libc::c_double
    } else {
        res =
            res * (1.0f64 - 1.0f64 / 16 as libc::c_int as libc::c_double) +
                val as libc::c_double *
                    (1.0f64 / 16 as libc::c_int as libc::c_double)
    }
    /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__ || __NetBSD__) */
    return res;
}
/* Count the number of logical CPU cores. */
#[no_mangle]
pub unsafe extern "C" fn get_core_count() -> s32 {
    let mut cpu_core_count: s32 = 0 as libc::c_int;
    cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN as libc::c_int) as s32;
    /* ^HAVE_AFFINITY */
    /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */
    if cpu_core_count > 0 as libc::c_int {
        let mut cur_runnable: u32_0 = 0 as libc::c_int as u32_0;
        cur_runnable = get_runnable_processes() as u32_0;
        /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */
        printf(b"\x1b[1;92m[+] \x1b[0mYou have %d CPU core%s and %u runnable tasks (utilization: %0.0f%%).\x00"
                   as *const u8 as *const libc::c_char, cpu_core_count,
               if cpu_core_count > 1 as libc::c_int {
                   b"s\x00" as *const u8 as *const libc::c_char
               } else { b"\x00" as *const u8 as *const libc::c_char },
               cur_runnable,
               cur_runnable as libc::c_double * 100.0f64 /
                   cpu_core_count as libc::c_double);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        if cpu_core_count > 1 as libc::c_int {
            if cur_runnable as libc::c_double >
                   cpu_core_count as libc::c_double * 1.5f64 {
                printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mSystem under apparent load, performance may be spotty.\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            } else if cur_runnable as s64 + 1 as libc::c_int as libc::c_long
                          <= cpu_core_count as s64 {
                printf(b"\x1b[1;92m[+] \x1b[0mTry parallel jobs\x00" as
                           *const u8 as *const libc::c_char);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            }
        }
    } else {
        cpu_core_count = 0 as libc::c_int;
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mUnable to figure out the number of CPU cores.\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    }
    return cpu_core_count;
}
#[no_mangle]
pub unsafe extern "C" fn bind_to_cpu() -> afl_ret_t {
    let mut cpu_used: [u8_0; 4096] = [0; 4096];
    let mut i: s32 = 0;
    // Let's open up /proc and check if there are any CPU cores available
    let mut proc_0: *mut DIR =
        0 as *mut DIR; // Leave files which aren't process files
    let mut dir_entry: *mut dirent = 0 as *mut dirent;
    proc_0 = opendir(b"/proc\x00" as *const u8 as *const libc::c_char);
    loop  {
        dir_entry = readdir(proc_0);
        if dir_entry.is_null() { break ; }
        if *(*__ctype_b_loc()).offset((*dir_entry).d_name[0 as libc::c_int as
                                                              usize] as
                                          libc::c_int as isize) as libc::c_int
               & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int == 0
           {
            continue ;
        }
        let mut fn_0: [libc::c_char; 4096] = [0; 4096];
        let mut tmp: [libc::c_char; 8192] = [0; 8192];
        let mut f: *mut FILE = 0 as *mut FILE;
        let mut has_vmsize: u8_0 = 0 as libc::c_int as u8_0;
        snprintf(fn_0.as_mut_ptr(), 4096 as libc::c_int as libc::c_ulong,
                 b"/proc/%s/status\x00" as *const u8 as *const libc::c_char,
                 (*dir_entry).d_name.as_mut_ptr());
        f =
            fopen(fn_0.as_mut_ptr(),
                  b"r\x00" as *const u8 as *const libc::c_char);
        if f.is_null() { continue ; }
        while !fgets(tmp.as_mut_ptr(), 8192 as libc::c_int, f).is_null() {
            let mut hval: u32_0 = 0;
            /* Processes without VmSize are probably kernel tasks. */
            if strncmp(tmp.as_mut_ptr(),
                       b"VmSize:\t\x00" as *const u8 as *const libc::c_char,
                       8 as libc::c_int as libc::c_ulong) == 0 {
                has_vmsize = 1 as libc::c_int as u8_0
            }
            if !(strncmp(tmp.as_mut_ptr(),
                         b"Cpus_allowed_list:\t\x00" as *const u8 as
                             *const libc::c_char,
                         19 as libc::c_int as libc::c_ulong) == 0 &&
                     strchr(tmp.as_mut_ptr(), '-' as i32).is_null() &&
                     strchr(tmp.as_mut_ptr(), ',' as i32).is_null() &&
                     sscanf(tmp.as_mut_ptr().offset(19 as libc::c_int as
                                                        isize),
                            b"%u\x00" as *const u8 as *const libc::c_char,
                            &mut hval as *mut u32_0) == 1 as libc::c_int &&
                     (hval as libc::c_ulong) <
                         ::std::mem::size_of::<[u8_0; 4096]>() as
                             libc::c_ulong && has_vmsize as libc::c_int != 0)
               {
                continue ;
            }
            cpu_used[hval as usize] = 1 as libc::c_int as u8_0;
            break ;
        }
        fclose(f);
    }
    closedir(proc_0);
    let mut cpu_start: size_t = 0 as libc::c_int as size_t;
    let mut cpu_core_count: s32 = get_core_count();
    i = cpu_start as s32;
    while i < cpu_core_count {
        if !(cpu_used[i as usize] != 0) {
            printf(b"\x1b[1;92m[+] \x1b[0mFound a free CPU core, try binding to #%u.\x00"
                       as *const u8 as *const libc::c_char, i);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            if bind_cpu(i) != 0 { break ; }
            printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0msetaffinity failed to CPU %d, trying next CPU\x00"
                       as *const u8 as *const libc::c_char, i);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            cpu_start = cpu_start.wrapping_add(1)
        }
        i += 1
    }
    return AFL_RET_SUCCESS;
}
