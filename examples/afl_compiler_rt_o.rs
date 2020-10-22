use ::libc;
use ::c2rust_bitfields;
extern "C" {
    #[no_mangle]
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char,
              _: libc::c_int) -> libc::c_long;
    #[no_mangle]
    fn random() -> libc::c_long;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn abort() -> !;
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
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    static mut stderr: *mut _IO_FILE;
    #[no_mangle]
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn perror(__s: *const libc::c_char);
    #[no_mangle]
    fn signal(__sig: libc::c_int, __handler: __sighandler_t)
     -> __sighandler_t;
    #[no_mangle]
    fn kill(__pid: __pid_t, __sig: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn raise(__sig: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn close(__fd: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
    #[no_mangle]
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t)
     -> ssize_t;
    #[no_mangle]
    fn _exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn sysconf(__name: libc::c_int) -> libc::c_long;
    #[no_mangle]
    fn fork() -> __pid_t;
    #[no_mangle]
    fn mmap(__addr: *mut libc::c_void, __len: size_t, __prot: libc::c_int,
            __flags: libc::c_int, __fd: libc::c_int, __offset: __off_t)
     -> *mut libc::c_void;
    #[no_mangle]
    fn munmap(__addr: *mut libc::c_void, __len: size_t) -> libc::c_int;
    #[no_mangle]
    fn msync(__addr: *mut libc::c_void, __len: size_t, __flags: libc::c_int)
     -> libc::c_int;
    #[no_mangle]
    fn shmat(__shmid: libc::c_int, __shmaddr: *const libc::c_void,
             __shmflg: libc::c_int) -> *mut libc::c_void;
    #[no_mangle]
    fn waitpid(__pid: __pid_t, __stat_loc: *mut libc::c_int,
               __options: libc::c_int) -> __pid_t;
    #[no_mangle]
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn ioctl(__fd: libc::c_int, __request: libc::c_ulong, _: ...)
     -> libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __ssize_t = libc::c_long;
pub type int32_t = __int32_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
pub type ssize_t = __ssize_t;
pub type u8_0 = uint8_t;
pub type u16_0 = uint16_t;
pub type u32_0 = uint32_t;
pub type u64_0 = libc::c_ulonglong;
pub type s32 = int32_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C, packed)]
pub struct cmp_header {
    #[bitfield(name = "hits", ty = "libc::c_uint", bits = "0..=19")]
    #[bitfield(name = "cnt", ty = "libc::c_uint", bits = "20..=39")]
    #[bitfield(name = "id", ty = "libc::c_uint", bits = "40..=55")]
    #[bitfield(name = "shape", ty = "libc::c_uint", bits = "56..=60")]
    #[bitfield(name = "type_0", ty = "libc::c_uint", bits = "61..=61")]
    pub hits_cnt_id_shape_type_0: [u8; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cmp_operands {
    pub v0: u64_0,
    pub v1: u64_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cmpfn_operands {
    pub v0: [u8_0; 32],
    pub v1: [u8_0; 32],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cmp_map {
    pub headers: [cmp_header; 65536],
    pub log: [[cmp_operands; 256]; 65536],
}
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
pub type __sighandler_t = Option<unsafe extern "C" fn(_: libc::c_int) -> ()>;
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
pub type PREV_LOC_T = u16_0;
#[inline]
unsafe extern "C" fn atoi(mut __nptr: *const libc::c_char) -> libc::c_int {
    return strtol(__nptr, 0 as *mut libc::c_void as *mut *mut libc::c_char,
                  10 as libc::c_int) as libc::c_int;
}
/*
   american fuzzy lop++ - snapshot helpers routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

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
// From AFL-Snapshot-LKM/include/afl_snapshot.h (must be kept synced)
// Trace new mmaped ares and unmap them on restore.
// Do not snapshot any page (by default all writeable not-shared pages
// are shanpshotted.
// Snapshot file descriptor state, close newly opened descriptors
// Snapshot registers state
// Perform a restore when exit_group is invoked
// TODO(andrea) allow not COW snapshots (high perf on small processes)
// Disable COW, restore all the snapshotted pages
// Do not snapshot Stack pages
unsafe extern "C" fn afl_snapshot_take(mut config: libc::c_int)
 -> libc::c_int {
    return ioctl(afl_snapshot_dev_fd,
                 ((2 as libc::c_uint) <<
                      0 as libc::c_int + 8 as libc::c_int + 8 as libc::c_int +
                          14 as libc::c_int |
                      ((44313 as libc::c_int) <<
                           0 as libc::c_int + 8 as libc::c_int) as
                          libc::c_uint |
                      ((5 as libc::c_int) << 0 as libc::c_int) as
                          libc::c_uint) as libc::c_ulong |
                     (::std::mem::size_of::<libc::c_int>() as libc::c_ulong)
                         <<
                         0 as libc::c_int + 8 as libc::c_int +
                             8 as libc::c_int, config);
}
unsafe extern "C" fn afl_snapshot_init() -> libc::c_int {
    afl_snapshot_dev_fd =
        open(b"/dev/afl_snapshot\x00" as *const u8 as *const libc::c_char,
             0 as libc::c_int);
    return afl_snapshot_dev_fd;
}
static mut afl_snapshot_dev_fd: libc::c_int = 0;
#[no_mangle]
pub static mut __afl_area_initial: [u8_0; 256000] = [0; 256000];
#[no_mangle]
pub static mut __afl_area_ptr: *mut u8_0 =
    unsafe { __afl_area_initial.as_ptr() as *mut _ };
#[no_mangle]
pub static mut __afl_dictionary: *mut u8_0 = 0 as *const u8_0 as *mut u8_0;
#[no_mangle]
pub static mut __afl_fuzz_ptr: *mut u8_0 = 0 as *const u8_0 as *mut u8_0;
#[no_mangle]
pub static mut __afl_fuzz_len_dummy: u32_0 = 0;
#[no_mangle]
pub static mut __afl_fuzz_len: *mut u32_0 =
    unsafe { &__afl_fuzz_len_dummy as *const u32_0 as *mut u32_0 };
#[no_mangle]
pub static mut __afl_final_loc: u32_0 = 0;
#[no_mangle]
pub static mut __afl_map_size: u32_0 =
    ((1 as libc::c_int) << 16 as libc::c_int) as u32_0;
#[no_mangle]
pub static mut __afl_dictionary_len: u32_0 = 0;
#[no_mangle]
pub static mut __afl_map_addr: u64_0 = 0;
#[no_mangle]
#[thread_local]
pub static mut __afl_prev_loc: [PREV_LOC_T; 16] = [0; 16];
#[no_mangle]
#[thread_local]
pub static mut __afl_prev_ctx: u32_0 = 0;
#[no_mangle]
#[thread_local]
pub static mut __afl_cmp_counter: u32_0 = 0;
#[no_mangle]
pub static mut __afl_sharedmem_fuzzing: libc::c_int = 0;
/* not supported by c2rust atm -> use dummy function, then do this:
https://stackoverflow.com/questions/54999851/how-do-i-get-the-return-address-of-a-function
*/
#[no_mangle]
pub unsafe extern "C" fn fake__builtin_return_address(mut depth: u32_0)
 -> uintptr_t {
    return ::std::mem::transmute::<Option<unsafe extern "C" fn(_: u32_0)
                                              -> uintptr_t>,
                                   *mut libc::c_void>(Some(fake__builtin_return_address
                                                               as
                                                               unsafe extern "C" fn(_:
                                                                                        u32_0)
                                                                   ->
                                                                       uintptr_t))
               as uintptr_t;
}
#[no_mangle]
pub static mut __afl_cmp_map: *mut cmp_map =
    0 as *const cmp_map as *mut cmp_map;
/* Running in persistent mode? */
static mut is_persistent: u8_0 = 0;
/* Are we in sancov mode? */
static mut _is_sancov: u8_0 = 0;
/* Uninspired gcc plugin instrumentation */
#[no_mangle]
pub unsafe extern "C" fn __afl_trace(x: u32_0) {
    let mut prev: PREV_LOC_T = __afl_prev_loc[0 as libc::c_int as usize];
    __afl_prev_loc[0 as libc::c_int as usize] =
        (x >> 1 as libc::c_int) as PREV_LOC_T;
    let mut p: *mut u8_0 =
        &mut *__afl_area_ptr.offset((prev as libc::c_uint ^ x) as isize) as
            *mut u8_0;
    /* enable for neverZero feature. */
    let (fresh0, fresh1) = (*p).overflowing_add(1 as libc::c_int as u8_0);
    *p = fresh0;
    let mut c: u8_0 = fresh1 as u8_0;
    *p = (*p as libc::c_int + c as libc::c_int) as u8_0;
}
/* Error reporting to forkserver controller */
#[no_mangle]
pub unsafe extern "C" fn send_forkserver_error(mut error: libc::c_int) {
    let mut status: u32_0 = 0;
    if error == 0 || error > 0xffff as libc::c_int { return }
    status =
        0xf800008f as libc::c_uint |
            ((error & 0xffff as libc::c_int) << 8 as libc::c_int) as
                libc::c_uint;
    if write(198 as libc::c_int + 1 as libc::c_int,
             &mut status as *mut u32_0 as *mut libc::c_char as
                 *const libc::c_void, 4 as libc::c_int as size_t) !=
           4 as libc::c_int as libc::c_long {
        return
    };
}
/* SHM fuzzing setup. */
unsafe extern "C" fn __afl_map_shm_fuzz() {
    let mut id_str: *mut libc::c_char =
        getenv(b"__AFL_SHM_FUZZ_ID\x00" as *const u8 as *const libc::c_char);
    if !id_str.is_null() {
        let mut map: *mut u8_0 = 0 as *mut u8_0;
        let mut shm_id: u32_0 = atoi(id_str) as u32_0;
        map =
            shmat(shm_id as libc::c_int, 0 as *const libc::c_void,
                  0 as libc::c_int) as *mut u8_0;
        /* Whooooops. */
        if map.is_null() ||
               map == -(1 as libc::c_int) as *mut libc::c_void as *mut u8_0 {
            perror(b"Could not access fuzzign shared memory\x00" as *const u8
                       as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        __afl_fuzz_len = map as *mut u32_0;
        __afl_fuzz_ptr =
            map.offset(::std::mem::size_of::<u32_0>() as libc::c_ulong as
                           isize);
        if !getenv(b"AFL_DEBUG\x00" as *const u8 as
                       *const libc::c_char).is_null() {
            fprintf(stderr,
                    b"DEBUG: successfully got fuzzing shared memory\n\x00" as
                        *const u8 as *const libc::c_char);
        }
    } else {
        fprintf(stderr,
                b"Error: variable for fuzzing shared memory is not set\n\x00"
                    as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    };
}
/* SHM setup. */
unsafe extern "C" fn __afl_map_shm() {
    // we we are not running in afl ensure the map exists
    if __afl_area_ptr.is_null() {
        __afl_area_ptr = __afl_area_initial.as_mut_ptr()
    }
    let mut id_str: *mut libc::c_char =
        getenv(b"__AFL_SHM_ID\x00" as *const u8 as *const libc::c_char);
    if __afl_final_loc != 0 {
        if __afl_final_loc.wrapping_rem(8 as libc::c_int as libc::c_uint) != 0
           {
            __afl_final_loc =
                (__afl_final_loc.wrapping_add(7 as libc::c_int as
                                                  libc::c_uint) >>
                     3 as libc::c_int) << 3 as libc::c_int
        }
        __afl_map_size = __afl_final_loc;
        if __afl_final_loc >
               ((1 as libc::c_int) << 16 as libc::c_int) as libc::c_uint {
            let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut val: u32_0 = 0 as libc::c_int as u32_0;
            ptr =
                getenv(b"AFL_MAP_SIZE\x00" as *const u8 as
                           *const libc::c_char);
            if !ptr.is_null() { val = atoi(ptr) as u32_0 }
            if val < __afl_final_loc {
                if __afl_final_loc >
                       ((0xfffffe as libc::c_int >> 1 as libc::c_int) +
                            1 as libc::c_int) as libc::c_uint {
                    if getenv(b"AFL_QUIET\x00" as *const u8 as
                                  *const libc::c_char).is_null() {
                        fprintf(stderr,
                                b"Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to be able to run this instrumented program!\n\x00"
                                    as *const u8 as *const libc::c_char,
                                __afl_final_loc);
                    }
                    if !id_str.is_null() {
                        send_forkserver_error(1 as libc::c_int);
                        exit(-(1 as libc::c_int));
                    }
                } else if getenv(b"AFL_QUIET\x00" as *const u8 as
                                     *const libc::c_char).is_null() {
                    fprintf(stderr,
                            b"Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to be able to run this instrumented program!\n\x00"
                                as *const u8 as *const libc::c_char,
                            __afl_final_loc);
                }
            }
        }
    }
    /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */
    if !getenv(b"AFL_DEBUG\x00" as *const u8 as *const libc::c_char).is_null()
       {
        fprintf(stderr,
                b"DEBUG: id_str %s, __afl_area_ptr %p, __afl_area_initial %p, __afl_map_addr 0x%llx, MAP_SIZE %u, __afl_final_loc %u, max_size_forkserver %u/0x%x\n\x00"
                    as *const u8 as *const libc::c_char,
                if id_str.is_null() {
                    b"<null>\x00" as *const u8 as *const libc::c_char
                } else { id_str }, __afl_area_ptr,
                __afl_area_initial.as_mut_ptr(), __afl_map_addr,
                (1 as libc::c_int) << 16 as libc::c_int, __afl_final_loc,
                (0xfffffe as libc::c_int >> 1 as libc::c_int) +
                    1 as libc::c_int,
                (0xfffffe as libc::c_int >> 1 as libc::c_int) +
                    1 as libc::c_int);
    }
    if !id_str.is_null() {
        if !__afl_area_ptr.is_null() &&
               __afl_area_ptr != __afl_area_initial.as_mut_ptr() {
            if __afl_map_addr != 0 {
                munmap(__afl_map_addr as *mut libc::c_void,
                       __afl_final_loc as size_t);
            } else { free(__afl_area_ptr as *mut libc::c_void); }
            __afl_area_ptr = __afl_area_initial.as_mut_ptr()
        }
        let mut shm_id: u32_0 = atoi(id_str) as u32_0;
        __afl_area_ptr =
            shmat(shm_id as libc::c_int, __afl_map_addr as *mut libc::c_void,
                  0 as libc::c_int) as *mut u8_0;
        /* Whooooops. */
        if __afl_area_ptr ==
               -(1 as libc::c_int) as *mut libc::c_void as *mut u8_0 {
            if __afl_map_addr != 0 {
                send_forkserver_error(2 as libc::c_int);
            } else { send_forkserver_error(8 as libc::c_int); }
            _exit(1 as libc::c_int);
        }
        /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */
        *__afl_area_ptr.offset(0 as libc::c_int as isize) =
            1 as libc::c_int as u8_0
    } else if (__afl_area_ptr.is_null() ||
                   __afl_area_ptr == __afl_area_initial.as_mut_ptr()) &&
                  __afl_map_addr != 0 {
        __afl_area_ptr =
            mmap(__afl_map_addr as *mut libc::c_void,
                 __afl_map_size as size_t,
                 0x1 as libc::c_int | 0x2 as libc::c_int,
                 0x10 as libc::c_int | 0x1 as libc::c_int |
                     0x20 as libc::c_int, -(1 as libc::c_int),
                 0 as libc::c_int as __off_t) as
                *mut u8_0; // = signal(SIGCHLD, SIG_DFL);
        if __afl_area_ptr ==
               -(1 as libc::c_int) as *mut libc::c_void as *mut u8_0 {
            fprintf(stderr,
                    b"can not acquire mmap for address %p\n\x00" as *const u8
                        as *const libc::c_char,
                    __afl_map_addr as *mut libc::c_void);
            exit(1 as libc::c_int);
        }
    } else if _is_sancov as libc::c_int != 0 &&
                  __afl_area_ptr != __afl_area_initial.as_mut_ptr() {
        free(__afl_area_ptr as *mut libc::c_void);
        __afl_area_ptr = 0 as *mut u8_0;
        if __afl_final_loc > 256000 as libc::c_int as libc::c_uint {
            __afl_area_ptr =
                malloc(__afl_final_loc as libc::c_ulong) as *mut u8_0
        }
        if __afl_area_ptr.is_null() {
            __afl_area_ptr = __afl_area_initial.as_mut_ptr()
        }
    }
    id_str =
        getenv(b"__AFL_CMPLOG_SHM_ID\x00" as *const u8 as
                   *const libc::c_char);
    if !getenv(b"AFL_DEBUG\x00" as *const u8 as *const libc::c_char).is_null()
       {
        fprintf(stderr,
                b"DEBUG: cmplog id_str %s\n\x00" as *const u8 as
                    *const libc::c_char,
                if id_str.is_null() {
                    b"<null>\x00" as *const u8 as *const libc::c_char
                } else { id_str });
    }
    if !id_str.is_null() {
        let mut shm_id_0: u32_0 = atoi(id_str) as u32_0;
        __afl_cmp_map =
            shmat(shm_id_0 as libc::c_int, 0 as *const libc::c_void,
                  0 as libc::c_int) as *mut cmp_map;
        if __afl_cmp_map ==
               -(1 as libc::c_int) as *mut libc::c_void as *mut cmp_map {
            _exit(1 as libc::c_int);
        }
    };
}
unsafe extern "C" fn __afl_start_snapshots() {
    static mut tmp: [u8_0; 4] =
        [0 as libc::c_int as u8_0, 0 as libc::c_int as u8_0,
         0 as libc::c_int as u8_0, 0 as libc::c_int as u8_0];
    let mut child_pid: s32 = 0;
    let mut status: u32_0 = 0 as libc::c_int as u32_0;
    let mut already_read_first: u32_0 = 0 as libc::c_int as u32_0;
    let mut was_killed: u32_0 = 0;
    let mut child_stopped: u8_0 = 0 as libc::c_int as u8_0;
    let mut old_sigchld_handler:
            Option<unsafe extern "C" fn(_: libc::c_int) -> ()> = None;
    /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */
    status |=
        0x80000001 as libc::c_uint |
            0x20000000 as libc::c_int as libc::c_uint;
    if __afl_sharedmem_fuzzing != 0 as libc::c_int {
        status |= 0x1000000 as libc::c_int as libc::c_uint
    }
    if __afl_map_size <=
           ((0xfffffe as libc::c_int >> 1 as libc::c_int) + 1 as libc::c_int)
               as libc::c_uint {
        status |=
            (if __afl_map_size <= 1 as libc::c_int as libc::c_uint ||
                    __afl_map_size >
                        ((0xfffffe as libc::c_int >> 1 as libc::c_int) +
                             1 as libc::c_int) as libc::c_uint {
                 0 as libc::c_int as libc::c_uint
             } else {
                 (__afl_map_size.wrapping_sub(1 as libc::c_int as
                                                  libc::c_uint)) <<
                     1 as libc::c_int
             }) | 0x40000000 as libc::c_int as libc::c_uint
    }
    if __afl_dictionary_len != 0 && !__afl_dictionary.is_null() {
        status |= 0x10000000 as libc::c_int as libc::c_uint
    }
    memcpy(tmp.as_mut_ptr() as *mut libc::c_void,
           &mut status as *mut u32_0 as *const libc::c_void,
           4 as libc::c_int as libc::c_ulong);
    if write(198 as libc::c_int + 1 as libc::c_int,
             tmp.as_mut_ptr() as *const libc::c_void,
             4 as libc::c_int as size_t) != 4 as libc::c_int as libc::c_long {
        return
    }
    if __afl_sharedmem_fuzzing != 0 ||
           __afl_dictionary_len != 0 && !__afl_dictionary.is_null() {
        if read(198 as libc::c_int,
                &mut was_killed as *mut u32_0 as *mut libc::c_void,
                4 as libc::c_int as size_t) !=
               4 as libc::c_int as libc::c_long {
            _exit(1 as libc::c_int);
        }
        if !getenv(b"AFL_DEBUG\x00" as *const u8 as
                       *const libc::c_char).is_null() {
            fprintf(stderr,
                    b"target forkserver recv: %08x\n\x00" as *const u8 as
                        *const libc::c_char, was_killed);
        }
        if was_killed &
               (0x80000001 as libc::c_uint |
                    0x1000000 as libc::c_int as libc::c_uint) ==
               0x80000001 as libc::c_uint |
                   0x1000000 as libc::c_int as libc::c_uint {
            __afl_map_shm_fuzz();
        }
        if was_killed &
               (0x80000001 as libc::c_uint |
                    0x10000000 as libc::c_int as libc::c_uint) ==
               0x80000001 as libc::c_uint |
                   0x10000000 as libc::c_int as libc::c_uint &&
               __afl_dictionary_len != 0 && !__afl_dictionary.is_null() {
            // great lets pass the dictionary through the forkserver FD
            let mut len: u32_0 = __afl_dictionary_len;
            let mut offset: u32_0 = 0 as libc::c_int as u32_0;
            let mut ret: s32 = 0;
            if write(198 as libc::c_int + 1 as libc::c_int,
                     &mut len as *mut u32_0 as *const libc::c_void,
                     4 as libc::c_int as size_t) !=
                   4 as libc::c_int as libc::c_long {
                write(2 as libc::c_int,
                      b"Error: could not send dictionary len\n\x00" as
                          *const u8 as *const libc::c_char as
                          *const libc::c_void,
                      strlen(b"Error: could not send dictionary len\n\x00" as
                                 *const u8 as *const libc::c_char));
                _exit(1 as libc::c_int);
            }
            while len != 0 as libc::c_int as libc::c_uint {
                ret =
                    write(198 as libc::c_int + 1 as libc::c_int,
                          __afl_dictionary.offset(offset as isize) as
                              *const libc::c_void, len as size_t) as s32;
                if ret < 1 as libc::c_int {
                    write(2 as libc::c_int,
                          b"Error: could not send dictionary\n\x00" as
                              *const u8 as *const libc::c_char as
                              *const libc::c_void,
                          strlen(b"Error: could not send dictionary\n\x00" as
                                     *const u8 as *const libc::c_char));
                    _exit(1 as libc::c_int);
                }
                len =
                    (len as libc::c_uint).wrapping_sub(ret as libc::c_uint) as
                        u32_0 as u32_0;
                offset =
                    (offset as libc::c_uint).wrapping_add(ret as libc::c_uint)
                        as u32_0 as u32_0
            }
        } else if __afl_fuzz_ptr.is_null() {
            already_read_first = 1 as libc::c_int as u32_0
        }
    }
    loop  {
        let mut status_0: libc::c_int = 0;
        if already_read_first != 0 {
            already_read_first = 0 as libc::c_int as u32_0
        } else if read(198 as libc::c_int,
                       &mut was_killed as *mut u32_0 as *mut libc::c_void,
                       4 as libc::c_int as size_t) !=
                      4 as libc::c_int as libc::c_long {
            _exit(1 as libc::c_int);
        }
        // uh this forkserver does not understand extended option passing
      // or does not want the dictionary
        /* Wait for parent by reading from the pipe. Abort if read fails. */
        /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */
        if child_stopped as libc::c_int != 0 && was_killed != 0 {
            child_stopped = 0 as libc::c_int as u8_0;
            if waitpid(child_pid, &mut status_0, 0 as libc::c_int) <
                   0 as libc::c_int {
                _exit(1 as libc::c_int);
            }
        }
        if child_stopped == 0 {
            /* Once woken up, create a clone of our process. */
            child_pid = fork();
            if child_pid < 0 as libc::c_int { _exit(1 as libc::c_int); }
            /* In child process: close fds, resume execution. */
            if child_pid == 0 {
                //(void)nice(-20);  // does not seem to improve
                signal(17 as libc::c_int, old_sigchld_handler);
                close(198 as libc::c_int);
                close(198 as libc::c_int + 1 as libc::c_int);
                if afl_snapshot_take(1 as libc::c_int | 4 as libc::c_int |
                                         8 as libc::c_int | 16 as libc::c_int)
                       == 0 {
                    raise(19 as libc::c_int);
                }
                *__afl_area_ptr.offset(0 as libc::c_int as isize) =
                    1 as libc::c_int as u8_0;
                memset(__afl_prev_loc.as_mut_ptr() as *mut libc::c_void,
                       0 as libc::c_int,
                       (16 as libc::c_uint as
                            libc::c_ulong).wrapping_mul(::std::mem::size_of::<PREV_LOC_T>()
                                                            as
                                                            libc::c_ulong));
                return
            }
        } else {
            /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */
            kill(child_pid, 18 as libc::c_int);
            child_stopped = 0 as libc::c_int as u8_0
        }
        /* In parent process: write PID to pipe, then wait for child. */
        if write(198 as libc::c_int + 1 as libc::c_int,
                 &mut child_pid as *mut s32 as *const libc::c_void,
                 4 as libc::c_int as size_t) !=
               4 as libc::c_int as libc::c_long {
            _exit(1 as libc::c_int);
        }
        if waitpid(child_pid, &mut status_0, 2 as libc::c_int) <
               0 as libc::c_int {
            _exit(1 as libc::c_int);
        }
        /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */
        if status_0 & 0xff as libc::c_int == 0x7f as libc::c_int {
            child_stopped = 1 as libc::c_int as u8_0
        }
        /* Relay wait status to pipe, then loop back. */
        if write(198 as libc::c_int + 1 as libc::c_int,
                 &mut status_0 as *mut libc::c_int as *const libc::c_void,
                 4 as libc::c_int as size_t) !=
               4 as libc::c_int as libc::c_long {
            _exit(1 as libc::c_int);
        }
    };
}
/* Fork server logic. */
unsafe extern "C" fn __afl_start_forkserver() {
    if __afl_cmp_map.is_null() &&
           getenv(b"AFL_NO_SNAPSHOT\x00" as *const u8 as
                      *const libc::c_char).is_null() &&
           afl_snapshot_init() >= 0 as libc::c_int {
        __afl_start_snapshots(); // = signal(SIGCHLD, SIG_DFL);
        return
    }
    let mut tmp: [u8_0; 4] =
        [0 as libc::c_int as u8_0, 0 as libc::c_int as u8_0,
         0 as libc::c_int as u8_0, 0 as libc::c_int as u8_0];
    let mut child_pid: s32 = 0;
    let mut status: u32_0 = 0 as libc::c_int as u32_0;
    let mut already_read_first: u32_0 = 0 as libc::c_int as u32_0;
    let mut was_killed: u32_0 = 0;
    let mut child_stopped: u8_0 = 0 as libc::c_int as u8_0;
    let mut old_sigchld_handler:
            Option<unsafe extern "C" fn(_: libc::c_int) -> ()> = None;
    if __afl_map_size <=
           ((0xfffffe as libc::c_int >> 1 as libc::c_int) + 1 as libc::c_int)
               as libc::c_uint {
        status |=
            (if __afl_map_size <= 1 as libc::c_int as libc::c_uint ||
                    __afl_map_size >
                        ((0xfffffe as libc::c_int >> 1 as libc::c_int) +
                             1 as libc::c_int) as libc::c_uint {
                 0 as libc::c_int as libc::c_uint
             } else {
                 (__afl_map_size.wrapping_sub(1 as libc::c_int as
                                                  libc::c_uint)) <<
                     1 as libc::c_int
             }) | 0x40000000 as libc::c_int as libc::c_uint
    }
    if __afl_dictionary_len != 0 && !__afl_dictionary.is_null() {
        status |= 0x10000000 as libc::c_int as libc::c_uint
    }
    if __afl_sharedmem_fuzzing != 0 as libc::c_int {
        status |= 0x1000000 as libc::c_int as libc::c_uint
    }
    if status != 0 { status |= 0x80000001 as libc::c_uint }
    memcpy(tmp.as_mut_ptr() as *mut libc::c_void,
           &mut status as *mut u32_0 as *const libc::c_void,
           4 as libc::c_int as libc::c_ulong);
    /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */
    if write(198 as libc::c_int + 1 as libc::c_int,
             tmp.as_mut_ptr() as *const libc::c_void,
             4 as libc::c_int as size_t) != 4 as libc::c_int as libc::c_long {
        return
    }
    if __afl_sharedmem_fuzzing != 0 ||
           __afl_dictionary_len != 0 && !__afl_dictionary.is_null() {
        if read(198 as libc::c_int,
                &mut was_killed as *mut u32_0 as *mut libc::c_void,
                4 as libc::c_int as size_t) !=
               4 as libc::c_int as libc::c_long {
            _exit(1 as libc::c_int);
        }
        if !getenv(b"AFL_DEBUG\x00" as *const u8 as
                       *const libc::c_char).is_null() {
            fprintf(stderr,
                    b"target forkserver recv: %08x\n\x00" as *const u8 as
                        *const libc::c_char, was_killed);
        }
        if was_killed &
               (0x80000001 as libc::c_uint |
                    0x1000000 as libc::c_int as libc::c_uint) ==
               0x80000001 as libc::c_uint |
                   0x1000000 as libc::c_int as libc::c_uint {
            __afl_map_shm_fuzz();
        }
        if was_killed &
               (0x80000001 as libc::c_uint |
                    0x10000000 as libc::c_int as libc::c_uint) ==
               0x80000001 as libc::c_uint |
                   0x10000000 as libc::c_int as libc::c_uint &&
               __afl_dictionary_len != 0 && !__afl_dictionary.is_null() {
            // great lets pass the dictionary through the forkserver FD
            let mut len: u32_0 = __afl_dictionary_len;
            let mut offset: u32_0 = 0 as libc::c_int as u32_0;
            let mut ret: s32 = 0;
            if write(198 as libc::c_int + 1 as libc::c_int,
                     &mut len as *mut u32_0 as *const libc::c_void,
                     4 as libc::c_int as size_t) !=
                   4 as libc::c_int as libc::c_long {
                write(2 as libc::c_int,
                      b"Error: could not send dictionary len\n\x00" as
                          *const u8 as *const libc::c_char as
                          *const libc::c_void,
                      strlen(b"Error: could not send dictionary len\n\x00" as
                                 *const u8 as *const libc::c_char));
                _exit(1 as libc::c_int);
            }
            while len != 0 as libc::c_int as libc::c_uint {
                ret =
                    write(198 as libc::c_int + 1 as libc::c_int,
                          __afl_dictionary.offset(offset as isize) as
                              *const libc::c_void, len as size_t) as s32;
                if ret < 1 as libc::c_int {
                    write(2 as libc::c_int,
                          b"Error: could not send dictionary\n\x00" as
                              *const u8 as *const libc::c_char as
                              *const libc::c_void,
                          strlen(b"Error: could not send dictionary\n\x00" as
                                     *const u8 as *const libc::c_char));
                    _exit(1 as libc::c_int);
                }
                len =
                    (len as libc::c_uint).wrapping_sub(ret as libc::c_uint) as
                        u32_0 as u32_0;
                offset =
                    (offset as libc::c_uint).wrapping_add(ret as libc::c_uint)
                        as u32_0 as u32_0
            }
        } else if __afl_fuzz_ptr.is_null() {
            already_read_first = 1 as libc::c_int as u32_0
        }
    }
    loop  {
        let mut status_0: libc::c_int = 0;
        // uh this forkserver does not understand extended option passing
      // or does not want the dictionary
        /* Wait for parent by reading from the pipe. Abort if read fails. */
        if already_read_first != 0 {
            already_read_first = 0 as libc::c_int as u32_0
        } else if read(198 as libc::c_int,
                       &mut was_killed as *mut u32_0 as *mut libc::c_void,
                       4 as libc::c_int as size_t) !=
                      4 as libc::c_int as libc::c_long {
            _exit(1 as libc::c_int);
        }
        /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */
        if child_stopped as libc::c_int != 0 && was_killed != 0 {
            child_stopped = 0 as libc::c_int as u8_0;
            if waitpid(child_pid, &mut status_0, 0 as libc::c_int) <
                   0 as libc::c_int {
                _exit(1 as libc::c_int);
            }
        }
        if child_stopped == 0 {
            /* Once woken up, create a clone of our process. */
            child_pid = fork();
            if child_pid < 0 as libc::c_int { _exit(1 as libc::c_int); }
            /* In child process: close fds, resume execution. */
            if child_pid == 0 {
                //(void)nice(-20);
                signal(17 as libc::c_int, old_sigchld_handler);
                close(198 as libc::c_int);
                close(198 as libc::c_int + 1 as libc::c_int);
                return
            }
        } else {
            /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */
            kill(child_pid, 18 as libc::c_int);
            child_stopped = 0 as libc::c_int as u8_0
        }
        /* In parent process: write PID to pipe, then wait for child. */
        if write(198 as libc::c_int + 1 as libc::c_int,
                 &mut child_pid as *mut s32 as *const libc::c_void,
                 4 as libc::c_int as size_t) !=
               4 as libc::c_int as libc::c_long {
            _exit(1 as libc::c_int);
        }
        if waitpid(child_pid, &mut status_0,
                   (if is_persistent as libc::c_int != 0 {
                        2 as libc::c_int
                    } else { 0 as libc::c_int })) < 0 as libc::c_int {
            _exit(1 as libc::c_int);
        }
        /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */
        if status_0 & 0xff as libc::c_int == 0x7f as libc::c_int {
            child_stopped = 1 as libc::c_int as u8_0
        }
        /* Relay wait status to pipe, then loop back. */
        if write(198 as libc::c_int + 1 as libc::c_int,
                 &mut status_0 as *mut libc::c_int as *const libc::c_void,
                 4 as libc::c_int as size_t) !=
               4 as libc::c_int as libc::c_long {
            _exit(1 as libc::c_int);
        }
    };
}
/* A simplified persistent mode handler, used as explained in
 * README.llvm.md. */
#[no_mangle]
pub unsafe extern "C" fn __afl_persistent_loop(mut max_cnt: libc::c_uint)
 -> libc::c_int {
    static mut first_pass: u8_0 = 1 as libc::c_int as u8_0;
    static mut cycle_cnt: u32_0 = 0;
    if first_pass != 0 {
        /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */
        if is_persistent != 0 {
            memset(__afl_area_ptr as *mut libc::c_void, 0 as libc::c_int,
                   __afl_map_size as libc::c_ulong);
            *__afl_area_ptr.offset(0 as libc::c_int as isize) =
                1 as libc::c_int as u8_0;
            memset(__afl_prev_loc.as_mut_ptr() as *mut libc::c_void,
                   0 as libc::c_int,
                   (16 as libc::c_uint as
                        libc::c_ulong).wrapping_mul(::std::mem::size_of::<PREV_LOC_T>()
                                                        as libc::c_ulong));
        }
        cycle_cnt = max_cnt;
        first_pass = 0 as libc::c_int as u8_0;
        return 1 as libc::c_int
    }
    if is_persistent != 0 {
        cycle_cnt = cycle_cnt.wrapping_sub(1);
        if cycle_cnt != 0 {
            raise(19 as libc::c_int);
            *__afl_area_ptr.offset(0 as libc::c_int as isize) =
                1 as libc::c_int as u8_0;
            memset(__afl_prev_loc.as_mut_ptr() as *mut libc::c_void,
                   0 as libc::c_int,
                   (16 as libc::c_uint as
                        libc::c_ulong).wrapping_mul(::std::mem::size_of::<PREV_LOC_T>()
                                                        as libc::c_ulong));
            return 1 as libc::c_int
        } else {
            /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */
            __afl_area_ptr = __afl_area_initial.as_mut_ptr()
        }
    }
    return 0 as libc::c_int;
}
/* This one can be called from user code when deferred forkserver mode
    is enabled. */
#[no_mangle]
pub unsafe extern "C" fn __afl_manual_init() {
    static mut init_done: u8_0 = 0;
    if !getenv(b"AFL_DISABLE_LLVM_INSTRUMENTATION\x00" as *const u8 as
                   *const libc::c_char).is_null() {
        init_done = 1 as libc::c_int as u8_0;
        is_persistent = 0 as libc::c_int as u8_0;
        __afl_sharedmem_fuzzing = 0 as libc::c_int;
        if __afl_area_ptr.is_null() {
            __afl_area_ptr = __afl_area_initial.as_mut_ptr()
        }
        if !getenv(b"AFL_DEBUG\x00" as *const u8 as
                       *const libc::c_char).is_null() {
            fprintf(stderr,
                    b"DEBUG: disabled instrumentation because of AFL_DISABLE_LLVM_INSTRUMENTATION\n\x00"
                        as *const u8 as *const libc::c_char);
        }
    }
    if init_done == 0 {
        __afl_start_forkserver();
        init_done = 1 as libc::c_int as u8_0
    };
}
/* Initialization of the forkserver - latest possible */
#[no_mangle]
pub unsafe extern "C" fn __afl_auto_init() {
    if !getenv(b"AFL_DISABLE_LLVM_INSTRUMENTATION\x00" as *const u8 as
                   *const libc::c_char).is_null() {
        return
    }
    if !getenv(b"__AFL_DEFER_FORKSRV\x00" as *const u8 as
                   *const libc::c_char).is_null() {
        return
    }
    __afl_manual_init();
}
/* Initialization of the shmem - earliest possible because of LTO fixed mem. */
#[no_mangle]
pub unsafe extern "C" fn __afl_auto_early() {
    is_persistent =
        !getenv(b"__AFL_PERSISTENT\x00" as *const u8 as
                    *const libc::c_char).is_null() as libc::c_int as u8_0;
    if !getenv(b"AFL_DISABLE_LLVM_INSTRUMENTATION\x00" as *const u8 as
                   *const libc::c_char).is_null() {
        return
    }
    __afl_map_shm();
}
/* preset __afl_area_ptr #2 */
#[no_mangle]
pub unsafe extern "C" fn __afl_auto_second() {
    if !getenv(b"AFL_DISABLE_LLVM_INSTRUMENTATION\x00" as *const u8 as
                   *const libc::c_char).is_null() {
        return
    }
    let mut ptr: *mut u8_0 = 0 as *mut u8_0;
    if __afl_final_loc != 0 {
        if !__afl_area_ptr.is_null() &&
               __afl_area_ptr != __afl_area_initial.as_mut_ptr() {
            free(__afl_area_ptr as *mut libc::c_void);
        }
        if __afl_map_addr != 0 {
            ptr =
                mmap(__afl_map_addr as *mut libc::c_void,
                     __afl_final_loc as size_t,
                     0x1 as libc::c_int | 0x2 as libc::c_int,
                     0x10 as libc::c_int | 0x1 as libc::c_int |
                         0x20 as libc::c_int, -(1 as libc::c_int),
                     0 as libc::c_int as __off_t) as *mut u8_0
        } else { ptr = malloc(__afl_final_loc as libc::c_ulong) as *mut u8_0 }
        if !ptr.is_null() &&
               ptr as ssize_t != -(1 as libc::c_int) as libc::c_long {
            __afl_area_ptr = ptr
        }
    };
}
/* preset __afl_area_ptr #1 - at constructor level 0 global variables have
   not been set */
#[no_mangle]
pub unsafe extern "C" fn __afl_auto_first() {
    if !getenv(b"AFL_DISABLE_LLVM_INSTRUMENTATION\x00" as *const u8 as
                   *const libc::c_char).is_null() {
        return
    }
    let mut ptr: *mut u8_0 = 0 as *mut u8_0;
    ptr = malloc(1024000 as libc::c_int as libc::c_ulong) as *mut u8_0;
    if !ptr.is_null() && ptr as ssize_t != -(1 as libc::c_int) as libc::c_long
       {
        __afl_area_ptr = ptr
    };
}
/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.md.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(mut guard:
                                                            *mut uint32_t) {
    // For stability analysis, if you want to know to which function unstable
  // edge IDs belong - uncomment, recompile+install llvm_mode, recompile
  // the target. libunwind and libbacktrace are better solutions.
  // Set AFL_DEBUG_CHILD_OUTPUT=1 and run afl-fuzz with 2>file to capture
  // the backtrace output
  /*
  uint32_t unstable[] = { ... unstable edge IDs };
  uint32_t idx;
  char bt[1024];
  for (idx = 0; i < sizeof(unstable)/sizeof(uint32_t); i++) {

    if (unstable[idx] == __afl_area_ptr[*guard]) {

      int bt_size = backtrace(bt, 256);
      if (bt_size > 0) {

        char **bt_syms = backtrace_symbols(bt, bt_size);
        if (bt_syms) {

          fprintf(stderr, "DEBUG: edge=%u caller=%s\n", unstable[idx],
  bt_syms[0]);
          free(bt_syms);

        }

      }

    }

  }

  */
    let ref mut fresh2 = *__afl_area_ptr.offset(*guard as isize);
    *fresh2 = (*fresh2).wrapping_add(1);
}
/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start:
                                                                 *mut uint32_t,
                                                             mut stop:
                                                                 *mut uint32_t) {
    let mut inst_ratio: u32_0 = 100 as libc::c_int as u32_0;
    let mut x: *mut libc::c_char = 0 as *mut libc::c_char;
    _is_sancov = 1 as libc::c_int as u8_0;
    if !getenv(b"AFL_DEBUG\x00" as *const u8 as *const libc::c_char).is_null()
       {
        fprintf(stderr,
                b"Running __sanitizer_cov_trace_pc_guard_init: %p-%p\n\x00" as
                    *const u8 as *const libc::c_char, start, stop);
    }
    if start == stop || *start != 0 { return }
    x = getenv(b"AFL_INST_RATIO\x00" as *const u8 as *const libc::c_char);
    if !x.is_null() { inst_ratio = atoi(x) as u32_0 }
    if inst_ratio == 0 || inst_ratio > 100 as libc::c_int as libc::c_uint {
        fprintf(stderr,
                b"[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n\x00" as
                    *const u8 as *const libc::c_char);
        abort();
    }
    /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */
    let fresh3 = start;
    start = start.offset(1);
    *fresh3 =
        (random() %
             (((1 as libc::c_int) << 16 as libc::c_int) - 1 as libc::c_int) as
                 libc::c_long + 1 as libc::c_int as libc::c_long) as uint32_t;
    while start < stop {
        if (random() % 100 as libc::c_int as libc::c_long) <
               inst_ratio as libc::c_long {
            __afl_final_loc = __afl_final_loc.wrapping_add(1);
            *start = __afl_final_loc
        } else { *start = 0 as libc::c_int as uint32_t }
        start = start.offset(1)
    };
}
// /// CmpLog instrumentation
#[no_mangle]
pub unsafe extern "C" fn __cmplog_ins_hook1(mut arg1: uint8_t,
                                            mut arg2: uint8_t) {
    if __afl_cmp_map.is_null() { return }
    let mut k: uintptr_t =
        fake__builtin_return_address(0 as libc::c_int as u32_0);
    k = k >> 4 as libc::c_int ^ k << 8 as libc::c_int;
    k &= (65536 as libc::c_int - 1 as libc::c_int) as libc::c_ulong;
    (*__afl_cmp_map).headers[k as
                                 usize].set_type_0(0 as libc::c_int as
                                                       libc::c_uint);
    let mut hits: u32_0 = (*__afl_cmp_map).headers[k as usize].hits();
    (*__afl_cmp_map).headers[k as
                                 usize].set_hits(hits.wrapping_add(1 as
                                                                       libc::c_int
                                                                       as
                                                                       libc::c_uint));
    // if (!__afl_cmp_map->headers[k].cnt)
  //  __afl_cmp_map->headers[k].cnt = __afl_cmp_counter++;
    (*__afl_cmp_map).headers[k as
                                 usize].set_shape(0 as libc::c_int as
                                                      libc::c_uint);
    hits &= (256 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
    (*__afl_cmp_map).log[k as usize][hits as usize].v0 = arg1 as u64_0;
    (*__afl_cmp_map).log[k as usize][hits as usize].v1 = arg2 as u64_0;
}
#[no_mangle]
pub unsafe extern "C" fn __cmplog_ins_hook2(mut arg1: uint16_t,
                                            mut arg2: uint16_t) {
    if __afl_cmp_map.is_null() { return }
    let mut k: uintptr_t =
        fake__builtin_return_address(0 as libc::c_int as u32_0);
    k = k >> 4 as libc::c_int ^ k << 8 as libc::c_int;
    k &= (65536 as libc::c_int - 1 as libc::c_int) as libc::c_ulong;
    (*__afl_cmp_map).headers[k as
                                 usize].set_type_0(0 as libc::c_int as
                                                       libc::c_uint);
    let mut hits: u32_0 = (*__afl_cmp_map).headers[k as usize].hits();
    (*__afl_cmp_map).headers[k as
                                 usize].set_hits(hits.wrapping_add(1 as
                                                                       libc::c_int
                                                                       as
                                                                       libc::c_uint));
    (*__afl_cmp_map).headers[k as
                                 usize].set_shape(1 as libc::c_int as
                                                      libc::c_uint);
    hits &= (256 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
    (*__afl_cmp_map).log[k as usize][hits as usize].v0 = arg1 as u64_0;
    (*__afl_cmp_map).log[k as usize][hits as usize].v1 = arg2 as u64_0;
}
#[no_mangle]
pub unsafe extern "C" fn __cmplog_ins_hook4(mut arg1: uint32_t,
                                            mut arg2: uint32_t) {
    if __afl_cmp_map.is_null() { return }
    let mut k: uintptr_t =
        fake__builtin_return_address(0 as libc::c_int as u32_0);
    k = k >> 4 as libc::c_int ^ k << 8 as libc::c_int;
    k &= (65536 as libc::c_int - 1 as libc::c_int) as libc::c_ulong;
    (*__afl_cmp_map).headers[k as
                                 usize].set_type_0(0 as libc::c_int as
                                                       libc::c_uint);
    let mut hits: u32_0 = (*__afl_cmp_map).headers[k as usize].hits();
    (*__afl_cmp_map).headers[k as
                                 usize].set_hits(hits.wrapping_add(1 as
                                                                       libc::c_int
                                                                       as
                                                                       libc::c_uint));
    (*__afl_cmp_map).headers[k as
                                 usize].set_shape(3 as libc::c_int as
                                                      libc::c_uint);
    hits &= (256 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
    (*__afl_cmp_map).log[k as usize][hits as usize].v0 = arg1 as u64_0;
    (*__afl_cmp_map).log[k as usize][hits as usize].v1 = arg2 as u64_0;
}
#[no_mangle]
pub unsafe extern "C" fn __cmplog_ins_hook8(mut arg1: uint64_t,
                                            mut arg2: uint64_t) {
    if __afl_cmp_map.is_null() { return }
    let mut k: uintptr_t =
        fake__builtin_return_address(0 as libc::c_int as u32_0);
    k = k >> 4 as libc::c_int ^ k << 8 as libc::c_int;
    k &= (65536 as libc::c_int - 1 as libc::c_int) as libc::c_ulong;
    (*__afl_cmp_map).headers[k as
                                 usize].set_type_0(0 as libc::c_int as
                                                       libc::c_uint);
    let mut hits: u32_0 = (*__afl_cmp_map).headers[k as usize].hits();
    (*__afl_cmp_map).headers[k as
                                 usize].set_hits(hits.wrapping_add(1 as
                                                                       libc::c_int
                                                                       as
                                                                       libc::c_uint));
    (*__afl_cmp_map).headers[k as
                                 usize].set_shape(7 as libc::c_int as
                                                      libc::c_uint);
    hits &= (256 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
    (*__afl_cmp_map).log[k as usize][hits as usize].v0 = arg1 as u64_0;
    (*__afl_cmp_map).log[k as usize][hits as usize].v1 = arg2 as u64_0;
}
/* defined(__APPLE__) */
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_switch(mut val: uint64_t,
                                                      mut cases:
                                                          *mut uint64_t) {
    if __afl_cmp_map.is_null() { return }
    let mut i: uint64_t = 0 as libc::c_int as uint64_t;
    while i < *cases.offset(0 as libc::c_int as isize) {
        let mut k: uintptr_t =
            fake__builtin_return_address(0 as libc::c_int as
                                             u32_0).wrapping_add(i);
        k = k >> 4 as libc::c_int ^ k << 8 as libc::c_int;
        k &= (65536 as libc::c_int - 1 as libc::c_int) as libc::c_ulong;
        (*__afl_cmp_map).headers[k as
                                     usize].set_type_0(0 as libc::c_int as
                                                           libc::c_uint);
        let mut hits: u32_0 = (*__afl_cmp_map).headers[k as usize].hits();
        (*__afl_cmp_map).headers[k as
                                     usize].set_hits(hits.wrapping_add(1 as
                                                                           libc::c_int
                                                                           as
                                                                           libc::c_uint));
        (*__afl_cmp_map).headers[k as
                                     usize].set_shape(7 as libc::c_int as
                                                          libc::c_uint);
        hits &= (256 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
        (*__afl_cmp_map).log[k as usize][hits as usize].v0 = val as u64_0;
        (*__afl_cmp_map).log[k as usize][hits as usize].v1 =
            *cases.offset(i.wrapping_add(2 as libc::c_int as libc::c_ulong) as
                              isize) as u64_0;
        i = i.wrapping_add(1)
    };
}
// POSIX shenanigan to see if an area is mapped.
// If it is mapped as X-only, we have a problem, so maybe we should add a check
// to avoid to call it on .text addresses
unsafe extern "C" fn area_is_mapped(mut ptr: *mut libc::c_void,
                                    mut len: size_t) -> libc::c_int {
    let mut p: *mut libc::c_char = ptr as *mut libc::c_char;
    let mut page: *mut libc::c_char =
        (p as uintptr_t &
             !(sysconf(_SC_PAGESIZE as libc::c_int) -
                   1 as libc::c_int as libc::c_long) as libc::c_ulong) as
            *mut libc::c_char;
    let mut r: libc::c_int =
        msync(page as *mut libc::c_void,
              (p.wrapping_offset_from(page) as libc::c_long as
                   libc::c_ulong).wrapping_add(len), 1 as libc::c_int);
    if r < 0 as libc::c_int {
        return (*__errno_location() != 12 as libc::c_int) as libc::c_int
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn __cmplog_rtn_hook(mut ptr1: *mut u8_0,
                                           mut ptr2: *mut u8_0) {
    if __afl_cmp_map.is_null() { return }
    if area_is_mapped(ptr1 as *mut libc::c_void, 32 as libc::c_int as size_t)
           == 0 ||
           area_is_mapped(ptr2 as *mut libc::c_void,
                          32 as libc::c_int as size_t) == 0 {
        return
    }
    let mut k: uintptr_t =
        fake__builtin_return_address(0 as libc::c_int as u32_0);
    k = k >> 4 as libc::c_int ^ k << 8 as libc::c_int;
    k &= (65536 as libc::c_int - 1 as libc::c_int) as libc::c_ulong;
    (*__afl_cmp_map).headers[k as
                                 usize].set_type_0(1 as libc::c_int as
                                                       libc::c_uint);
    let mut hits: u32_0 = (*__afl_cmp_map).headers[k as usize].hits();
    (*__afl_cmp_map).headers[k as
                                 usize].set_hits(hits.wrapping_add(1 as
                                                                       libc::c_int
                                                                       as
                                                                       libc::c_uint));
    (*__afl_cmp_map).headers[k as
                                 usize].set_shape(31 as libc::c_int as
                                                      libc::c_uint);
    hits &=
        (256 as libc::c_int / 4 as libc::c_int - 1 as libc::c_int) as
            libc::c_uint;
    libc::memcpy((*((*__afl_cmp_map).log[k as usize].as_mut_ptr() as
                        *mut cmpfn_operands).offset(hits as
                                                        isize)).v0.as_mut_ptr()
                     as *mut libc::c_void, ptr1 as *const libc::c_void,
                 32 as libc::c_int as libc::c_ulong as libc::size_t);
    libc::memcpy((*((*__afl_cmp_map).log[k as usize].as_mut_ptr() as
                        *mut cmpfn_operands).offset(hits as
                                                        isize)).v1.as_mut_ptr()
                     as *mut libc::c_void, ptr2 as *const libc::c_void,
                 32 as libc::c_int as libc::c_ulong as libc::size_t);
}
