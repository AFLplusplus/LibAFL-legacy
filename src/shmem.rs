use ::libc;
extern "C" {
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn strncpy(_: *mut libc::c_char, _: *const libc::c_char, _: libc::c_ulong)
     -> *mut libc::c_char;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn shmctl(__shmid: libc::c_int, __cmd: libc::c_int, __buf: *mut shmid_ds)
     -> libc::c_int;
    #[no_mangle]
    fn shmget(__key: key_t, __size: size_t, __shmflg: libc::c_int)
     -> libc::c_int;
    #[no_mangle]
    fn shmat(__shmid: libc::c_int, __shmaddr: *const libc::c_void,
             __shmflg: libc::c_int) -> *mut libc::c_void;
    #[no_mangle]
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char,
              _: libc::c_int) -> libc::c_long;
    #[no_mangle]
    fn setenv(__name: *const libc::c_char, __value: *const libc::c_char,
              __replace: libc::c_int) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __key_t = libc::c_int;
pub type __syscall_ulong_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ipc_perm {
    pub __key: __key_t,
    pub uid: __uid_t,
    pub gid: __gid_t,
    pub cuid: __uid_t,
    pub cgid: __gid_t,
    pub mode: libc::c_ushort,
    pub __pad1: libc::c_ushort,
    pub __seq: libc::c_ushort,
    pub __pad2: libc::c_ushort,
    pub __glibc_reserved1: __syscall_ulong_t,
    pub __glibc_reserved2: __syscall_ulong_t,
}
pub type key_t = __key_t;
pub type shmatt_t = __syscall_ulong_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct shmid_ds {
    pub shm_perm: ipc_perm,
    pub shm_segsz: size_t,
    pub shm_atime: __time_t,
    pub shm_dtime: __time_t,
    pub shm_ctime: __time_t,
    pub shm_cpid: __pid_t,
    pub shm_lpid: __pid_t,
    pub shm_nattch: shmatt_t,
    pub __glibc_reserved4: __syscall_ulong_t,
    pub __glibc_reserved5: __syscall_ulong_t,
}
pub type uint8_t = __uint8_t;
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
pub type u8_0 = uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_shmem {
    pub shm_str: [libc::c_char; 20],
    pub shm_id: libc::c_int,
    pub map: *mut u8_0,
    pub map_size: size_t,
}
// A generic sharememory region to be used by any functions (queues or feedbacks
// too.)
pub type afl_shmem_t = afl_shmem;
#[inline]
unsafe extern "C" fn atoi(mut __nptr: *const libc::c_char) -> libc::c_int {
    return strtol(__nptr, 0 as *mut libc::c_void as *mut *mut libc::c_char,
                  10 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn afl_shmem_deinit(mut shm: *mut afl_shmem_t) {
    if shm.is_null() || (*shm).map.is_null() {
        /* Serialized map id */
        // Not set or not initialized;
        return
    }
    (*shm).shm_str[0 as libc::c_int as usize] =
        '\u{0}' as i32 as libc::c_char;
    shmctl((*shm).shm_id, 0 as libc::c_int, 0 as *mut shmid_ds);
    (*shm).map = 0 as *mut u8_0;
}
// Functions to create Shared memory region, for observation channels and
// opening inputs and stuff.
#[no_mangle]
pub unsafe extern "C" fn afl_shmem_init(mut shm: *mut afl_shmem_t,
                                        mut map_size: size_t) -> *mut u8_0 {
    (*shm).map_size = map_size;
    (*shm).map = 0 as *mut u8_0;
    (*shm).shm_id =
        shmget(0 as libc::c_int, map_size,
               0o1000 as libc::c_int | 0o2000 as libc::c_int |
                   0o600 as libc::c_int);
    if (*shm).shm_id < 0 as libc::c_int {
        (*shm).shm_str[0 as libc::c_int as usize] =
            '\u{0}' as i32 as libc::c_char;
        return 0 as *mut u8_0
    }
    snprintf((*shm).shm_str.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 20]>() as libc::c_ulong,
             b"%d\x00" as *const u8 as *const libc::c_char, (*shm).shm_id);
    (*shm).shm_str[(::std::mem::size_of::<[libc::c_char; 20]>() as
                        libc::c_ulong).wrapping_sub(1 as libc::c_int as
                                                        libc::c_ulong) as
                       usize] = '\u{0}' as i32 as libc::c_char;
    (*shm).map =
        shmat((*shm).shm_id, 0 as *const libc::c_void, 0 as libc::c_int) as
            *mut u8_0;
    if (*shm).map == -(1 as libc::c_int) as *mut libc::c_void as *mut u8_0 ||
           (*shm).map.is_null() {
        shmctl((*shm).shm_id, 0 as libc::c_int, 0 as *mut shmid_ds);
        (*shm).shm_id = -(1 as libc::c_int);
        (*shm).shm_str[0 as libc::c_int as usize] =
            '\u{0}' as i32 as libc::c_char;
        return 0 as *mut u8_0
    }
    return (*shm).map;
}
#[no_mangle]
pub unsafe extern "C" fn afl_shmem_by_str(mut shm: *mut afl_shmem_t,
                                          mut shm_str: *mut libc::c_char,
                                          mut map_size: size_t) -> *mut u8_0 {
    if shm.is_null() || shm_str.is_null() ||
           *shm_str.offset(0 as libc::c_int as isize) == 0 || map_size == 0 {
        return 0 as *mut u8_0
    }
    (*shm).map = 0 as *mut u8_0;
    (*shm).map_size = map_size;
    strncpy((*shm).shm_str.as_mut_ptr(), shm_str,
            (::std::mem::size_of::<[libc::c_char; 20]>() as
                 libc::c_ulong).wrapping_sub(1 as libc::c_int as
                                                 libc::c_ulong));
    (*shm).shm_id = atoi(shm_str);
    (*shm).map =
        shmat((*shm).shm_id, 0 as *const libc::c_void, 0 as libc::c_int) as
            *mut u8_0;
    if (*shm).map == -(1 as libc::c_int) as *mut libc::c_void as *mut u8_0 {
        (*shm).map = 0 as *mut u8_0;
        (*shm).map_size = 0 as libc::c_int as size_t;
        (*shm).shm_str[0 as libc::c_int as usize] =
            '\u{0}' as i32 as libc::c_char;
        return 0 as *mut u8_0
    }
    return (*shm).map;
}
/* Write sharedmap as env var */
/* Write sharedmap as env var and the size as name#_SIZE */
#[no_mangle]
pub unsafe extern "C" fn afl_shmem_to_env_var(mut shmem: *mut afl_shmem_t,
                                              mut env_name: *mut libc::c_char)
 -> afl_ret_t {
    if env_name.is_null() || shmem.is_null() ||
           *env_name.offset(0 as libc::c_int as isize) == 0 ||
           (*shmem).shm_str[0 as libc::c_int as usize] == 0 ||
           strlen(env_name) > 200 as libc::c_int as libc::c_ulong {
        return AFL_RET_NULL_PTR
    }
    let mut shm_str: [libc::c_char; 256] = [0; 256];
    snprintf(shm_str.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
             b"%d\x00" as *const u8 as *const libc::c_char, (*shmem).shm_id);
    if setenv(env_name, shm_str.as_mut_ptr(), 1 as libc::c_int) <
           0 as libc::c_int {
        return AFL_RET_ERRNO
    }
    /* Write the size to env, too */
    let mut size_env_name: [libc::c_char; 256] = [0; 256];
    snprintf(size_env_name.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
             b"%s_SIZE\x00" as *const u8 as *const libc::c_char, env_name);
    snprintf(shm_str.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
             b"%d\x00" as *const u8 as *const libc::c_char, (*shmem).shm_id);
    if setenv(size_env_name.as_mut_ptr(), shm_str.as_mut_ptr(),
              1 as libc::c_int) < 0 as libc::c_int {
        return AFL_RET_ERRNO
    }
    return AFL_RET_SUCCESS;
}
