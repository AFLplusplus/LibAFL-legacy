use ::libc;
extern "C" {
    pub type png_struct_def;
    pub type png_info_def;
    #[no_mangle]
    fn _setjmp(_: *mut __jmp_buf_tag) -> libc::c_int;
    #[no_mangle]
    fn longjmp(_: *mut __jmp_buf_tag, _: libc::c_int) -> !;
    #[no_mangle]
    fn png_create_read_struct(user_png_ver: png_const_charp,
                              error_ptr: png_voidp, error_fn: png_error_ptr,
                              warn_fn: png_error_ptr) -> png_structp;
    #[no_mangle]
    fn png_set_longjmp_fn(png_ptr: png_structrp, longjmp_fn: png_longjmp_ptr,
                          jmp_buf_size: size_t) -> *mut jmp_buf;
    #[no_mangle]
    fn png_create_info_struct(png_ptr: png_const_structrp) -> png_infop;
    #[no_mangle]
    fn png_set_crc_action(png_ptr: png_structrp, crit_action: libc::c_int,
                          ancil_action: libc::c_int);
    #[no_mangle]
    fn png_set_progressive_read_fn(png_ptr: png_structrp,
                                   progressive_ptr: png_voidp,
                                   info_fn: png_progressive_info_ptr,
                                   row_fn: png_progressive_row_ptr,
                                   end_fn: png_progressive_end_ptr);
    #[no_mangle]
    fn png_process_data(png_ptr: png_structrp, info_ptr: png_inforp,
                        buffer: png_bytep, buffer_size: png_size_t);
    #[no_mangle]
    fn png_set_user_limits(png_ptr: png_structrp, user_width_max: png_uint_32,
                           user_height_max: png_uint_32);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type __jmp_buf = [libc::c_long; 8];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __jmp_buf_tag {
    pub __jmpbuf: __jmp_buf,
    pub __mask_was_saved: libc::c_int,
    pub __saved_mask: __sigset_t,
}
pub type jmp_buf = [__jmp_buf_tag; 1];
pub type png_byte = libc::c_uchar;
pub type png_uint_32 = libc::c_uint;
pub type png_size_t = size_t;
pub type png_voidp = *mut libc::c_void;
pub type png_bytep = *mut png_byte;
pub type png_const_charp = *const libc::c_char;
pub type png_struct = png_struct_def;
pub type png_structp = *mut png_struct;
pub type png_info = png_info_def;
pub type png_infop = *mut png_info;
pub type png_structrp = *mut png_struct;
pub type png_const_structrp = *const png_struct;
pub type png_inforp = *mut png_info;
pub type png_error_ptr
    =
    Option<unsafe extern "C" fn(_: png_structp, _: png_const_charp) -> ()>;
pub type png_progressive_info_ptr
    =
    Option<unsafe extern "C" fn(_: png_structp, _: png_infop) -> ()>;
pub type png_progressive_end_ptr
    =
    Option<unsafe extern "C" fn(_: png_structp, _: png_infop) -> ()>;
pub type png_progressive_row_ptr
    =
    Option<unsafe extern "C" fn(_: png_structp, _: png_bytep, _: png_uint_32,
                                _: libc::c_int) -> ()>;
pub type png_longjmp_ptr
    =
    Option<unsafe extern "C" fn(_: *mut __jmp_buf_tag, _: libc::c_int) -> ()>;
/* An in mmeory fuzzing example. Fuzzer for libpng library */
/* The actual harness. Using PNG for our example. */
#[no_mangle]
pub unsafe extern "C" fn LLVMFuzzerTestOneInput(mut input: *const uint8_t,
                                                mut len: size_t)
 -> libc::c_int {
    let mut png_ptr: png_structp =
        png_create_read_struct(b"1.6.34\x00" as *const u8 as
                                   *const libc::c_char,
                               0 as *mut libc::c_void, None, None);
    png_set_user_limits(png_ptr, 65535 as libc::c_int as png_uint_32,
                        65535 as libc::c_int as png_uint_32);
    let mut info_ptr: png_infop =
        png_create_info_struct(png_ptr as *const png_struct);
    png_set_crc_action(png_ptr, 4 as libc::c_int, 4 as libc::c_int);
    if _setjmp((*png_set_longjmp_fn(png_ptr,
                                    ::std::mem::transmute::<Option<unsafe extern "C" fn(_:
                                                                                            *mut __jmp_buf_tag,
                                                                                        _:
                                                                                            libc::c_int)
                                                                       -> !>,
                                                            png_longjmp_ptr>(Some(longjmp
                                                                                      as
                                                                                      unsafe extern "C" fn(_:
                                                                                                               *mut __jmp_buf_tag,
                                                                                                           _:
                                                                                                               libc::c_int)
                                                                                          ->
                                                                                              !)),
                                    ::std::mem::size_of::<jmp_buf>() as
                                        libc::c_ulong)).as_mut_ptr()) != 0 {
        return 0 as libc::c_int
    }
    png_set_progressive_read_fn(png_ptr, 0 as *mut libc::c_void, None, None,
                                None);
    png_process_data(png_ptr, info_ptr, input as *mut uint8_t, len);
    return 0 as libc::c_int;
}
