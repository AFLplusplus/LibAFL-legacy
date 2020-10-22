#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(asm)]
#![feature(const_raw_ptr_to_usize_cast)]
#![feature(extern_types)]
#![feature(label_break_value)]
#![feature(main)]
#![feature(ptr_wrapping_offset_from)]
#![feature(register_tool)]
#![feature(thread_local)]
#![register_tool(c2rust)]


#[macro_use]
extern crate c2rust_bitfields;#[macro_use]
extern crate c2rust_asm_casts;
extern crate libc;



pub mod examples {
pub mod afl_compiler_rt_o;
pub mod libaflfuzzer_harness_test;
} // mod examples
pub mod src {
pub mod aflpp;
pub mod common;
pub mod engine;
pub mod feedback;
pub mod fuzzone;
pub mod input;
pub mod llmp;
pub mod mutator;
pub mod observer;
pub mod os;
pub mod queue;
pub mod shmem;
pub mod stage;
} // mod src

