/*
 * Copyright (C) 2023-2026 Ligero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Basic API functions for Ligetron

use std::ptr;

pub fn assert_zero<T: Into<i32>>(val: T) {
    unsafe {
        _assert_zero(val.into());
    }
}

pub fn assert_one<T: Into<i32>>(val: T) {
    unsafe {
        _assert_one(val.into());
    }
}

pub fn assert_constant<T: Into<i32>>(val: T) {
    unsafe {
        _assert_constant(val.into());
    }
}

pub fn print_str(s: &[u8]) {
    unsafe { _print_str(s.as_ptr(), s.len() as i32) }
}

pub fn println_str(s: &[u8]) {
    unsafe { _print_str(s.as_ptr(), s.len() as i32) }
    print_str(b"\n");
}

pub fn dump_memory(data: &[u8]) {
    unsafe { _dump_memory(data.as_ptr(), data.len() as i32) }
}

pub fn get_file_size(filename: &str) -> i32 {
    let c_str = format!("{}\0", filename);
    unsafe { _file_size_get(c_str.as_ptr()) }
}

pub fn read_file(filename: &str, buffer: &mut [u8]) -> i32 {
    let c_str = format!("{}\0", filename);
    unsafe { _file_get(buffer.as_mut_ptr(), c_str.as_ptr()) }
}

pub fn strlen(string_start: *const i8) -> usize {
    let ptr = string_start;
    let mut len: usize = 0;

    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
    }
    len
}

#[macro_export]
macro_rules! fail_with_message {
    ($msg:expr) => {{
        println_str($msg);
        assert_zero(0);
        std::process::exit(1);
    }};
}

pub struct ArgHolder {
    arg_buffer: Vec<u8>,
    arg_ranges: Vec<(usize, usize)>, // (start, end) indices into arg_buffer
}

impl ArgHolder {
    /// Get the argument at the given index as a byte slice
    pub fn get_as_bytes(&self, index: usize) -> &[u8] {
        self.arg_ranges.get(index)
            .map(|(start, end)| &self.arg_buffer[*start..*end])
            .unwrap_or_else(|| fail_with_message!(b"Invalid argument index!"))
    }

    /// Get the argument at the given index as an i64 integer
    pub fn get_as_int(&self, index: usize) -> i64 {
        let arg_bytes = self.get_as_bytes(index);
        if arg_bytes.len() != 8 {
            fail_with_message!(b"Invalid argument length for i64!");
        } else {
            unsafe { *(arg_bytes.as_ptr() as *const i64) }
        }
    }

    /// Get the argument at the given index as a pointer to C-Style string
    pub fn get_as_c_str(&self, index: usize) -> *const i8 {
        let start = self.arg_ranges.get(index)
            .map(|(s, _)| *s)
            .unwrap_or_else(|| fail_with_message!(b"Invalid argument index!"));

        self.arg_buffer[start..].as_ptr() as *const i8
    }

    /// Get the number of arguments
    pub fn len(&self) -> usize {
        self.arg_ranges.len()
    }

    /// Iterate over all argument slices
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.arg_ranges.iter().map(|(start, end)| &self.arg_buffer[*start..*end])
    }
}

/// Get command line arguments
pub fn get_args() -> ArgHolder {
    let mut argc: i32 = 0;
    let mut argv_len: i32 = 0;
    let mut arg_struct = ArgHolder {
        arg_buffer: Vec::new(),
        arg_ranges: Vec::new(),
    };

    unsafe {
        if _args_sizes_get(&mut argc, &mut argv_len) == 0 {
            arg_struct.arg_buffer = vec![0u8; argv_len as usize];
            let mut argv: Vec<*mut u8> = vec![ptr::null_mut(); argc as usize];

            if _args_get(argv.as_mut_ptr() as *mut *mut u8, arg_struct.arg_buffer.as_mut_ptr() as *mut u8) == 0 {
                arg_struct.arg_ranges = Vec::with_capacity(argc as usize);
                let buffer_start = arg_struct.arg_buffer.as_ptr();

                for i in 0..argc as usize {
                    let start_offset = argv[i].offset_from(buffer_start) as usize;
                    let len: usize;
                    if i == argc as usize - 1 {
                        len = argv[0].add(argv_len as usize).offset_from(argv[i]) as usize;
                    } else {
                        len = argv[i + 1].offset_from(argv[i]) as usize;
                    }
                    arg_struct.arg_ranges.push((start_offset, start_offset + len));
                }
            }
        }
    }

    arg_struct
}

pub fn oblivious_if<T>(c: bool, t: T, f: T) -> T
where
    T: From<bool> + std::ops::Add<Output = T> + std::ops::Mul<Output = T>,
{
    (t * T::from(c)) + (f * T::from(!c))
}

pub fn oblivious_min<T>(a: T, b: T) -> T
where
    T: From<bool> + std::ops::Add<Output = T> + std::ops::Mul<Output = T> + std::cmp::PartialOrd,
{
    oblivious_if(a < b, a, b)
}

pub fn oblivious_max<T>(a: T, b: T) -> T
where
    T: From<bool> + std::ops::Add<Output = T> + std::ops::Mul<Output = T> + std::cmp::PartialOrd,
{
    oblivious_if(a > b, a, b)
}

#[link(wasm_import_module = "env")]
extern "C" {
    /// Assert that a value is zero
    #[link_name = "assert_zero"]
    fn _assert_zero(value: i32);

    /// Assert that a value is one
    #[link_name = "assert_one"]
    fn _assert_one(value: i32);

    /// Assert that a value is constant
    #[link_name = "assert_constant"]
    fn _assert_constant(value: i32);

    /// Print a string
    #[link_name = "print_str"]
    fn _print_str(ptr: *const u8, len: i32);

    /// Dump memory contents
    #[link_name = "dump_memory"]
    fn _dump_memory(ptr: *const u8, len: i32);

    /// Get file size
    #[link_name = "file_size_get"]
    fn _file_size_get(name_ptr: *const u8) -> i32;

    /// Read file contents
    #[link_name = "file_get"]
    fn _file_get(buf_ptr: *mut u8, name_ptr: *const u8) -> i32;
}

// WASI imports
#[link(wasm_import_module = "wasi_snapshot_preview1")]
extern "C" {
    #[link_name = "args_sizes_get"]
    fn _args_sizes_get(argc: *mut i32, buf_size: *mut i32) -> i32;

    #[link_name = "args_get"]
    fn _args_get(argv: *mut *mut u8, buf: *mut u8) -> i32;
}