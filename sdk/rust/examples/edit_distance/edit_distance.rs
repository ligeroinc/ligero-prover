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

//! Edit Distance Example
//!
//! Proves the knowledge that the private string is
//! within the edit distance of 5 characters from the public string.
//!
//! Arguments:
//!     [1]: Input text A (private) (as string)
//!     [2]: Input text B (as string)

use ligetron::*;

fn min_distance(word1: *const i8, word2: *const i8, m : usize, n : usize) -> i32 {
    let mut pre: i32;
    let mut cur:Vec<i32> = vec![0; n + 1];

    for j in 0..=n {
        cur[j] = j as i32;
    }

    for i in 1..=m {
        pre = cur[0];
        cur[0] = i as i32;
        for j in 1..=n {
            unsafe {
                let temp = cur[j];
                let cond = *(word1.add(i - 1)) == *(word2.add(j - 1));
                let minimum = oblivious_min(pre, oblivious_min(cur[j - 1], cur[j])) + 1;

                cur[j] = oblivious_if(cond, pre, minimum);
                pre = temp;
            }
        }
    }

    cur[n]
}

fn main() {
    let args = get_args();

    let len1: usize = args.get_as_int(3).try_into().unwrap();
    let len2: usize = args.get_as_int(4).try_into().unwrap();

    let dist = min_distance(args.get_as_c_str(1), args.get_as_c_str(2), len1, len2);

    assert_one(dist < 5);
}
