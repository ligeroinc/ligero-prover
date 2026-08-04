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

//! The SHA-2 family (FIPS 180-4): [`sha256`] and [`sha512`].
//!
//! ## C API parity
//!
//! [`ligetron_sha2_256`] and [`ligetron_sha2_512`] keep the names and shapes of their C++
//! counterparts, both declared in `sha2.h`, so the two trees stay greppable against each other.
//! Prefer [`sha256`] and [`sha512`] in Rust code; reach for the `ligetron_*` forms only to hash
//! part of a buffer, or when matching C++ line for line.

mod sha256;
mod sha512;

pub use sha256::{ligetron_sha2_256, sha256};
pub use sha512::{ligetron_sha2_512, sha512};
