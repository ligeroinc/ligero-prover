# MPZ Util Tests (native & WebAssembly)

This directory builds and runs the `test_mpz_get` unit tests for the ligetron project.

- **Native**: runs as a normal binary.
- **WebAssembly**: compiles with **Emscripten** and runs under **Node.js** (the target emits a `.js` launcher).

By default, the WASM build expects prebuilt third-party static libs (Boost.Test, GMP) under **`/opt/wasm-libs`** as provided by our Docker build image.

---

## Prerequisites

**Native**
- CMake ≥ 3.24
- A C++20 compiler (gcc/clang)
- Boost (headers + `unit_test_framework`)
- GMP (`gmp`, `gmpxx`; discovered via `pkg-config`)

**WebAssembly**
- Emscripten SDK (emsdk), with `emcc`/`em++` on PATH
  ```bash
  # Example:
  source /emsdk/emsdk_env.sh
  ```
- Node.js (to run the generated `.js` launcher)
- Prebuilt static libs for wasm in `/opt/wasm-libs` (or override paths below):
  ```
  /opt/wasm-libs/
    include/boost/...            # Boost headers
    include/gmpxx.h, gmp.h       # GMP headers
    lib/libboost_unit_test_framework.a
    lib/libgmp.a
    lib/libgmpxx.a
  ```

---

## Build & run (Native)

```bash
# From the project root
cmake -S . -B build/native -DCMAKE_BUILD_TYPE=Debug
cmake --build build/native -j

# Run just these tests
ctest --test-dir build/native -R MPZUtilTests --output-on-failure
```

Tip: You can scope to a single test case with Boost.Test args:
```bash
# After a native build
./build/native/tests/util/test_mpz_get --run_test=*your_case_name*
```

---

## Build & run (WebAssembly / Node.js)

```bash
# Ensure emscripten is active
source /emsdk/emsdk_env.sh

# Configure using emcmake; -DCMAKE_PREFIX_PATH helps CMake find Boost in /opt/wasm-libs
emcmake cmake -S . -B build/wasm -DCMAKE_BUILD_TYPE=Web   -DCMAKE_PREFIX_PATH=/opt/wasm-libs

cmake --build build/wasm -j

# Run (ctest calls `node $<TARGET_FILE:test_mpz_get>` automatically)
ctest --test-dir build/wasm -R MPZUtilTests --output-on-failure
```

To pass Boost.Test arguments in WASM mode:
```bash
# Run the generated launcher directly
node build/wasm/tests/util/test_mpz_get.js -- --run_test=*your_case_name*
```
> Note the `--` separator: Node.js args end before test program args begin.

---

## Overriding the default WASM paths (`/opt/wasm-libs`)

There are **three** non-destructive ways to point CMake at a different prefix *without editing CMake files*:

### 1) Prefer this: make `find_package(Boost)` succeed (skip manual fallback)

`FindBoost.cmake` honors these variables. Set them so the normal discovery works (and our manual fallback won’t be used):

```bash
# Any shell
export BOOST_ROOT=/some/prefix                # top-level prefix
export BOOST_INCLUDEDIR=/some/prefix/include
export BOOST_LIBRARYDIR=/some/prefix/lib

# Also give CMake a general hint path (good for multiple packages):
emcmake cmake -S . -B build/wasm -DCMAKE_BUILD_TYPE=Web   -DCMAKE_PREFIX_PATH=/some/prefix
```

If your GMP headers/libs are also under the same prefix, the include and lib dirs will be picked up as well.

### 2) CMake’s generic search paths

If you can’t or don’t want to set the Boost variables, use CMake’s generic vars:

```bash
emcmake cmake -S . -B build/wasm -DCMAKE_BUILD_TYPE=Web   -DCMAKE_PREFIX_PATH=/some/prefix   -DCMAKE_INCLUDE_PATH=/some/prefix/include   -DCMAKE_LIBRARY_PATH=/some/prefix/lib
```

### 3) Quick-and-dirty: symlink your prefix to `/opt/wasm-libs`

If your toolchain expects `/opt/wasm-libs`, just point it there:

```bash
sudo ln -sfn /your/actual/prefix /opt/wasm-libs
```

> Why so many options?
> The test CMake first tries `find_package(Boost COMPONENTS unit_test_framework)`. If Boost isn’t found there, it **falls back** to a manual imported target that references `libboost_unit_test_framework.a` and headers under `/opt/wasm-libs`. By making `find_package` succeed (options 1 or 2), you avoid the fallback and don’t need that exact path.

---

## Common knobs & examples

- More verbose CMake logs (helpful if discovery fails):
  ```bash
  cmake -S . -B build/wasm -DCMAKE_BUILD_TYPE=Web     -DREALLY_VERBOSE=ON -DCMAKE_PREFIX_PATH=/some/prefix     -Wdev --debug-find
  ```

- Reconfigure from scratch:
  ```bash
  rm -rf build/wasm
  emcmake cmake -S . -B build/wasm -DCMAKE_BUILD_TYPE=Web -DCMAKE_PREFIX_PATH=/opt/wasm-libs
  ```

- Show where the test artifact landed:
  ```bash
  cmake --build build/wasm --target test_mpz_get --verbose
  ls -l build/wasm/tests/util/test_mpz_get.js
  ```

---

## Troubleshooting

- **`Could NOT find Boost (missing: Boost_INCLUDE_DIR unit_test_framework)`**
  - Set `BOOST_ROOT`, `BOOST_INCLUDEDIR`, `BOOST_LIBRARYDIR` **and/or** `-DCMAKE_PREFIX_PATH` to your wasm libs prefix (see “Overriding…”).
  - Verify the files exist:
    ```bash
    ls -l /some/prefix/include/boost/version.hpp
    ls -l /some/prefix/lib/libboost_unit_test_framework.a
    ```

- **Undefined symbols at link time (WASM)**
  - Ensure `libgmp.a` and `libgmpxx.a` exist in your prefix’s `lib/`.
  - If they’re elsewhere, add `-DCMAKE_LIBRARY_PATH=/path/to/lib` (or use a symlink).

- **`node: not found` or test won’t run**
  - Install Node.js, or ensure it’s on PATH.
  - You can also run the `.js` launcher explicitly as shown above.

- **Running a single test case / suite**
  - Boost.Test filters work in both native and wasm:
    ```bash
    # Native
    ./build/native/tests/util/test_mpz_get -- --run_test=MySuite/MyCase

    # WASM
    node build/wasm/tests/util/test_mpz_get.js -- --run_test=MySuite/MyCase
    ```

---

## Environment summary (defaults)

- **Native**
  - Boost + GMP discovered via system paths (`pkg-config` for GMP).
- **WASM**
  - Prefers `find_package(Boost ...)` with your hints.
  - Fallback manual import expects:
    - Headers: `/opt/wasm-libs/include`
    - Libs: `/opt/wasm-libs/lib/libboost_unit_test_framework.a`, `libgmp.a`, `libgmpxx.a`
  - Link options: memory growth, `EXIT_RUNTIME=1`, `ENVIRONMENT=node`

---

If you want a dedicated cache variable to override the fallback paths (e.g., `-DWASM_THIRD_PARTY_PREFIX=/your/prefix`), say the word and I’ll add that switch to the CMake so you don’t need env vars or symlinks.
